import re
import os
import json
import time
import socket
import signal
import subprocess

from pwn import ssh, unpack_many, process

from qemu_runner import QEMURunner
from log import new_logger

# Configuration
IP = '127.0.0.1'
USERNAME = 'root'
REMOTE_EXP_PATH = "/tmp/exp"
DEFAULT_MAX_RUNTIME = 300
DIRNAME = os.path.dirname(os.path.abspath(__file__))
MAX_RETRY_TIMES = 10
SUCCESS_BANNER = b'Analysis Success!!!'

UTIL_DIR = os.path.join(os.path.dirname(__file__), "utils")
KEY_PATH = os.path.join(UTIL_DIR, "img", "stretch.id_rsa")
GDB_SCRIPT = os.path.join(UTIL_DIR, "gdb.py")
PATCH_SCRIPT = os.path.join(UTIL_DIR, "patch.py")
ANALYZE_SCRIPT = os.path.join(UTIL_DIR, "analyze.py")

def handler(signum, frame):
    raise Exception("Time up!")
signal.signal(signal.SIGALRM, handler)

def safe_setup(func):
    def wrapper(*args, **kwargs):
        self = args[0]
        self.logger.debug("Setting up...")
        for i in range(5):
            try:
                self.ssh_port = self._get_open_port()
                self.gdb_port = self._get_open_port()
                self.monitor_port = self._get_open_port()
                if func(*args, **kwargs):
                    break
            except RuntimeError as e:
                if self.qemu:
                    self.cleanup()
                    self.qemu = None
                self.logger.exception(e)
            self.logger.warning("Setting up EXP environment fails... retry... %d", i)
        else:
            raise RuntimeError("Fail to launch qemu")

        # make sure we have ssh connection
        if not self.ssh:
            raise RuntimeError("Fail to connect ssh")

        self.bootstrap()
        self.upload_exp()
        if self.mod_path:
            self.insmod()
    return wrapper

class Crasher:
    def __init__(self, exp_path, kernel_path, mod_path=None, vmlinux_path=None):
        self.ssh_port = None
        self.gdb_port = None
        self.monitor_port = None
        self.exp_path = os.path.abspath(exp_path)
        self.kernel_path = os.path.abspath(kernel_path)
        self.mod_path = os.path.abspath(mod_path) if mod_path else None
        self.vmlinux_path = os.path.abspath(vmlinux_path) if vmlinux_path else None
        self.max_runtime = DEFAULT_MAX_RUNTIME

        self.logger = new_logger("Crasher", level="DEBUG")

        self.qemu = None
        self.ssh = None
        self.key = KEY_PATH
        self.symbols = None
        self.gdb_proc = None

        # sanity check
        assert os.path.exists(self.key)
        assert os.path.exists(self.exp_path)
        assert os.path.exists(self.kernel_path)

    def connect(self):
        self.logger.debug("Connecting ssh...")
        try:
            self.ssh = ssh(user=USERNAME, host=IP, port=self.ssh_port, keyfile=self.key)
            return True
        except Exception as e:
            self.logger.exception(e)
            return False

    def upload_exp(self):
        self.logger.debug("Uploading exp...")
        self.ssh.upload(self.exp_path, REMOTE_EXP_PATH)
        r = self.ssh.run('chmod u+x "%s"' % REMOTE_EXP_PATH)
        r.wait()

    def bootstrap(self):
        self.logger.debug("Bootstrap system...")
        r = self.ssh.run("echo 1 > /proc/sys/kernel/panic_on_rcu_stall")
        r.wait()
        r = self.ssh.run("echo 5 > /sys/module/rcupdate/parameters/rcu_cpu_stall_timeout")
        r.wait()

    def insmod(self):
        self.logger.debug(f"Uploading kernel module {self.mod_path}...")
        self.ssh.upload(self.mod_path, "/tmp/mod.ko")
        r = self.ssh.run('insmod /tmp/mod.ko')
        a = r.wait()
        if a != 0:
            self.logger.error(f"Failed to insert module {self.mod_path}")

    def run_exp(self, loop=False):
        self.logger.debug("Running exp...")

        r = None
        signal.alarm(5)
        try:
            if loop:
                r = self.ssh.process(f"while true; do {REMOTE_EXP_PATH}; done", shell=True)
            else:
                r = self.ssh.process([REMOTE_EXP_PATH])
        except Exception as e:
            self.logger.info(e)
        signal.alarm(0)
        return r

    def wait_result(self, r):
        self.logger.debug("Waiting for exp result...")
        start = time.time()
        output = b""
        while not self.qemu.crashed and time.time() - start < self.max_runtime:
            try:
                output += r.recv(timeout=0.5)
            except EOFError:
                break
        if time.time() - start >= self.max_runtime:
            self.logger.warning("Time out! Killing qemu!")
        if not self.qemu.crashed and r.poll() is None:
            r.kill()

    def crash_kernel(self, **kwargs):
        for i in range(MAX_RETRY_TIMES):
            r = self.run_exp()
            self.wait_result(r)
            if self.qemu.status == 'good_crash':
                return
            if self.qemu.crashed:
                self.logger.warning("Fail to crash the kernel with controlled RIP, trying again...%d", i)
            else:
                self.logger.warning("Fail to crash the kernel, trying again...%d", i)

            # reset everything
            self.cleanup()
            if not kwargs:
                self.basic_setup()
            elif "taint_regs" in kwargs:
                self.advanced_setup(**kwargs)
            else:
                self.insane_setup(**kwargs)

    def gdb_crash_kernel(self, **kwargs):
        result = None
        max_runtime = kwargs.pop("max_runtime", DEFAULT_MAX_RUNTIME)
        #max_no_output_cnt = 120 # 60s
        max_no_output_cnt = max_runtime

        for _ in range(MAX_RETRY_TIMES):
            r = self.run_exp(loop=True)
            self.logger.debug("Waiting for gdb result...")
            start = time.time()
            cnt = 0
            while time.time() - start < max_runtime and cnt < max_no_output_cnt:
                try:
                    output = self.gdb_proc.recvline(timeout=0.5)
                    if output:
                        cnt = 0
                        print(output.decode().strip())
                    else:
                        cnt += 1
                    if SUCCESS_BANNER in output:
                        a = output.split(b'|')[1].strip()
                        result = json.loads(a)
                        self.logger.info("Successfully extract valid user data information!")
                        self.wait_result(r)
                        return result
                except EOFError:
                    break

            if r is None:
                self.logger.warning("Fail to correctly launch the exploit! Restart the system!")

            if time.time() - start >= max_runtime:
                self.logger.warning("Time out! Killing qemu!")

            if cnt >= max_no_output_cnt:
                self.logger.warning("The script hangs! Restart the system!")

            if not self.qemu.crashed:
                r.kill()
            if self.gdb_proc and self.gdb_proc.poll() is None:
                self.gdb_proc.kill()
                self.gdb_proc = None

            # reset everything
            self.cleanup()
            self.insane_setup(**kwargs)
        return None

    def extract_rsp(self):
        """
        extract the first rsp value in the crash log
        """
        assert self.qemu.crashed is True
        crash_log = self.qemu.get_crash_log()
        line = ""
        for line in crash_log.splitlines():
            if "RSP: " in line:
                break
        else:
            raise RuntimeError("Cannot find RSP in crash log!")
        res = re.search(r"ffff[0-9a-f]{12}", line)
        assert res is not None, line
        return int(res.group(0), 16)

    def extract_memory(self, rsp):
        cmd = f"gdb -batch -quiet -nx -ex 'set var $port={self.gdb_port}' -ex 'set var $krsp={rsp:#x}' -x {GDB_SCRIPT} {self.vmlinux_path}"
        output = subprocess.getoutput(cmd)
        line = ""
        for line in output.splitlines():
            if "MEMORY" in line:
                break
        else:
            print(output)
            raise RuntimeError("Fail to read kernel memory")
        mem = line.split()[1]
        mem = bytes.fromhex(mem)
        return unpack_many(mem, 64, endian='little', sign=False) #pylint:disable=unexpected-keyword-arg

    def extract_symbols(self):
        data, status = self.ssh.run_to_end(f"cat /proc/kallsyms")
        assert status == 0
        lines = [x.split() for x in data.splitlines()]
        d = {}
        for x in lines:
            if x[0] == b'(null)':
                val = 0
            else:
                val = int(x[0], 16)
            d[x[-1].decode()] = val
        addrs = sorted(list(set(d.values()))) # get unique addresses
        syms = {}

        # required symbols
        names = ['prepare_kernel_cred', 'commit_creds', 'entry_SYSCALL_64_after_hwframe', 'entry_SYSCALL_64',
                 '__entry_text_end', '__irqentry_text_end', 'do_syscall_64', 'panic',
                 'set_brk', '__get_user_8', '_copy_from_user', 'oops_end']
        for name in names:
            if name not in d:
                raise ValueError(f"Fail to find '{name}' from kallsym, please provide it manually")
            addr = d[name]
            idx = addrs.index(addr)
            size = addrs[idx+1] - addr
            assert size > 0
            syms[name] = (addr, size)

        # optional symbols
        names = ['entry_SYSCALL_64_fastpath']
        for name in names:
            if name not in d:
                continue
            addr = d[name]
            idx = addrs.index(addr)
            size = addrs[idx+1] - addr
            assert size > 0
            syms[name] = (addr, size)

        self.symbols = syms
        return syms

    @safe_setup
    def insane_setup(self, **kwargs):
        self.qemu = QEMURunner(self.kernel_path, ssh_port=self.ssh_port, gdb_port=self.gdb_port,
                               monitor_port=self.monitor_port, stop=True)
        self.qemu.launch()

        sys_num = kwargs['sys_num']
        entry = self.symbols['entry_SYSCALL_64_after_hwframe'][0]
        entry_end = self.symbols['__entry_text_end'][0]
        irq_end = self.symbols['__irqentry_text_end'][0]
        do_syscall = self.symbols['do_syscall_64'][0]
        oops_end = self.symbols['oops_end'][0]
        fast_path = self.symbols['entry_SYSCALL_64_fastpath'][0] if 'entry_SYSCALL_64_fastpath' in self.symbols else 0
        panic = self.symbols['panic'][0]
        set_brk = self.symbols['set_brk'][0]
        get_user_8 = self.symbols['__get_user_8'][0]
        copy_from_user = self.symbols['_copy_from_user'][0]
        cmd = ["gdb", "-batch", "-quiet", "-nx",
                "-ex", f'set var $gdb_port={self.gdb_port}',
                "-ex", f'set var $monitor_port={self.monitor_port}',
                "-ex", f'set var $sys_num={sys_num}',
                "-ex", f'set var $entry={entry:#x}',
                "-ex", f'set var $entry_end={entry_end:#x}',
                "-ex", f'set var $irq_end={irq_end:#x}',
                "-ex", f'set var $do_syscall={do_syscall:#x}',
                "-ex", f'set var $oops_end={oops_end:#x}',
                "-ex", f'set var $fast_path={fast_path:#x}',
                "-ex", f'set var $panic={panic:#x}',
                "-ex", f'set var $set_brk={set_brk:#x}',
                "-ex", f'set var $get_user_8={get_user_8:#x}',
                "-ex", f'set var $copy_from_user={copy_from_user:#x}',
                "-x", f"{ANALYZE_SCRIPT}", f"{self.vmlinux_path}"]

        # print out human-friendly command
        print_cmd = ''
        for idx, x in enumerate(cmd):
            # quote gdb commands
            if x.startswith('set'):
                x = "'" + x + "'"
            print_cmd += x
            if idx != len(cmd):
                print_cmd += " "
        self.logger.debug(print_cmd)

        r = process(cmd)
        try:
            self.qemu.wait_ready()
        except RuntimeError:
            pass
        finally:
            output = r.recvuntil(b"Patch Success", timeout=60)
        if b"Patch Success" not in output:
            self.logger.warning(output.decode())
            raise RuntimeError("Fail to launch patched kernel!")

        self.gdb_proc = r

        return self.connect()

    @safe_setup
    def advanced_setup(self, **kwargs):
        self.qemu = QEMURunner(self.kernel_path, ssh_port=self.ssh_port, gdb_port=self.gdb_port,
                                monitor_port=self.monitor_port, stop=True)
        self.qemu.launch()

        entry_end = self.symbols['__entry_text_end'][0]
        irq_end = self.symbols['__irqentry_text_end'][0]
        entry = self.symbols['entry_SYSCALL_64_after_hwframe'][0]
        do_syscall = self.symbols['do_syscall_64'][0]
        fast_path = self.symbols['entry_SYSCALL_64_fastpath'][0] if 'entry_SYSCALL_64_fastpath' in self.symbols else 0
        sys_num = kwargs['sys_num']
        taint_regs = kwargs['taint_regs']
        reg_str = ",".join(taint_regs)
        cmd = ["gdb", "-batch", "-quiet", "-nx",
                "-ex", f'set var $port={self.gdb_port}',
                "-ex", f'set var $entry_end={entry_end:#x}',
                "-ex", f'set var $entry={entry:#x}',
                "-ex", f'set var $irq_end={irq_end:#x}',
                "-ex", f'set var $do_syscall={do_syscall:#x}',
                "-ex", f'set var $fast_path={fast_path:#x}',
                "-ex", f'set var $sys_num={sys_num}',
                "-ex", f'set var $taint_regs="{reg_str}"',
                "-x", f"{PATCH_SCRIPT}", f"{self.vmlinux_path}"]

        # print out human-friendly command
        print_cmd = ''
        for idx, x in enumerate(cmd):
            # quote gdb commands
            if x.startswith('set'):
                x = "'" + x + "'"
            print_cmd += x
            if idx != len(cmd):
                print_cmd += " "
        self.logger.debug(print_cmd)

        r = process(cmd)
        try:
            self.qemu.wait_ready()
        except RuntimeError:
            pass
        finally:
            output = r.recvall(timeout=60)
            r.close()
        if b"SUCCESS" not in output:
            self.logger.warning(output.decode())
            raise RuntimeError("Fail to launch patched kernel!")

        return self.connect()

    @safe_setup
    def basic_setup(self):
        self.qemu = QEMURunner(self.kernel_path, ssh_port=self.ssh_port, gdb_port=self.gdb_port,
                                monitor_port=self.monitor_port, stop=False)
        self.qemu.launch()
        self.qemu.wait_ready()
        return self.connect()

    def cleanup(self):
        self.logger.debug("Cleaning up...")
        self.qemu.kill()
        self.qemu = None
        if self.gdb_proc:
            self.gdb_proc.kill()
            self.gdb_proc = None

    @staticmethod
    def _get_open_port():
        """
        get a random open port
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("",0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        return port

if __name__ == '__main__':
    exp_path = os.path.abspath("../rand_kstack_success_rate/poc")
    kernel_path = os.path.abspath("../rand_kstack_success_rate/kernel/arch/x86/boot/bzImage")
    mod_path = os.path.abspath("../rand_kstack_success_rate/vuln_module/vuln.ko")
    crasher = Crasher(exp_path, kernel_path, mod_path=mod_path)
    crasher.basic_setup()

    print(crasher.ssh_port)
    symbols = crasher.extract_symbols()
    print(symbols)

    crasher.crash_kernel()

    rsp = crasher.extract_rsp()
    print("rsp: %#x" % rsp)
    memory = crasher.extract_memory(rsp)
    print(memory)

    print(crasher.qemu.status)
    # print(crasher.qemu.output.decode())
    crasher.cleanup()
