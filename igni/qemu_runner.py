import re
import os
import time
import threading
import traceback
import subprocess
from pwn import process, context

from log import new_logger

context.log_level = 'error'

CRASH_IP = b"ffffffffdeadbeef"
PANIC_BANNER = b" Kernel panic "
DEFAULT_MAX_READY_TIMEOUT = 60
CORE_NUM = 2
MEM_SIZE = 2

UTIL_DIR = os.path.join(os.path.dirname(__file__), "utils")
RUN_KERNEL = os.path.join(UTIL_DIR, "run_kernel")
COPY2VM = os.path.join(UTIL_DIR, "copy2vm")

logger = new_logger("QEMURunner")

class QEMURunner:
    """
    A component to launch and monitor the status of a QEMU system instance
    """
    def __init__(self, kernel_path, ssh_port=10069, gdb_port=8333, monitor_port=54545, timeout=0.1, stop=False):
        self.ssh_port = ssh_port
        self.gdb_port = gdb_port
        self.monitor_port = monitor_port
        self.kernel_path = os.path.abspath(kernel_path)

        self.kernel = None
        self.status = "dead"
        self.timeout = timeout
        self.output = b''
        self.init_event = threading.Event()
        self.start_ts = None
        self.stop = stop

    def launch(self):
        cmd = [RUN_KERNEL, self.kernel_path, str(self.ssh_port), str(self.gdb_port), str(self.monitor_port)]
        cmd += ['1'] if self.stop else []
        logger.debug("Launching QEMU with cmd: %s", ' '.join(cmd))
        self.kernel = process(cmd)
        self.status = "launching"
        self.start_ts = time.time()

        # launching update thread
        def update_func():
            self.init_event.wait()
            while self.status == 'ready':
                try:
                    self.update()
                    time.sleep(self.timeout)
                except Exception as e:
                    print(e, "handled")
                    self.kill()
        t = threading.Thread(target=update_func)
        t.start()

    def kill(self):
        # make sure the update thread exits
        self.status = "dead"
        time.sleep(self.timeout*2)
        self.kernel.kill()

    @property
    def crashed(self):
        return "crash" in self.status

    def update(self):
        if self.crashed:
            return
        elif self.status == "launching":
            try:
                output = self.kernel.recvuntil(b" login: ", timeout=self.timeout)
                self.output += output
                if b" login: " in output:
                    self.status = "ready"
            except EOFError:
                print("qemu output", self.output)
                raise RuntimeError("fail to launch qemu")
            except Exception as e:
                print("Something wrong with qemu")
                print(e)
                traceback.print_exc()
                raise RuntimeError("Something wrong with qemu")
                #import IPython;IPython.embed()
        elif self.status == "ready":
            try:
                output = self.kernel.recv(timeout=self.timeout)
                self.output += output
            except Exception as e:
                print("Something wrong with qemu")
                print(e)
                traceback.print_exc()
                raise RuntimeError("Something wrong with qemu")
                #import IPython;IPython.embed()

        # check whether the kernel is crashed
        if PANIC_BANNER in self.output:
            # if kernel crashed,
            if CRASH_IP in self.output:
                self.status = "good_crash"
            else:
                self.status = "unknown_crash"

    def save_fingerprint(self):
        ret = os.system("ssh-keygen -F [127.0.0.1]:%d -f ~/.ssh/known_hosts 2>/dev/null 1>/dev/null" % self.ssh_port)
        if ret == 0:
            return
        os.system("ssh-keyscan -t rsa -p %d 127.0.0.1 >> ~/.ssh/known_hosts 2>/dev/null" % self.ssh_port)

    def copy2vm(self, src_path):
        subprocess.run([COPY2VM, src_path, str(self.ssh_port)])

    def wait_ready(self, timeout=DEFAULT_MAX_READY_TIMEOUT):
        start = time.time()
        while self.status != "ready":
            self.update()
            time.sleep(self.timeout)
            if time.time() - start > timeout:
                raise RuntimeError("kernel is never ready")
        if b'[\x1b[0;1;31mFAILED\x1b[0m]' in self.output: # this happens to network subsystem often
            #print(self.output.decode())
            raise RuntimeError("kernel failed to initialize")
        self.init_event.set()
        self.save_fingerprint()

    def get_crash_log(self):
        assert self.crashed is True
        # use the last trace log as the start of the panic log
        idx = self.output.rindex(b"] CPU:")
        res = re.search(b"\] CPU:.*"+PANIC_BANNER, self.output[idx:], re.MULTILINE|re.DOTALL)
        assert res is not None, self.output.decode()
        return res.group(0).decode()

if __name__ == '__main__':
    qemu = QEMURunner("../rand_kstack_success_rate/kernel/arch/x86/boot/bzImage", 1264)
    qemu.launch()
    try:
        qemu.wait_ready()
    except RuntimeError:
        print(qemu.output.decode())
        qemu.kernel.interactive()
    print(qemu.output.decode())
    qemu.status = 'dead'
    #os.system("killall -9 qemu-system-x86_64")
    os.system("kill -9 %d" % qemu.kernel.pid)
    #qemu.kill()
