import os
import re
import struct
import tempfile
import subprocess

import angr
import jinja2
from elftools.elf.elffile import ELFFile

from crasher import Crasher
from log import new_logger

logger = new_logger("Analyzer")
angr.loggers.disable_root_logger()

def u64(val):
    return struct.unpack('<Q', val)[0]

UTIL_DIR = os.path.join(os.path.dirname(__file__), "utils")
EXTRACT = os.path.join(UTIL_DIR, "extract-vmlinux")

EXTRA_REGS = ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15']
ARG_REGS = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']

# syscall number to number of arguments map
ARG_MAP = [ 3, 3, 3, 1, 2, 2, 2, 3, 3, 6, 3, 2, 1, 4, 4, 1, 3, 4, 4, 3, 3, 2, 1, 5, 0, 5,
            3, 3, 3, 3, 3, 3, 1, 2, 0, 2, 2, 1, 3, 0, 4, 3, 3, 3, 6, 6, 3, 3, 2, 3, 2, 3,
            3, 4, 5, 5, 5, 0, 0, 3, 1, 4, 2, 1, 3, 3, 4, 1, 2, 4, 5, 3, 3, 2, 1, 1, 2, 2,
            3, 2, 1, 1, 2, 2, 1, 2, 2, 1, 2, 3, 2, 2, 3, 3, 3, 1, 2, 2, 2, 1, 1, 4, 0, 3,
            0, 1, 1, 0, 0, 2, 0, 0, 0, 2, 2, 2, 2, 3, 3, 3, 3, 1, 1, 1, 1, 2, 2, 2, 4, 3,
            2, 2, 2, 3, 1, 1, 2, 2, 2, 3, 2, 3, 2, 2, 3, 1, 1, 1, 2, 2, 2, 1, 0, 0, 3, 2,
            1, 5, 2, 1, 2, 1, 0, 1, 2, 5, 2, 2, 1, 4, 2, 2, 1, 3, 6, 3, 2, 6, 6, 4, 6, 6,
            6, 6, 6, 6, 0, 3, 5, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2, 1, 6, 3, 3, 1, 2, 1,
            5, 3, 3, 1, 3, 1, 6, 6, 5, 3, 1, 0, 4, 4, 3, 4, 2, 1, 1, 2, 2, 2, 4, 1, 4, 4,
            3, 2, 6, 6, 3, 5, 4, 1, 5, 5, 2, 3, 4, 5, 5, 4, 5, 3, 2, 0, 3, 2, 4, 4, 3, 4,
            5, 3, 4, 3, 4, 5, 3, 4, 3, 3, 6, 5, 1, 2, 3, 6, 4, 4, 4, 6, 4, 6, 3, 2, 1, 4,
            4, 2, 4, 4, 2, 1, 3, 2, 1, 5, 5, 4, 5, 5, 2, 5, 4, 5, 3, 2, 1, 4, 2, 3, 6, 6,
            5, 3, 3, 4, 5, 3, 3, 2, 5, 3, 5, 1, 2, 3, 6, 6, 6, 4, 2, 1, 5]

calling_taints = {
        u64(b'z'*8): "rdi",
        u64(b'y'*8): "rsi",
        u64(b'x'*8): "rdx",
        u64(b'w'*8): "r8",
        u64(b'v'*8): "r9",
        u64(b'u'*8): "r10",
        u64(b't'*8): "rbx",
        u64(b's'*8): "rbp",
        u64(b'r'*8): "r12",
        u64(b'q'*8): "r13",
        u64(b'p'*8): "r14",
        u64(b'o'*8): "r15",
        }

env = jinja2.Environment(
    loader=jinja2.FileSystemLoader('templates'),
    trim_blocks=True)

class Analyzer:
    def __init__(self, exp_path, kernel_path, mod_path=None):
        # analyzer info
        self.vmlinux_path = None
        self.kernel_path = os.path.abspath(kernel_path)
        self.exp_path = os.path.abspath(exp_path)
        self.mod_path = os.path.abspath(mod_path) if mod_path else None
        self.static = self._is_static()

        # raw info
        self.symbols = None
        self.rsp = None
        self.sys_num = None
        self.stack = None
        self.stack_diff = None
        self.sim_stack = None
        self.user_data = None
        self.unused_regs = None
        self.how_unused_regs = None

        self.text_start = None
        self.text_end = None

    def __enter__(self):
        # extract vmlinux
        _, vmlinux_path = tempfile.mkstemp(prefix="retspill-")
        proc = subprocess.run(f"{EXTRACT} {self.kernel_path} > {vmlinux_path}", shell=True)
        assert proc.returncode == 0
        self.vmlinux_path = vmlinux_path
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        # cleanup
        os.unlink(self.vmlinux_path)

    def _is_static(self):
        """
        check whether the exploit is statically compiled
        """
        output = subprocess.getoutput(f"ldd {self.exp_path}")
        return "not a dynamic" in output

    def _in_kernel_text(self, val):
        # we can make this assumption because we are sure kaslr is off
        return self.text_start <= val <= self.text_end

    def print_stack(self, stack):
        """
        for debugging purpose
        """
        for i in range(len(stack)):
            val = stack[i]
            offset = i*8
            if type(val) == int:
                print(f"{offset:#x}  {val:#x}")
            elif type(val) == str:
                print(f"{offset:#x}  {val}")
            else:
                raise TypeError('unknown type')

    def stack_fixup(self, base_stack, new_stack):
        stack1 = base_stack
        stack2 = new_stack
        logger.info("Performing stack fixup")
        assert self._in_kernel_text(stack1[-22]) and self._in_kernel_text(stack2[-22])
        idx = len(stack2) - 22
        for i in range(idx-1, -1, -1):
            if self._in_kernel_text(stack2[i]):
                break
        assert (idx-i) == (len(stack2) - len(stack1))
        return stack2[:i] + stack2[idx:]

    def extract_data_symbols(self):
        """
        use heuristics to extract important data symbols from the kernel
        """
        # extract the address of init_cred
        addr, size = self.symbols['prepare_kernel_cred']
        start = addr
        end = addr + size
        output = subprocess.getoutput(f"objdump -M intel -d --start-address={start:#x} --stop-address={end:#x} {self.vmlinux_path}")
        addrs = [int(x, 16) for x in re.findall(r'0xffffffff[0-9a-f]{8}', output)]
        data_addrs = {x for x in addrs if not self._in_kernel_text(x)}

        for addr in data_addrs:
            output = subprocess.getoutput(f"objdump -s --start-address={addr:#x} --stop-address={addr+16:#x} {self.vmlinux_path}")
            if f"{addr:x}" not in output:
                continue
            if "04000000" in output: # this usage value is hardcoded into init_cred, so just look for it
                self.symbols["init_cred"] = (addr, 0x10)
                break

    def _conservative_fixup(self, stack1, stack2, stack3):
        """
        devide the stack frame by frame, only copy in the matching frames
        TODO: this algorithm is buggy, fix it
        """
        # stack1 is the anchor
        stack = stack1.copy()

        # if we are in conservative fixup, that means we are dealing with old Linux kernel, perform aggressive
        # stack stitching
        stack2 = stack2[:-25]+stack2[-22:]
        stack2[-22] = stack1[-22]

        # fill in stack2 content first, we don't need to worry about the last chunk, it is the register region
        prev_idx = None
        for i in range(len(stack)):
            # just copy the first part
            if prev_idx is None:
                stack[i] = stack2[i]
                if self._in_kernel_text(stack[i]):
                    prev_idx = i
            else:
                if not self._in_kernel_text(stack[i]):
                    continue
                if stack[prev_idx] not in stack2:
                    prev_idx = i
                    continue
                idx2 = stack2.index(stack[prev_idx])
                offset = i - prev_idx
                if stack2[idx2+offset] != stack[i]:
                    prev_idx = i
                    continue
                for j in range(prev_idx, i):
                    stack[j] = stack2[j]
                prev_idx = i

        # only fill in taints in stack3 and calling taints
        taints = [x[2] for x in self.user_data] + list(calling_taints.keys())
        prev_idx = None
        for i in range(len(stack)):
            # no need to copy the first part
            if prev_idx is None:
                if self._in_kernel_text(stack[i]):
                    prev_idx = i
            else:
                if not self._in_kernel_text(stack[i]):
                    continue
                if stack[prev_idx] not in stack3:
                    prev_idx = i
                    continue
                idx3 = stack3.index(stack[prev_idx])
                offset = i - prev_idx
                if stack3[idx3+offset] != stack[i]:
                    prev_idx = i
                    continue
                for j in range(prev_idx, i):
                    if stack3[j] in taints:
                        stack[j] = stack3[j]
                prev_idx = i

        return stack

    def get_raw_info(self):
        """
        run the exploit to crash the kernel and extract runtime info
        from the crash
        """
        # extract the range of .text section
        with open(self.vmlinux_path, "rb") as f:
            elffile = ELFFile(f)
            text = elffile.get_section_by_name(".text")
            self.text_start = text.header['sh_addr']
            self.text_end = self.text_start + text.header['sh_size']

        logger.info("Run the kernel to extract basic information")
        crasher = Crasher(self.exp_path, self.kernel_path,
                          mod_path=self.mod_path, vmlinux_path=self.vmlinux_path)

        # crash the vanilla kernel once to get the basic memory layout
        crasher.basic_setup()
        self.symbols = crasher.extract_symbols()
        self.extract_data_symbols()
        crasher.crash_kernel()
        rsp1 = crasher.extract_rsp()
        stack1 = crasher.extract_memory(rsp1)
        stack_diff1 = 0x1000 - (rsp1&0xfff) - 0xa8
        sys_num1 = stack1[-6]
        crasher.cleanup()
        logger.info("trigger sys_num: %d", sys_num1)
        logger.info("crash rsp: %#x", rsp1)
        logger.info("stack_diff1: %#x", stack_diff1)
        assert stack1[-1] == 0x2b
        assert stack1[-4] in [0x23, 0x33] # 0x33 is normal syscall, 0x23 is compact syscall
        assert stack_diff1 >= 0

        # based on the crashing syscall, decide what registers to taint
        taint_regs = self._get_taint_regs(sys_num1)

        # crash the patched kernel once to get more advanced information using taint analysis
        logger.info("Run the exploit in the patched kernel to extract advanced information")
        crasher.advanced_setup(sys_num=sys_num1, taint_regs=taint_regs)
        crasher.crash_kernel(sys_num=sys_num1, taint_regs=taint_regs)
        rsp2 = crasher.extract_rsp()
        stack2 = crasher.extract_memory(rsp2)
        stack_diff2 = 0x1000 - (rsp2&0xfff) - 0xa8
        sys_num2 = stack2[-6]
        crasher.cleanup()
        logger.info("trigger sys_num: %d", sys_num2)
        logger.info("crash rsp: %#x", rsp2)
        logger.info("stack_diff2: %#x, require a pivot gadget like: add rsp, %#x; ret", stack_diff2, stack_diff2)

        # crash a different patched kernel once again to get even more advanced information using taint analysis
        logger.info("Run the exploit in another patched kernel to extract user-controlled data on kernel stack")
        crasher.insane_setup(sys_num=sys_num1)
        data = crasher.gdb_crash_kernel(sys_num=sys_num1, max_runtime=600000)
        assert 'copy_data' in data and 'unused' in data and 'how' in data
        self.user_data = data['copy_data']
        self.unused_regs = data['unused']
        rsp3 = crasher.extract_rsp()
        # translate it to <offset in sim_stack>:<reason why it is pushed>, the raw data contain
        # pushed registers from the error handling stack frame, ignore them
        self.how_unused_regs = {(int(x)-rsp3)//8:y for x, y in data['how'].items() if int(x) >= rsp3}
        stack3 = crasher.extract_memory(rsp3)
        stack_diff3 = 0x1000 - (rsp3&0xfff) - 0xa8
        sys_num3 = stack3[-6]
        crasher.cleanup()
        logger.info("trigger sys_num: %d", sys_num3)
        logger.info("crash rsp: %#x", rsp3)
        logger.info("stack_diff3: %#x, require a pivot gadget like: add rsp, %#x; ret", stack_diff3, stack_diff3)

        # in case the stack layout differs, perform fixup
        # the diff is usually caused by do_syscall_64 vs sys_call_table
        # we try native fixup first, if it fails, we use the conservative fixup
        try:
            if stack_diff1 != stack_diff2:
                stack2 = self.stack_fixup(stack1, stack2)
                stack_diff2 = stack_diff1
            if stack_diff1 != stack_diff3:
                stack3 = self.stack_fixup(stack1, stack3)
                stack_diff3 = stack_diff1

            # now merge stack2 and stack3
            taints = [x[2] for x in self.user_data] + list(calling_taints.keys())
            for i in range(len(stack3)):
                if stack3[i] in taints:
                    stack2[i] = stack3[i]
            self.stack = stack2
        except Exception:
            logger.warning("Using the unfinished conservative approach to stitch stacks together...")
            self.stack = self._conservative_fixup(stack1, stack2, stack3)

        self.rsp = rsp1
        self.stack_diff = stack_diff1
        self.sys_num = sys_num1

        assert sys_num1 == sys_num2, "????????"
        assert self.stack[-1] == 0x2b
        assert self.stack[-4] in [0x23, 0x33] # 0x33 is normal syscall, 0x23 is compact syscall
        assert self.stack_diff >= 0

    def _get_taint_regs(self, sys_num):
        # make sure there is no xor stub, or there is not way to taint it
        # FIXME: patch level1: has xor stub but still can be tainted
        assert self.vmlinux_path
        sym = self.symbols['entry_SYSCALL_64_after_hwframe']
        start = sym[0]
        end = sym[0] + sym[1]
        output = subprocess.getoutput(f"objdump -M intel -d --start-address={start:#x} --stop-address={end:#x} {self.vmlinux_path}")
        lines = output.splitlines()

        # locate the push stub
        key_lines = [x for x in lines if 'push' in x and '0xffffffffffffffda' in x]
        assert len(key_lines) == 1
        key_line = key_lines[0]
        idx = lines.index(key_line)
        assert idx >= 5
        start_idx = idx

        # scan through the stub and reach the end of the push stub
        end_idx = None
        for i in range(start_idx, len(lines)):
            line = lines[i]
            if '\tpush' not in line:
                end_idx = i
                break
        assert end_idx is not None

        # well, if there is xor stub, don't taint anything
        if '\txor' in lines[end_idx]:
            return []

        unused = ARG_REGS
        arg_num = ARG_MAP[sys_num]
        unused = unused[arg_num:]
        return unused + EXTRA_REGS

    def _get_pushed_regs(self, sys_num):
        # analyze the controlled data introduced by saved registers
        # step 1: collect all unused registers
        unused = ARG_REGS
        arg_num = ARG_MAP[sys_num]
        unused = unused[arg_num:]

        # step 2: include extra registers if they are not saved (kernel version dependent)
        assert self.vmlinux_path
        sym = self.symbols['entry_SYSCALL_64_after_hwframe']
        start = sym[0]
        end = sym[0] + sym[1]
        output = subprocess.getoutput(f"objdump -M intel -d --start-address={start:#x} --stop-address={end:#x} {self.vmlinux_path}")
        # cover your eyes to avoid damage to your eyes from the bad code
        if '48 83 ec 30' not in output: # sub rsp, 0x30
            unused += EXTRA_REGS
        return unused

    def _analyze_regs(self):
        unused = self._get_pushed_regs(self.sys_num) + self.unused_regs

        # record the registers
        offset_map = {'rax': -6, 'rdi':-7, 'rsi': -8, 'rdx': -9, 'r8': -12, 'r9': -13, 'r10': -14,
                      'rbx': -16, 'rbp': -17, 'r12': -18, 'r13': -19, 'r14': -20, 'r15': -21}

        for reg in unused:
            self.sim_stack[offset_map[reg]] = "reg_" + reg

        logger.info("controlled registers: %s", unused)

    def _analyze_uninit_mem(self):
        for i in range(len(self.stack)):
            if self.stack[i] == 0x5a5a5a5a5a5a5a5a:
                self.sim_stack[i] = f'uninit_mem_{i*8:#x}'

    def _analyze_calling_convention(self):
        for i in range(len(self.stack)):
            val = self.stack[i]
            if val in calling_taints:
                if self.sim_stack[i] != 0: # possible for unused registers
                    continue
                if i in self.how_unused_regs and self.how_unused_regs[i] != 'conv':
                    continue
                self.sim_stack[i] = "conv_" + calling_taints[val]

    def _analyze_user_data(self):
        taint_dict = {x[2]:x[0] for x in self.user_data}
        for i in range(len(self.stack)):
            val = self.stack[i]
            if val in taint_dict:
                addr = taint_dict[val]
                self.sim_stack[i] = f"user_{addr:#x}"

    def analyze_layout(self):
        # initialize the stack abstraction
        self.sim_stack = [0] * len(self.stack)

        self._analyze_regs()
        self._analyze_uninit_mem()
        self._analyze_calling_convention()
        self._analyze_user_data()

        # self.print_stack(self.sim_stack)

    def dump(self, constraints):
        template = env.get_template("code.c")

        # sanity check
        if not all(x.startswith("reg_") or x.startswith("conv_") or x.startswith("user_") or x == "init" for x in constraints):
            raise NotImplementedError("Only register control is implemented at this moment!!!")
        if any(x.startswith("user_") for x in constraints) and not self.static:
            raise ValueError("The exploit has to be statically linked to support controlled user data!")

        regs = {x.split("_")[-1]:y for x, y in constraints.items() if x.startswith("reg_") or x.startswith("conv_")}
        user_data = {x.split("_")[-1]:y for x, y in constraints.items() if x.startswith("user_")}
        init_pc = constraints["init"]
        return template.render(sys_num=self.sys_num, regs=regs, init_pc=init_pc, user_data=user_data)

if __name__ == '__main__':
    import argparse
    from chain_builder import ChainBuilder

    import monkeyhex
    parser = argparse.ArgumentParser(description='Scripts to evaluate stability of kernel exploits',
                                     usage="%(prog)s [options] -c <CVE number>")
    parser.add_argument('-k', '--kernel', type=str,
                        help="the path to the vulnerable kernel (bzImage)", required=True)
    parser.add_argument('-e', '--exp', type=str,
                        help="the path to the exploit binary", required=True)
    parser.add_argument('-m', '--module', type=str,
                        help="vulnerable module", default=None)
    args = parser.parse_args()

    # exp_path = os.path.abspath("../rand_kstack_success_rate/crash_poc")
    # kernel_path = os.path.abspath("../rand_kstack_success_rate/kernel/arch/x86/boot/bzImage")
    # mod_path = os.path.abspath("../rand_kstack_success_rate/vuln_module/vuln.ko")

    with Analyzer(args.exp, args.kernel, mod_path=args.module) as analyzer:
        analyzer.get_raw_info()
        analyzer.analyze_layout()
        sim_stack = [0 if type(x) == str and x.startswith("uninit_mem") else x for x in analyzer.sim_stack]
        analyzer.print_stack(analyzer.sim_stack)
        with ChainBuilder(args.kernel, sim_stack, analyzer.symbols) as builder:
            builder.get_gadgets()
            builder.analyze_rdi_gadgets()
            constraints = builder.find_solve()
            print(monkeyhex.maybe_hex(constraints))
        #analyzer.print_stack(analyzer.sim_stack)
        print(analyzer.dump(constraints))
