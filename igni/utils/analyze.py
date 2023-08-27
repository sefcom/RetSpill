import gdb

import re
import os
import sys
import json
import time
import signal
import struct
import traceback
import subprocess

# fix python environment
prefix = subprocess.check_output(["python3", "-c", "import os, sys;print((sys.prefix))"]).strip()
if prefix != sys.base_prefix:
    SITE_PACKAGES_DIRS = subprocess.check_output(["python3", "-c", "import os, sys;print(os.linesep.join(sys.path).strip())"]).decode("utf-8").split()
    sys.path.extend(SITE_PACKAGES_DIRS)

# suppress the terminal requirement in pwntools
import monkeyhex

os.environ["PWNLIB_NOTERM"] = "1"
from pwnlib.tubes.remote import remote
from pwnlib.asm import asm, disasm
from pwnlib.util.cyclic import cyclic
from pwnlib.util.packing import u64

##################### Configuration #########################
CRASH_ADDR = 0xffffffffdeadbeef
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
ARG_REGS = ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
offset_map = {'rax': -6, 'rdi':-7, 'rsi': -8, 'rdx': -9, 'r8': -12, 'r9': -13, 'r10': -14,
                'rbx': -16, 'rbp': -17, 'r12': -18, 'r13': -19, 'r14': -20, 'r15': -21}
calling_taints = {
        "rdi": u64(b'z'*8),
        "rsi": u64(b'y'*8),
        "rdx": u64(b'x'*8),
        "r8":  u64(b'w'*8),
        "r9":  u64(b'v'*8),
        "r10": u64(b'u'*8),
        "rbx": u64(b't'*8),
        "rbp": u64(b's'*8),
        "r12": u64(b'r'*8),
        "r13": u64(b'q'*8),
        "r14": u64(b'p'*8),
        "r15": u64(b'o'*8),
        }
TAG = b"snapshot"
INIT_TAG = b"init_snapshot"
SYSCALL_TAG = b"crashing_syscall_snapshot"
SYSCALL_WITH_USERDATA_TAG = b"crashing_syscall_with_userdata_snapshot"
MONITOR_PROMPT = b"(qemu) "

comm_offset = None
current_task_offset = None
nop_addr = None
execve_addr = None
xor_stub = None
do_syscall_end_addr = None
stack_top = None
stack_end = None
final_results = {}
#############################################################

##################### Initialization ########################
gdb_port = int(gdb.parse_and_eval("$gdb_port"))
monitor_port = int(gdb.parse_and_eval("$monitor_port"))
sys_num = int(gdb.parse_and_eval("$sys_num"))
entry = int(gdb.parse_and_eval("$entry"))
entry_end = int(gdb.parse_and_eval("$entry_end"))
irq_end = int(gdb.parse_and_eval("$irq_end"))
do_syscall = int(gdb.parse_and_eval("$do_syscall"))
fast_path = int(gdb.parse_and_eval("$fast_path"))
panic = int(gdb.parse_and_eval("$panic"))
set_brk = int(gdb.parse_and_eval("$set_brk"))
get_user_8 = int(gdb.parse_and_eval("$get_user_8"))
copy_from_user = int(gdb.parse_and_eval("$copy_from_user"))
oops_end = int(gdb.parse_and_eval("$oops_end"))

gdb.execute("set disassembly-flavor intel")
gdb.execute("set pagination off")
gdb.execute("target remote :%d" % gdb_port)
inferior = gdb.inferiors()[0]

# initialize QEMU monitor
class Monitor:
    def __init__(self, port):
        self.conn = remote("localhost", port, timeout=3)
        self.conn.recvuntil(b"QEMU")

    def save_snapshot(self, tag):
        self.conn.clean()
        self.conn.sendline(b"savevm " + tag)
        self.conn.recvuntil(b"savevm " + tag)

        output = self.conn.recvuntil(MONITOR_PROMPT)
        assert b"Error" not in output, output

    def list_snapshots(self):
        self.conn.clean()
        self.conn.sendline( b"info snapshots")
        self.conn.recvuntil(b"info snapshots")
        self.conn.recvline()

        output = self.conn.recvuntil(MONITOR_PROMPT)
        assert b'no block device can store' not in output, output
        return output.splitlines()

    def load_snapshot(self, tag):
        self.conn.clean()
        self.conn.sendline(b"loadvm " + tag)
        self.conn.recvuntil(b"loadvm " + tag)

        output = self.conn.recvuntil(MONITOR_PROMPT)
        assert b"Error" not in output, output

        # after loading the snapshot, we need to ensure that gdb actually sync the registers
        # and we are in the correct thread
        gdb.execute("maintenance flush register-cache")
        for thread in inferior.threads():
            thread.switch()
            if int(gdb.selected_frame().pc()) in [nop_addr, execve_addr]:
                break
        else:
            raise RuntimeError("Fail to sync registers")

monitor = Monitor(monitor_port)
#############################################################
def u64(val):
    return struct.unpack('<Q', val)[0]

def p32(val):
    return struct.pack('<I', val)

def read_u64(addr):
    return u64(inferior.read_memory(addr, 8).tobytes())

def get_line_addr(line):
    res = re.search(r'0x[0-9a-f]{16}', line.split(':')[0])
    assert res
    return int(res.group(0), 16)

def call_patch(call_addr, call_target, call_size, code_start):
    global execve_addr
    global nop_addr
    global do_syscall_end_addr

    assert call_size >= 5

    addr = code_start

    # step 1: nop out the stub
    inferior.write_memory(call_addr, b'\x90'*call_size)

    # overwrite the call to call our code
    diff = addr - call_addr - 5
    if diff < 0: diff += (1<<32)
    inferior.write_memory(call_addr, b'\xe8' + p32(diff))

    # speed up patch
    assembly1 = f"""
    cmp qword ptr [rsp+0x80], {sys_num};
    jne out;
    push rdi;
    mov rdi, QWORD PTR gs:{current_task_offset:#x};
    mov edi, dword ptr [rdi+{comm_offset}];
    cmp edi, 0x707865;
    jne fixed_out;
    pop rdi;
    nop;
    jmp out;
    fixed_out:
    pop rdi;
    out:
    """

    # snapshot stub
    assembly2 = f"""
    cmp qword ptr [rsp+0x80], 0x3b;
    jne out;
    push rdi;
    mov rdi, [rsp+0x80];
    cmp dword ptr [rdi], 0x706d742f;
    jne fixed_out;
    cmp dword ptr [rdi+4], 0x7078652f;
    jne fixed_out;
    pop rdi;
    nop;
    nop;
    jmp out
    fixed_out:
    pop rdi;
    out:
    """

    sc = asm(assembly1, arch='amd64') + asm(assembly2, arch='amd64')

    # now jump to the target function
    diff = call_target - addr - len(sc) - 5
    if diff < 0: diff += (1<<32)
    sc += b'\xe9' + p32(diff)

    execve_addr = code_start + sc.index(b'\x90\x90')
    nop_addr = code_start + sc.index(b'\x90')
    do_syscall_end_addr = call_addr + call_size

    # write the shellcode!
    inferior.write_memory(code_start, sc)

    return code_start + len(sc)

def patch_do_syscall(code_start):

    # find the instruction to invoke do_syscall_64
    call_addr = None
    call_target = None
    next_addr = None
    size = None
    output = gdb.execute(f"x/200i {entry:#x}", False, True)
    lines = output.splitlines()

    for i in range(len(lines)):
        line = lines[i]

        # there shouldn't be fast path check
        if 'test' in line and '0x900839df' in line and i != len(lines)-1 and 'jne' in lines[i+1]:
            raise

        if hex(do_syscall) not in line:
            continue

        # extract call target (do_syscall)
        res = re.search(r'0x[0-9a-f]{16}', line.split(':')[1])
        assert res
        call_target = int(res.group(0), 16)
        print("LINE!!!", line)

        # extract call instruction address
        call_addr = get_line_addr(line)

        # extract call instruction size
        assert i+1 < len(lines)
        line = lines[i+1]
        next_addr = get_line_addr(line)
        size = next_addr - call_addr

        break
    print(f"call_addr: {call_addr:#x}")
    print(f"size: {size}")
    assert call_addr is not None
    assert size >= 5

    ######################## Patching ##########################

    return call_patch(call_addr, call_target, size, code_start)

def patch_fast_path(code_start):

    # find the instruction to invoke the syscall handler
    call_addr = None
    call_target = None
    next_addr = None
    size = None
    output = gdb.execute(f"x/20i {fast_path:#x}", False, True)
    lines = output.splitlines()
    for i in range(len(lines)):
        line = lines[i]
        print(line)
        if 'call' not in line:
            continue

        # extract call target (syscall handler)
        # TODO: it may be just "call rax" if retpoline is disabled
        res = re.search(r'0x[0-9a-f]{16}', line.split(':')[1])
        assert res
        call_target = int(res.group(0), 16)
        print("LINE!!!", line)

        # extract call instruction address
        call_addr = get_line_addr(line)

        # extract call instruction size
        assert i+1 < len(lines)
        line = lines[i+1]
        next_addr = get_line_addr(line)
        size = next_addr - call_addr
        assert 'mov' in line and 'rsp+0x50' in line

        line = lines[i+2]
        do_syscall_end_addr = get_line_addr(line) + size
        break

    print(f"call_addr: {call_addr:#x}")
    print(f"size: {size}")
    assert call_addr is not None
    assert size >= 5

    ######################## Patching ##########################

    return call_patch(call_addr, call_target, size, code_start)

def do_patch():
    # decide where to put the code
    location = None
    mem = inferior.read_memory(entry_end, 0x100).tobytes()
    if mem == b'\xcc' * 0x100:
        location = entry_end
    mem = inferior.read_memory(irq_end, 0x100).tobytes()
    if mem == b'\x90' * 0x100:
        location = irq_end
    assert location is not None
    assert location > entry
    print(f"code location: {location:#x}")

    addr = location

    # valid user data analysis
    if fast_path:
        patch_fast_path(addr)
    else:
        patch_do_syscall(addr)

def run_to_the_end():
    monitor.load_snapshot(TAG)
    gdb.execute("continue")
    assert int(gdb.parse_and_eval("$rip")) == oops_end
    return int(gdb.parse_and_eval("((long*)$rdi)[19]"))

def get_status():
    pc = int(gdb.parse_and_eval("$rip"))
    if pc == nop_addr:
        return "ready"
    elif pc == oops_end:
        return "good_crash"
    elif pc == panic:
        return "bad_crash"
    elif pc == entry:
        return "timeout"
    raise RuntimeError(f"Land on unknown PC: {pc:#x}")

def _search_by_step(step, base_tag, save_tag):
    """
    make sure the snapshot will crash in <step> trigger syscalls by saving
    a snapshot every <step> trigger syscalls
    return: the upper limit of `continue` to trigger the expected crash
    """
    print("step:", step)
    # save the vm every <step> trigger syscalls
    monitor.load_snapshot(base_tag)

    # save a snapshot every <step> trigger syscalls
    cnt = 0
    while get_status() == "ready":
        monitor.save_snapshot(save_tag)
        gdb.execute(f"ignore 3 {step}")
        gdb.execute("continue")
        cnt += 1
        continue
    # print(gdb.execute("info b", False, True))
    gdb.execute(f"ignore 3 0")

    status = get_status()
    if status != "good_crash":
        return None

    return cnt*step

def search_by_step(step, base_tag, save_tag):
    for _ in range(3):
        res = _search_by_step(step, base_tag, save_tag)
        if res is not None:
            return res
        print("search_by_step: %d fails, retrying it again..." % step)
    return None

def extract_entry_regs(rsp):
    # look for stack top, since we do not know THREAD_SIZE, we use the stupid way:
    # search page by page
    top = rsp & ((1<<64)-0x1000) # this is top-0x1000
    while True:
        top += 0x1000
        if read_u64(top-8) != 0x000000000000002b:
            continue
        if read_u64(top-0x20) != 0x0000000000000033:
            continue
        if read_u64(top-0x30) != sys_num:
            continue
        break
    print(f"stack top: {top:#x}")

    # extract info from the stack and use it as the state
    arg_num = ARG_MAP[sys_num]
    arg_regs = ARG_REGS[:arg_num]
    regs = {x:read_u64(top+8*offset_map[x]) for x in arg_regs}
    regs["cr3"] = int(gdb.parse_and_eval("$cr3"))
    regs["rax"] = sys_num
    regs["rsp"] = top - 0xb0
    return regs

def look_for_crash_syscall():
    gdb.execute("disable 1")

    # break at executing the exploit and take a snapshot so we don't need to run the exploit again later
    gdb.execute(f"b *{execve_addr:#x}")
    gdb.execute("continue")
    monitor.save_snapshot(INIT_TAG)
    gdb.execute("disable 2")

    # break at the trigger syscall
    gdb.execute(f"b *{nop_addr:#x}")
    # break at oops_end with the expected argument so we know we hit the crash correctly
    # if the execution lands at oops_end
    gdb.execute(f"b *{oops_end:#x} if ($cr2 == {CRASH_ADDR-0x2a:#x} || $cr2 == {CRASH_ADDR:#x})")
    # if we reaches panic, that means an unexpected crash
    gdb.execute(f"b *{panic:#x}")

    # gradually approach the crashing syscall
    fail = True
    while fail:
        fail = False
        snapshot_tags = []
        steps = [2**i for i in range(11)]
        monitor.load_snapshot(INIT_TAG)

        # arrive at the first potential crashing syscall
        gdb.execute("continue")
        monitor.save_snapshot(TAG)

        base_tag = TAG
        for step in reversed(steps):
            print(step)
            step_tag = TAG+b'-'+str(step).encode()
            if search_by_step(step, base_tag, step_tag) is None:
                fail = True
                break
            base_tag = step_tag
            snapshot_tags.append(step_tag)

    # at this moment, we know that one continue can trigger the crash
    # although one continue does not guarantee the crash, it means
    # the crashing input is already triggered or the current syscall is
    # the crashing syscall. So, we are happy here. Let's go find the crashing syscall!

    # look for the crashing syscall
    # step 1: extract the state of the crashing syscall
    stack_end = int(gdb.parse_and_eval("(unsigned long)$rsp"))
    pc = int(gdb.parse_and_eval("$rip"))
    assert pc == oops_end
    entry_regs = extract_entry_regs(stack_end)
    # step 2: set breakpoint at the crashing syscall
    # we don't check rax because we are sure it is the correct syscall in a snapshot
    arg_num = ARG_MAP[sys_num]
    arg_regs = ARG_REGS[:arg_num]
    cmd = f"b *{nop_addr:#x} if " + " && ".join([f"*(unsigned long*)($rsp+{0xb0+offset_map[x]*8})=={entry_regs[x]:#x}" for x in arg_regs] + [f"${x}=={entry_regs[x]:#x}" for x in ['cr3', 'rsp']])
    print(cmd)
    gdb.execute(cmd)
    # now, cleanup the breakpoints so that there are only three breakpoints:
    # oops_end, panic, and the crashing syscall
    gdb.execute("disable 3")
    # step 3: look for the crashing syscall reversely
    for tag in reversed(snapshot_tags):
        print(tag)
        monitor.load_snapshot(tag)

        # first check whether it is already at the crashing syscall
        # we don't check rax because we are sure it is the correct syscall in a snapshot
        if all(int(gdb.parse_and_eval(f"*(unsigned long*)($rsp+{0xb0+offset_map[x]*8})")) == entry_regs[x] for x in arg_regs) and all(int(gdb.parse_and_eval("$"+x)) == entry_regs[x] for x in ['cr3', 'rsp']):
            break

        print("doing continue")
        gdb.execute("continue")
        if int(gdb.parse_and_eval("$rip")) == nop_addr:
            break
    else:
        raise RuntimeError("Fail to identify the crashing syscall, panic!")
    # step 4: now we are at the crashing syscall, save the snapshot!!!!
    monitor.save_snapshot(SYSCALL_TAG)
    return entry_regs, stack_end

def do_basic_analysis():
    global comm_offset
    global current_task_offset
    global xor_stub

    # first, use set_brk to identify current_task offset
    output = gdb.execute(f"x/100i {set_brk:#x}", False, True)
    lines = output.splitlines()
    line = None
    for line in lines:
        if 'gs:' in line:
            break
    assert line
    res = re.search('gs:(0x[0-9a-f]+)', line)
    assert res
    current_task_offset = int(res.group(1), 16)

    # now use the per-cpu current_task offset to search the comm offset in task struct
    gs_base = gdb.parse_and_eval("$gs_base")
    current = read_u64(gs_base+current_task_offset)
    task_mem = inferior.read_memory(current, 0x1000).tobytes()
    comm_offset = task_mem.index(b'init\x00')
    assert comm_offset >= 0

    # now, check whether the kernel xors registers before executing the syscall handler
    output = gdb.execute(f"x/200i {entry:#x}", False, True)
    lines = output.splitlines()
    for idx, line in enumerate(lines):
        if '\tcall' in line:
            break
    else:
        raise RuntimeError("Something wrong with the kernel, no 'call' instruction in syscall entry?")

    for line in lines[:idx]:
        if '\txor' in line:
            xor_stub = True
            break
    else:
        xor_stub = False

    print("xor_stub:", xor_stub)

def get_status2():
    pc = int(gdb.selected_frame().pc())
    rsp = int(gdb.parse_and_eval("$rsp"))
    rax = int(gdb.parse_and_eval(f"*(unsigned long*){stack_top-6*8:#x}"))
    if rsp > stack_top or rsp < stack_end-0x1000:
        return "irrelevant"
    elif pc == nop_addr: # this check must precede the rax check because rax is not pushed onto stack yet if it is here
        return "init"
    elif rax != sys_num:
        return "irrelevant"
    elif pc == oops_end:
        return "good_crash"
    elif pc == panic:
        return "bad_crash"
    elif pc in [copy_from_user, get_user_8]:
        return "logging"
    elif pc == do_syscall_end_addr:
        return "no_crash"
    raise RuntimeError(f"Land on unknown PC: {pc:#x}")

def log_all_user_input(entry_regs):
    # hook copy_from_user
    cr3 = entry_regs["cr3"]
    cmd = f"b *{copy_from_user:#x} if "
    cmd += f"$cr3=={cr3} && " # make sure it is the correct process
    cmd += f"$rdi<{stack_top:#x} && $rdi > {stack_end:#x} && " # make sure it overwrites on its own stack
    cmd += f"$rsp <= {stack_top:#x} && $rsp >= {stack_end:#x} && " # make sure it is the correct task
    cmd += f"*(long*){stack_top-6*8:#x} == {sys_num}" # make sure it is the correct syscall
    gdb.execute(cmd)

    # hook __get_user_8
    cmd = f"b *{get_user_8:#x} if "
    cmd += f"$cr3=={cr3} && " # make sure it is the correct process
    cmd += f"$rdi<{stack_top:#x} && $rdi > {stack_end:#x} && " # make sure it overwrites on its own stack
    cmd += f"$rsp <= {stack_top:#x} && $rsp >= {stack_end:#x} && " # make sure it is the correct task
    cmd += f"*(long*){stack_top-6*8:#x} == {sys_num}" # make sure it is the correct syscall
    gdb.execute(cmd)

    # now continue execution, if it lands on any of these two functions, log it until it crashes at the correct location
    user_data = []
    status = get_status2()
    while status not in ["good_crash", "bad_crash", "no_crash"]:
        if status == "logging":
            pc = int(gdb.selected_frame().pc())
            if pc == copy_from_user:
                dst_addr = int(gdb.parse_and_eval("(unsigned long)$rdi"))
                src_addr = int(gdb.parse_and_eval("(unsigned long)$rsi"))
                size = int(gdb.parse_and_eval("(unsigned long)$rdx"))
                print(f"copy_from_user: dst: {dst_addr:#x}, src: {src_addr:#x}, size: {size:#x}")
                user_data.append((src_addr, dst_addr, size))
            elif pc == get_user_8:
                src_addr = int(gdb.parse_and_eval("(unsigned long)$rax"))
                print(f"get_user_8: src: {src_addr:#x}, size: 0x8")
                user_data.append((src_addr, None, 8))
        gdb.execute("continue")
        status = get_status2()

    # disable the breakpoints
    gdb.execute("disable 7")
    gdb.execute("disable 8")
    print("Found user inputs in crashing syscall:")
    print(monkeyhex.maybe_hex(user_data))
    return user_data

def analyze_user_data(user_data, entry_regs):
    # cleanup break points
    gdb.execute("disable 6")
    # add a breakpoint at the return address of do_syscall_64 for the crashing syscall
    # so that we can catch it if the mutation fails the syscall instead of crashing the kernel
    cr3 = entry_regs["cr3"]
    cmd = f"b *{do_syscall_end_addr:#x} if "
    cmd += f"$cr3=={cr3} && " # make sure it is the correct process
    # cmd += f"$rdi<{stack_top:#x} && $rdi > {stack_end:#x} && " # make sure it overwrites on its own stack
    cmd += f"$rsp <= {stack_top:#x} && $rsp >= {stack_end:#x} && " # make sure it is the correct task
    cmd += f"*(long*){stack_top-6*8:#x} == {sys_num}" # make sure it is the correct syscall
    gdb.execute(cmd)

    # now cut the user data to mutation candidates
    mut_set = set()
    for addr, dst, size in user_data:
        print(hex(addr), hex(dst), hex(size))
        residual = dst % 8
        if residual != 0:
            addr += 8-residual
            dst += 8-residual

        for offset in range(0, size, 8):
            if offset + 8 < size:
                mut_set.add((addr+offset, dst+offset))

    controlled = set()
    pattern = cyclic(len(mut_set)*8)
    idx = 0
    # now for each mutation candidate, check whether it is controllable by attackers
    # FIXME: it will be better if we hook at timer interrupt instead of breakpoint 1 (syscall entry)
    gdb.execute("enable 1")
    for addr, dst in mut_set:
        taint = pattern[idx:idx+8]
        monitor.load_snapshot(SYSCALL_TAG)
        # do taint incrementally
        for x,_,z in controlled:
            inferior.write_memory(x, z)
        inferior.write_memory(addr, taint)
        # we overwrite the memory so anything can happen, for example, the task is killed maybe
        # or it goes into sleep waiting for something that does not exist, so, we set a timeout: 5s
        start = time.time()
        gdb.execute("ignore 1 100")
        gdb.execute("continue")
        while time.time() - start < 5 and int(gdb.selected_frame().pc()) == entry:
            gdb.execute("ignore 1 100")
            gdb.execute("continue")

        status = get_status2()
        if status == "good_crash":
            controlled.add((addr, dst, taint))
            idx += 8
    gdb.execute("ignore 1 0")
    gdb.execute("disable 1")

    # we get everything we want already
    # print out the result and crash the kernel
    data = [[x[0], x[1], u64(x[2])] for x in controlled]
    print("data:", monkeyhex.maybe_hex(data))
    #print("USER DATA ANALYSIS SUCCESS! |", json.dumps(data))
    final_results["copy_data"] = data

    monitor.load_snapshot(SYSCALL_TAG)
    for x,_,z in controlled:
        inferior.write_memory(x, z)

    # now save the snapshot
    monitor.save_snapshot(SYSCALL_WITH_USERDATA_TAG)

def taint_reg(reg):
    taint = calling_taints[reg]
    if not xor_stub:
        gdb.execute(f"set ${reg}={taint:#x}")
    ptr = stack_top + offset_map[reg]*8
    gdb.execute("set {long}(%#x)=%#x" % (ptr, taint))

def execute_syscall():
    start = time.time()
    gdb.execute("ignore 1 100")
    gdb.execute("continue")
    while time.time() - start < 5 and int(gdb.selected_frame().pc()) == entry:
        gdb.execute("ignore 1 100")
        gdb.execute("continue")
    return get_status2()

def analyze_regs():
    """
    load the crashing syscall snapshot and agressively mutate the valid arguments for the syscall
    in order to identify args that are not in use.
    Then we can analyze the whether those unused registers are saved onto stack
    """
    # step 1: identify the list of registers we want to analyze
    # basically, all the argument registers for the crashing syscall
    regs = ARG_REGS[:ARG_MAP[sys_num]]

    # step 2: mutate one register at a time and see whether it can still cause
    # a crash
    unused = set()
    for reg in reversed(regs):
        print("analyzing:", reg)
        # load snapshot at the crashing syscall
        monitor.load_snapshot(SYSCALL_WITH_USERDATA_TAG)

        # taint previously confirmed unused regs and this one
        for x in unused: taint_reg(x)
        taint_reg(reg)

        # now see whether it still crashes
        status = execute_syscall()
        if status == "good_crash":
            unused.add(reg)

    # step 3: check how each controlled value on stack is written
    # either through calling convention (push <reg>) or variable-saving (mov)
    results = {}

    # first crash the kernel
    monitor.load_snapshot(SYSCALL_WITH_USERDATA_TAG)
    for x in unused: taint_reg(x)
    status = execute_syscall()
    assert status == "good_crash"

    # extract stack content and find all the data locations
    rsp = int(gdb.parse_and_eval("$rsp"))
    stack = inferior.read_memory(rsp, stack_top-rsp).tobytes()
    stack = [u64(stack[i:i+8]) for i in range(0, len(stack), 8)]
    assert len(stack) > 21, "kernel crashes before finishing register pushing???"
    info = {}
    for i, val in enumerate(stack[:-21]):
        for reg, taint in calling_taints.items():
            if val == taint:
                addr = rsp + i*8
                info[addr] = reg
                results[addr] = "user"

    # somehow snapshot has some issues with hardware breakpoints
    # we have to use the breakpoints in that specific run
    monitor.load_snapshot(SYSCALL_WITH_USERDATA_TAG)

    # now set hardware breakpoints at all the locations
    for addr, reg in info.items():
        taint = calling_taints[reg]
        gdb.execute("watch *%#x if *(long *)%#x==%#x" % (addr, addr, taint))

    # now try to crash the kernel again while at the same time monitoring
    # data writes
    for x in unused: taint_reg(x)
    gdb.execute("disable 9")
    while True:
        gdb.execute("continue")
        pc = int(gdb.selected_frame().pc())
        if pc in [oops_end, panic]:
            break
        print(f"stop at pc: {pc:#x}")

        # try to see whether it is a push

        # (1). the data must be at the stack top to be a push
        #      if not, it might be a mov [rsp+X], Y
        rsp = int(gdb.parse_and_eval("$rsp"))
        if rsp not in info:
            continue
        if read_u64(rsp) != calling_taints[info[rsp]]:
            continue

        # (2). the potential previous instructions must be pushes
        data = inferior.read_memory(pc-2, 2).tobytes()
        potential_regs = set()
        for raw in [data[1:], data]:
            try:
                inst = disasm(raw, arch='amd64')
            except Exception:
                continue
            if 'push' not in inst:
                continue
            if '\n' in inst:
                continue
            reg = inst.split()[-1].strip()
            potential_regs.add(reg)

        # (3). at least one of the potential pushed registers holds the taint
        if any(int(gdb.parse_and_eval(f"${x}")) == calling_taints[info[rsp]] for x in potential_regs):
            results[rsp] = "conv"

    final_results["unused"] = list(unused)
    final_results["how"] = results

    print("unused:", unused)
    print("how:", monkeyhex.maybe_hex(results))

    monitor.load_snapshot(SYSCALL_WITH_USERDATA_TAG)
    for x in unused: taint_reg(x)

try:

    # first time enter syscall
    gdb.execute(f"b *{entry:#x}")
    gdb.execute("continue")

    # do static analysis for later use
    do_basic_analysis()

    do_patch()
    print("Patch Success!!!")

    entry_regs, stack_end = look_for_crash_syscall()
    stack_top = entry_regs["rsp"] + 0xb0
    print("Found the Crashing Syscall!!!")

    user_data = log_all_user_input(entry_regs)
    print("Successfully log all user input")

    user_data = analyze_user_data(user_data, entry_regs)
    print("Successfully analyzed directly controlled user data!")

    analyze_regs()

    print("Analysis Success!!! |", json.dumps(final_results))
    gdb.execute("detach")

except Exception:
    print(traceback.format_exc())
    gdb.execute("kill")

# exit
gdb.execute("quit")
