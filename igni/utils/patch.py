import gdb

import os
import re
import struct
import traceback
import subprocess

# fix python environment
prefix = subprocess.check_output(["python3", "-c", "import os, sys;print((sys.prefix))"]).strip()
if prefix != sys.base_prefix:
    SITE_PACKAGES_DIRS = subprocess.check_output(["python3", "-c", "import os, sys;print(os.linesep.join(sys.path).strip())"]).decode("utf-8").split()
    sys.path.extend(SITE_PACKAGES_DIRS)

# suppress the terminal requirement in pwntools
os.environ["PWNLIB_NOTERM"] = "1"
from pwnlib.tubes.remote import remote
from pwnlib.asm import asm
from pwnlib.util.cyclic import cyclic

############################ Configuration ############################
def u64(val):
    return struct.unpack('<Q', val)[0]

def p8(val):
    return struct.pack('<B', val)

def p32(val):
    return struct.pack('<I', val)

calling_taints = {
        "rdi": b'z'*8,
        "rsi": b'y'*8,
        "rdx": b'x'*8,
        "r8":  b'w'*8,
        "r9":  b'v'*8,
        "r10": b'u'*8,
        "rbx": b't'*8,
        "rbp": b's'*8,
        "r12": b'r'*8,
        "r13": b'q'*8,
        "r14": b'p'*8,
        "r15": b'o'*8,
        }

############################ Initialization ############################
port = int(gdb.parse_and_eval("$port"))
entry = int(gdb.parse_and_eval("$entry"))
entry_end = int(gdb.parse_and_eval("$entry_end"))
irq_end = int(gdb.parse_and_eval("$irq_end"))
do_syscall = int(gdb.parse_and_eval("$do_syscall"))
fast_path = int(gdb.parse_and_eval("$fast_path"))
taint_regs = str(gdb.parse_and_eval("$taint_regs")).strip('"').split(',')
taint_regs = [x for x in taint_regs if x]
sys_num = int(gdb.parse_and_eval("$sys_num"))

gdb.execute("set disassembly-flavor intel")
gdb.execute("target remote :%d" % port)
inferior = gdb.inferiors()[0]
print("port:", port)
print("entry_end:", hex(entry_end))
print("irq_end:", hex(irq_end))

def get_line_addr(line):
    res = re.search(r'0x[0-9a-f]{16}', line.split(':')[0])
    assert res
    return int(res.group(0), 16)

def patch(inst_addr, inst_size, code_start, code_mem):
    assert inst_size >= 5
    # step 1: nop out the stub
    inferior.write_memory(inst_addr, b'\x90'*inst_size)

    # step 2: jmp to the code region
    diff = code_start - (inst_addr+5) # jmp xxx is 5 bytes
    inferior.write_memory(inst_addr, b'\xe9'+p32(diff))

    # step 3: write the code
    addr = code_start
    inferior.write_memory(addr, code_mem)
    addr += len(code_mem)

    # step 4: jmp back to the end of the stub
    diff = (1<<32) - (addr + 5 - inst_addr - inst_size)
    inst = b'\xe9' + p32(diff)
    inferior.write_memory(addr, inst)
    addr += len(inst)
    return addr

def patch_fast_path(code_start):
    # find the instruction to invoke the syscall handler
    call_addr = None
    call_target = None
    next_addr = None
    next_size = None
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
        next_next_addr = get_line_addr(line)
        next_size = next_next_addr - next_addr

        break
    print(f"call_addr: {call_addr:#x}")
    print(f"size: {size}")
    assert call_addr is not None
    assert size >= 5
    assert next_size >=5

    ######################## Patching ##########################

    addr = code_start

    # overwrite call __x86_indirect_thunk_rax to call our code
    # somehow this is the only way to make it work properly, the jump patch does not work
    diff = addr - call_addr - 5
    if diff < 0: diff += (1<<32)
    inferior.write_memory(call_addr, b'\xe8' + p32(diff))

    taint_insts = b''

    # clear stack
    taint_insts += asm("push rax; push rdi; push rcx;", arch='amd64') # preserve values
    taint_insts += asm("lea rdi, [rsp-0x1000]; movabs rax,0x5a5a5a5a5a5a5a5a; mov ecx,0x1000; shr ecx, 0x3; rep stos QWORD PTR es:[rdi], rax;", arch='amd64') # do clearing
    taint_insts += asm("pop rcx; pop rdi; pop rax;", arch='amd64') # restore preserved values

    # assemble the taint instructions
    for reg in taint_regs:
        taint_insts += asm(f"movabs {reg}, {u64(calling_taints[reg]):#x}", arch='amd64')

    # save extra registers
    sc = b''
    sc += asm("mov [rsp+0x8], r15", arch='amd64')
    sc += asm("mov [rsp+0x10], r14", arch='amd64')
    sc += asm("mov [rsp+0x18], r13", arch='amd64')
    sc += asm("mov [rsp+0x20], r12", arch='amd64')
    sc += asm("mov [rsp+0x28], rbp", arch='amd64')
    sc += asm("mov [rsp+0x30], rbx", arch='amd64')

    # insert cmp rax, sys_num
    sc += asm(f"cmp qword ptr [rsp+0x80], {sys_num}", arch='amd64')

    # insert jne out
    sc += b'\x0f\x85' + p32(len(taint_insts))

    # insert the taint instructions
    sc += taint_insts

    # finally, jump to the syscall handler
    diff = call_target - addr - len(sc) - 5
    if diff < 0: diff += (1<<32)
    sc += b'\xe9' + p32(diff)

    # write the shellcode!
    inferior.write_memory(code_start, sc)

    # retore extra registers
    sc2 = b''
    sc2 += asm("mov r15, [rsp]", arch='amd64')
    sc2 += asm("mov r14, [rsp+0x8]", arch='amd64')
    sc2 += asm("mov r13, [rsp+0x10]", arch='amd64')
    sc2 += asm("mov r12, [rsp+0x18]", arch='amd64')
    sc2 += asm("mov rbp, [rsp+0x20]", arch='amd64')
    sc2 += asm("mov rbx, [rsp+0x28]", arch='amd64')
    sc2 += asm("mov [rsp+0x50], rax", arch='amd64')
    return patch(next_addr, size, code_start+len(sc), sc2)

def patch_do_syscall(code_start):
    # find the instruction to invoke do_syscall_64
    call_addr = None
    call_target = None
    next_addr = None
    size = None
    output = gdb.execute(f"x/200i {entry:#x}", False, True)
    lines = output.splitlines()
    # print(output)
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

    addr = code_start

    taint_insts = b''

    # clear stack
    taint_insts += asm("push rax; push rdi; push rcx;", arch='amd64') # preserve values
    taint_insts += asm("lea rdi, [rsp-0x1000]; movabs rax,0x5a5a5a5a5a5a5a5a; mov ecx,0x1000; shr ecx, 0x3; rep stos QWORD PTR es:[rdi], rax;", arch='amd64') # do clearing
    taint_insts += asm("pop rcx; pop rdi; pop rax;", arch='amd64') # restore preserved values

    # assemble the taint instructions
    for reg in taint_regs:
        taint_insts += asm(f"movabs {reg}, {u64(calling_taints[reg]):#x}", arch='amd64')

    # insert cmp rax, sys_num
    sc = b'H=' + p32(sys_num) # cmp rax, sys_num

    # insert jne out
    sc += b'\x0f\x85' + p32(len(taint_insts))

    # insert the taint instructions
    sc += taint_insts

    # call do_syscall_64
    diff = call_target - code_start - len(sc) - 5
    if diff < 0: diff += (1<<32)
    sc += b'\xe8' + p32(diff)

    return patch(call_addr, size, code_start, sc)

def do_patch():
    gdb.execute(f"b *{entry:#x}")
    gdb.execute("continue")

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

    # patch syscall entry to perform un-init memory analysis and calling convention analysis
    # if there is a fast path, we should patch the fast path. Otherwise, we patch the call to do_syscall_64
    if fast_path:
        addr = patch_fast_path(addr)
    else:
        addr = patch_do_syscall(addr)

try:
    do_patch()
    print("SUCCESS!!!")
    gdb.execute("detach")
except Exception:
    print(traceback.format_exc())
    gdb.execute("kill")

# exit
gdb.execute("quit")
