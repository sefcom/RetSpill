import subprocess

UNISTD_HEADER = "kernel/arch/x86/include/generated/uapi/asm/unistd_64.h"

class SYSCALL:
    def __init__(self, name):
        self.name = name
        self.sys_num = None
        self.arg_num = None

    def set_sys_num(self, sys_num):
        self.sys_num = sys_num

    def set_arg_num(self, arg_num):
        self.arg_num = arg_num

    def __repr__(self):
        return f"SYSCALL: {self.name}, {self.sys_num}, {self.arg_num}"

def get_syscalls():
    syscalls = []
    with open(UNISTD_HEADER, "r") as f:
        for line in f:
            if not line.startswith("#define __NR"):
                continue

            stuff = line.strip().split()
            assert stuff[1].startswith("__NR_")
            name = stuff[1][5:]
            sys_num = int(stuff[2])

            call = SYSCALL(name)
            call.set_sys_num(sys_num)

            syscalls.append(call)
    return syscalls

def get_syscall_declarations():
    decs = {}
    output = subprocess.getoutput("grep -r -G '^SYSCALL_DEFINE.(' kernel")
    lines = output.splitlines()
    lines = [x for x in lines if ('arch' not in x) or 'arch/x86' in x]
    for line in lines:
        desc = line.split(":")[1]
        stuff = desc.split('(')
        arg_num = int(stuff[0][-1])
        name = stuff[1].split(',')[0].strip(')')
        decs[name] = arg_num

    # manually add some declarations
    # reference: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
    decs['rt_sigreturn'] = 1
    decs['_sysctl'] = 1
    decs['umount2'] = 2
    decs['ioperm'] = 3
    decs['create_module'] = 6 # removed
    decs['get_kernel_syms'] = 6 # removed
    decs['query_module'] = 6 # removed
    decs['nfsservctl'] = 6 # not implemented
    decs['getpmsg'] = 6 # not implemented
    decs['putpmsg'] = 6 # not implemented
    decs['afs_syscall'] = 6 # not implemented
    decs['tuxcall'] = 6 # not implemented
    decs['security'] = 6 # not implemented
    decs['epoll_ctl_old'] = 6 # not implemented
    decs['epoll_wait_old'] = 6 # not implemented
    decs['vserver'] = 6 # not implemented
    return decs

syscalls = get_syscalls()
decs = get_syscall_declarations()
for dec_name, arg_num in decs.items():
    for syscall in syscalls:
        if syscall.name == dec_name:
            syscall.set_arg_num(arg_num)
# for syscall in syscalls:
#     print(syscall)
#     assert syscall.arg_num is not None
string = ""
for i in range(len(syscalls)):
    assert syscalls[i].sys_num == i
    string += f", {syscalls[i].arg_num}"
string = "{" + string[2:]+"}"
print(string)
