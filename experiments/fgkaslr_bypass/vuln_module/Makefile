CC=gcc
ARCH=x86_64
KERNEL_ROOT=../kernel/
obj-m += vuln.o

all:
	make ARCH=$(ARCH) -C $(KERNEL_ROOT) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_ROOT) M=$(PWD) clean

