CC=gcc
ARCH=x86_64
KERNEL_ROOT=../../../scripts/kernel_builder/kernel/
obj-m += vuln.o

all:
	make ARCH=$(ARCH) -C $(KERNEL_ROOT) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_ROOT) M=$(PWD) clean

