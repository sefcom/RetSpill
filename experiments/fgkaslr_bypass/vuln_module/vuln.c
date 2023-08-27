/**********************************
*
*  A vulnerable Linux kernel module to demonstrate the effectiveness
*  of retspill exploitation technique
*
***********************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/ioctl.h>

#include <asm/uaccess.h>

#define DEVICE_NAME "vuln"
#define DEVICE_CLASS_NAME "vuln_dev"

// define commands
#define IOCTL_BASE 'W'
#define	CMD_ALLOC	_IO(IOCTL_BASE, 0)
#define	CMD_WRITE	_IO(IOCTL_BASE, 1)
#define	CMD_READ	_IO(IOCTL_BASE, 2)
#define	CMD_CALL	_IO(IOCTL_BASE, 3)

/***************************************
 *
 * structs and global variables
 *
 ***************************************/

/* global variables */
static struct class *vuln_class;
static int major_num;
static struct file_operations file_ops;

typedef struct {
	void (*func)(void);
} vuln_obj_t;

static vuln_obj_t *obj = NULL;

/***************************************
 *
 * device driver code
 *
 ***************************************/

static int vuln_open(struct inode *inode, struct file *file)
{
	// printk(KERN_INFO "vulnerable device is opened\n");
	return 0;
}

static int vuln_release(struct inode *inode, struct file *file)
{
	if(obj) {
		kfree(obj);
		obj = NULL;
	}
	// printk(KERN_INFO "vulnerable device is closed\n");
	return 0;
}

static long vuln_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	printk(KERN_INFO "vuln_ioctl called with cmd: %d, arg: 0x%lx\n", cmd, arg);

	switch(cmd) {
		case CMD_ALLOC:
			obj = kzalloc(sizeof(vuln_obj_t), GFP_KERNEL);
			obj->func = (void(*)(void))(unsigned long long)&init_task; // just a random kernel data pointer for leaking kernel base
			// printk(KERN_INFO "obj is allocated @ 0x%lx\n", (unsigned long)obj);
			return 0;
		case CMD_WRITE:
			return copy_from_user(obj, (void *)arg, sizeof(obj));
		case CMD_READ:
			return copy_to_user((void *)arg, obj, sizeof(obj));
		case CMD_CALL:
			if(!obj) return -EINVAL;
			obj->func();
			return 0;
		default:
			return -EINVAL;
	}

	return -EINVAL;
}

static struct file_operations file_ops = { 
	.unlocked_ioctl = vuln_ioctl,
	.open = vuln_open,
	.release = vuln_release
};


/***************************************
 * 
 * kernel module related code
 *
 **************************************/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yihui Zeng; zengyhkyle@asu.edu");
MODULE_DESCRIPTION("A vulnerable Linux kernel module to demonstrate the effectiveness of retspill exploitation technique.");
MODULE_VERSION("0.01");

static int __init vuln_init(void)
{
	printk(KERN_INFO "vulnerable module initialization\n");

	// this registers 0x100 minor numbers
	major_num = register_chrdev(0, DEVICE_NAME, &file_ops);
	if(major_num < 0) {
		printk(KERN_WARNING "Fail to get major number");
		return -EINVAL;
	}

	/* populate a device node */
	vuln_class = class_create(THIS_MODULE, DEVICE_CLASS_NAME);
	device_create(vuln_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);

	return 0;
}

static void __exit vuln_exit(void)
{
	printk(KERN_INFO "vulneralbe module destruction\n");

	// destory the device node first
	device_destroy(vuln_class, MKDEV(major_num, 0));

	// destroy the device class
	class_destroy(vuln_class);

	// unregister chrdev
	unregister_chrdev(major_num, DEVICE_NAME);
}

module_init(vuln_init);
module_exit(vuln_exit);
