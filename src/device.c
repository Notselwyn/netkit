#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/device.h>

#include "device.h"
#include "command.h"
#include "auth.h"
#include "packet.h"

#define DEVICE_NAME "netkit"

static struct class *device_class = NULL;
static int device_major = 0;

static int device_open(struct inode *inode, struct file *file)
{
    pr_err("[*] device open...\n");

    return 0;
}

static ssize_t device_read(struct file *file, char __user *user_buffer, size_t count, loff_t *offset)
{
    char *kernel_data = "Hello from kernel";
    ssize_t data_len = strlen(kernel_data); 

    pr_err("[*] device read...\n");

    if (count > data_len)
        count = data_len;

    if (copy_to_user(user_buffer, kernel_data, count))
        return -EFAULT;

    return count;
}

static ssize_t device_write(struct file *file, const char __user *user_buf, size_t count, loff_t *offset)
{
    struct raw_packet_header *raw_packet;
    packet_t *packet;

    pr_err("[*] device write...\n");

    raw_packet = kmalloc(count, GFP_KERNEL);
    if (!raw_packet)
        return -ENOMEM;

    if (copy_from_user(raw_packet, user_buf, count))
        goto ERR;

    packet = packet_init(raw_packet, count);
    if (!packet)
        goto ERR;

    process_request(packet);

    PUT_REF(packet);

    return count;

ERR:
    kfree(raw_packet);
    return -EFAULT;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .read = device_read,
    .write = device_write,
};

/**
 * major: the major number of the device
 *  if major < 0, an error occured
 */
int device_init(void)
{
    device_major = register_chrdev(0, DEVICE_NAME, &fops);
    if (device_major < 0)
    {
        pr_err("[!] failed to register character device (err: %d)\n", device_major);

        return device_major;
    }

    device_class = class_create("netkit_device_class");
    if (IS_ERR(device_class))
    {
        pr_err("[!] failed to create device class\n");
        unregister_chrdev(device_major, DEVICE_NAME);
        
        return PTR_ERR(device_class);
    }

    device_create(device_class, NULL, MKDEV(device_major, 0), NULL, DEVICE_NAME);
    pr_err("[+] device loaded (major: %d)\n", device_major);

    return device_major;
}

int device_exit(void)
{
    pr_err("[*] exiting device... (major: %d, class: %p)\n", device_major, device_class);

    device_destroy(device_class, MKDEV(device_major, 0));
    class_unregister(device_class);
    class_destroy(device_class);
    unregister_chrdev(device_major, DEVICE_NAME);

    device_class = NULL;
    device_major = 0;
    
    return 0;
}