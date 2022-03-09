#include <linux/cdev.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("anton");
MODULE_DESCRIPTION("io-lab1");
MODULE_VERSION("1.0");

#define DEVICE_NAME "var2"
#define WRITE_BUF_LEN 256
#define RESULT_BUF_LEN 256
#define HISTORY_DATA_LEN 2048

static struct class * cls;
static dev_t major;
static struct cdev cdev;
static struct proc_dir_entry * entry;

static char msg[HISTORY_DATA_LEN];

static int parse_simple_expr(const char * expr, int * result)
{
    int ind = 0;
    int left = 0;

    bool left_neg = false;
    if (expr[ind] == '-') {
        left_neg = true;
        ind++;
    }
    else if (ind == '+') {
        ind++;
    }

    while (isdigit(expr[ind])) {
        left = left * 10 + (expr[ind] - '0');
        ind++;
    }

    if (left_neg) left = -left;

    char op;

    switch (expr[ind]) {
        case '+':
        case '-':
        case '*':
        case '/':
            op = expr[ind];
            break;
        default:
            return -1;
    }

    ind++;

    int right = 0;

    bool right_neg = false;
    if (expr[ind] == '-') {
        right_neg = true;
        ind++;
    }
    else if (ind == '+') {
        ind++;
    }

    while (isdigit(expr[ind])) {
        right = right * 10 + (expr[ind] - '0');
        ind++;
    }

    if (right_neg) right = -right;

    if (ind != strlen(expr)-1) {
        return -1;
    }

    switch (op) {
        case '+':
            *result = left + right;
            break;
        case '-':
            *result = left - right;
            break;
        case '*':
            *result = left * right;
            break;
        case '/':
            *result = left / right;
            break;
        default:
            return -1;
    }

    return 0;
}

static ssize_t proc_read(struct file * file, char __user * ubuf, size_t size, loff_t * offset) 
{
    ssize_t len = min(HISTORY_DATA_LEN, size);

    if (*offset > 0 || len == 0) {
        return 0;
    }

    if (copy_to_user(ubuf, msg, len)) {
        return -EFAULT;
    }

    *offset = len;
    return len;
}

static ssize_t device_read(struct file * file, char __user * ubuf, size_t size, loff_t * offset) 
{
    pr_info("Lab1: %s\n", msg);
    return 0;
}

static ssize_t device_write(struct file * file, const char __user * ubuf, size_t size, loff_t * offset)
{
    char input[WRITE_BUF_LEN];
    char result[RESULT_BUF_LEN];

    ssize_t len = min(WRITE_BUF_LEN, size);

    if (len == 0) {
        return 0;
    }

    if (copy_from_user(input, ubuf, len)) {
        return -EFAULT;
    }

    input[len] = '\0';

    int res;
    if (parse_simple_expr(input, &res) != 0) {
        sprintf(result, "Error\n");
    }
    else {
        sprintf(result, "%d\n", res);
    }


    strcat(msg, result);

    *offset = len;
    return len;
}

static const struct file_operations fops = {
    .write = device_write,
    .read = device_read,
};

static const struct proc_ops proc_file_ops = {
    .proc_read = proc_read
};

static int __init lab1_init(void)
{
    pr_info("INIT MODULE\n");

    if (alloc_chrdev_region(&major, 0, 1, DEVICE_NAME) != 0)
    {
        pr_alert("Failed to register character device");
        return -1;
    }

    if (!(cls = class_create(THIS_MODULE, DEVICE_NAME)))
    {
        unregister_chrdev_region(major, 1);
        return -1;
    }

    if (device_create(cls, NULL, major, NULL, DEVICE_NAME) == NULL)
    {
        class_destroy(cls);
        unregister_chrdev_region(major, 1);
        return -1;
    }

    cdev_init(&cdev, &fops);
    
    if (cdev_add(&cdev, major, 1) != 0)
    {
        device_destroy(cls, major);
        class_destroy(cls);
        unregister_chrdev_region(major, 1);
        return -1;
    }

    entry = proc_create(DEVICE_NAME, 0444, NULL, &proc_file_ops);

    pr_info("Device created on /dev/%s\n", DEVICE_NAME);

    return 0;
}

static void __exit lab1_exit(void)
{
    cdev_del(&cdev);
    device_destroy(cls, major);
    class_destroy(cls);
    unregister_chrdev_region(major, 1);

    proc_remove(entry);

    pr_info("DEINIT MODULE\n");
}

module_init(lab1_init);
module_exit(lab1_exit);