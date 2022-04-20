#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME "lab2"
#define SIZE (50 << 20)
#define SECTOR_SIZE 512
#define SECTORS(s) (s / SECTOR_SIZE) // Size of Ram disk in sectors

static int major = 0;

static int disk_size = SIZE;

/* Structure associated with Block device*/
static struct mydiskdrive_dev
{
    // sector_t capacity;
    u8 *data;
    struct blk_mq_tag_set tag_set;
    struct request_queue *queue;
    struct gendisk *gdisk;
} device;

static int my_open(struct block_device *dev, fmode_t mode)
{
    pr_info(DEVICE_NAME ": open\n");
    return 0;
}

static void my_release(struct gendisk *gdisk, fmode_t mode)
{
    pr_info(DEVICE_NAME ": release\n");
}

static struct block_device_operations fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
};

static int rb_transfer(struct request *req, unsigned int *nr_bytes)
{
    int dir = rq_data_dir(req);
    int ret = 0;
    sector_t start_sector = blk_rq_pos(req);
    unsigned int sector_cnt = blk_rq_sectors(req);
    struct bio_vec bv;
#define BV_PAGE(bv) ((bv).bv_page)
#define BV_OFFSET(bv) ((bv).bv_offset)
#define BV_LEN(bv) ((bv).bv_len)
    struct req_iterator iter;
    sector_t sector_offset;
    unsigned int sectors;
    u8 *buffer;
    sector_offset = 0;
    rq_for_each_segment(bv, req, iter)
    {
        buffer = page_address(BV_PAGE(bv)) + BV_OFFSET(bv);
        if (BV_LEN(bv) % (SECTOR_SIZE) != 0)
        {
            printk(KERN_ERR "bio size is not a multiple ofsector size\n");
            ret = -EIO;
        }
        sectors = BV_LEN(bv) / SECTOR_SIZE;

        if (dir == WRITE)
        {
            memcpy((device.data) + ((start_sector + sector_offset) * SECTOR_SIZE), buffer, sectors * SECTOR_SIZE);
        }
        else
        {
            memcpy(buffer, (device.data) + ((start_sector + sector_offset) * SECTOR_SIZE), sectors * SECTOR_SIZE);
        }
        sector_offset += sectors;
        *nr_bytes += BV_LEN(bv);
    }

    if (sector_offset != sector_cnt)
    {
        printk("mydisk: bio info doesn't match with the request info");
        ret = -EIO;
    }
#undef BV_PAGE
#undef BV_OFFSET
#undef BV_LEN
    return ret;
}

static blk_status_t queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
    unsigned int nr_bytes = 0;
    blk_status_t status = BLK_STS_OK;
    struct request *rq = bd->rq;

    /* Start request serving procedure */
    blk_mq_start_request(rq);

    if (rb_transfer(rq, &nr_bytes) != 0)
    {
        status = BLK_STS_IOERR;
    }

    /* Notify kernel about processed nr_bytes */
    if (blk_update_request(rq, status, nr_bytes))
    {
        /* Shouldn't fail */
        BUG();
    }

    /* Stop request serving procedure */
    __blk_mq_end_request(rq, status);

    return status;
}

static struct blk_mq_ops mq_ops = {
    .queue_rq = queue_rq,
};


static int disk_size_mb;

static int my_set(const char *val, const struct kernel_param *kp)
{
    int n = 0;
    if (kstrtoint(val, 10, &n) != 0 || n <= 0) {
        pr_alert(DEVICE_NAME ": Failed to cast disk_size parameter to integer\n");
        return -EINVAL;
    }
    if (param_set_int(val, kp) != 0) {
        pr_alert(DEVICE_NAME ": Failed to set disk_size parameter\n");
        return -1;
    }

    disk_size = disk_size_mb << 20;
    pr_alert(DEVICE_NAME ": Parameters set: disk_size_mb = %d, disk_size = %d\n", disk_size_mb, disk_size);
    if (device.data) {
        vfree(device.data);
        device.data = vmalloc(disk_size);
        if (!device.data) {
            pr_alert(DEVICE_NAME ": Failed to reallocate device IO buffer\n");
            return -ENOMEM;
        }
        set_capacity(device.gdisk, SECTORS(disk_size));
    }

    return 0;
}

static const struct kernel_param_ops param_ops = {
    .set = my_set,
    .get = param_get_int,
};

module_param_cb(disk_size, &param_ops, &disk_size_mb, 0664);


int device_setup(void)
{
    pr_info(DEVICE_NAME ": Setting up: disk_size = %d\n", disk_size);
    major = register_blkdev(major, DEVICE_NAME);
    device.data = vmalloc(disk_size);

    if (!device.data)
    {
        pr_alert(DEVICE_NAME ": Failed to allocate device IO buffer\n");
        unregister_blkdev(major, DEVICE_NAME);
        return -ENOMEM;
    }

    device.queue = blk_mq_init_sq_queue(&device.tag_set, &mq_ops, 128, BLK_MQ_F_SHOULD_MERGE);

    if (!device.queue)
    {
        pr_alert(DEVICE_NAME ": Failed to allocate device queue\n");
        vfree(device.data);
        unregister_blkdev(major, DEVICE_NAME);
        return -ENOMEM;
    }

    /* Set driver's structure as user data of the queue */
    device.queue->queuedata = &device;

    /* Allocate new disk */
    device.gdisk = alloc_disk(8);
    device.gdisk->major = major;
    device.gdisk->first_minor = 0;
    device.gdisk->flags = GENHD_FL_NO_PART_SCAN;

    device.gdisk->fops = &fops;
    device.gdisk->queue = device.queue;
    device.gdisk->private_data = &device;

    /* Set device name as it will be represented in /dev */
    sprintf(device.gdisk->disk_name, DEVICE_NAME);

    pr_info(DEVICE_NAME ": Adding disk %s\n", device.gdisk->disk_name);

    /* Set device capacity */
    set_capacity(device.gdisk, SECTORS(disk_size));

    /* Notify kernel about new disk device */
    add_disk(device.gdisk);

    pr_info(DEVICE_NAME ": Setup finished\n");

    return 0;
}

static int __init mydiskdrive_init(void)
{
    return device_setup();
}

void __exit mydiskdrive_exit(void)
{
    del_gendisk(device.gdisk);
    put_disk(device.gdisk);
    blk_cleanup_queue(device.queue);
    unregister_blkdev(major, DEVICE_NAME);
    vfree(device.data);
}

module_init(mydiskdrive_init);
module_exit(mydiskdrive_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Author");
MODULE_DESCRIPTION("BLOCK DRIVER");
