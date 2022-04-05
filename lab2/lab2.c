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
#define SECTORS (SIZE / SECTOR_SIZE)  // Size of Ram disk in sectors
#define MBR_SIZE SECTOR_SIZE
#define MBR_DISK_SIGNATURE_OFFSET 440
#define MBR_DISK_SIGNATURE_SIZE 4
#define PARTITION_TABLE_OFFSET 446
#define PARTITION_ENTRY_SIZE 16
#define PARTITION_TABLE_SIZE 64
#define MBR_SIGNATURE_OFFSET 510
#define MBR_SIGNATURE_SIZE 2
#define MBR_SIGNATURE 0xAA55
#define BR_SIZE SECTOR_SIZE
#define BR_SIGNATURE_OFFSET 510
#define BR_SIGNATURE_SIZE 2
#define BR_SIGNATURE 0xAA55

static int major = 0;

typedef struct
{
    unsigned char boot_type; // 0x00 - Inactive; 0x80 - Active (Bootable)
    unsigned char start_head;
    unsigned char start_sec : 6;
    unsigned char start_cyl_hi : 2;
    unsigned char start_cyl;
    unsigned char part_type;
    unsigned char end_head;
    unsigned char end_sec : 6;
    unsigned char end_cyl_hi : 2;
    unsigned char end_cyl;
    unsigned int abs_start_sec;
    unsigned int sec_in_part;
} PartEntry;

typedef PartEntry PartTable[4];

#define SEC_PER_HEAD 63
#define HEAD_PER_CYL 255
#define HEAD_SIZE (SEC_PER_HEAD * SECTOR_SIZE)
#define CYL_SIZE (SEC_PER_HEAD * HEAD_PER_CYL * SECTOR_SIZE)

#define sec4size(s) ((((s) % CYL_SIZE) % HEAD_SIZE) / SECTOR_SIZE)
#define head4size(s) (((s) % CYL_SIZE) / HEAD_SIZE)
#define cyl4size(s) ((s) / CYL_SIZE)

#define SECTORS_10_MB (10 * 1024 * 1024 / SECTOR_SIZE)
#define SECTORS_20_MB (20 * 1024 * 1024 / SECTOR_SIZE)

static PartTable def_part_table = {
    {
      boot_type : 0x00,
      start_sec : 0x1,
      start_head : 0x0,
      start_cyl_hi : 0x0,
      start_cyl : 0x0,
      part_type : 0x83,
      end_head : head4size(SECTORS_10_MB - 1),
      end_sec : sec4size(SECTORS_10_MB - 1) + 1,
      end_cyl_hi : (cyl4size(SECTORS_10_MB - 1) >> 8) & 0x3,
      end_cyl : cyl4size(SECTORS_10_MB - 1) & 0xFF,
      abs_start_sec : 0x1,
      sec_in_part : SECTORS_10_MB
    },
    {
      boot_type : 0x00,
      start_head : head4size(SECTORS_10_MB),
      start_sec : sec4size(SECTORS_10_MB) + 1,
      start_cyl_hi : (cyl4size(SECTORS_10_MB) >> 8) & 0x3,
      start_cyl : cyl4size(SECTORS_10_MB) & 0xFF,
      part_type : 0x83,
      end_sec : sec4size(SECTORS_10_MB + SECTORS_20_MB - 1) + 1,
      end_head : head4size(SECTORS_10_MB + SECTORS_20_MB - 1),
      end_cyl_hi : (cyl4size(SECTORS_10_MB + SECTORS_20_MB - 1) >> 8) & 0x3,
      end_cyl : cyl4size(SECTORS_10_MB + SECTORS_20_MB - 1) & 0xFF,
      abs_start_sec : SECTORS_10_MB + 1,
      sec_in_part : SECTORS_20_MB
    },
    {
      boot_type : 0x00,
      start_head : head4size(SECTORS_10_MB + SECTORS_20_MB),
      start_sec : sec4size(SECTORS_10_MB + SECTORS_20_MB) + 1,
      start_cyl_hi : (cyl4size(SECTORS_10_MB + SECTORS_20_MB) >> 8) & 0x3,
      start_cyl : cyl4size(SECTORS_10_MB + SECTORS_20_MB) & 0xFF,
      part_type : 0x05,
      end_sec : sec4size(SECTORS_10_MB + SECTORS_20_MB + SECTORS_20_MB - 1) + 1,
      end_head : head4size(SECTORS_10_MB + SECTORS_20_MB + SECTORS_20_MB - 1),
      end_cyl_hi :
              (cyl4size(SECTORS_10_MB + SECTORS_20_MB + SECTORS_20_MB - 1) >> 8) & 0x3,
      end_cyl : cyl4size(SECTORS_10_MB + SECTORS_20_MB + SECTORS_20_MB - 1) & 0xFF,
      abs_start_sec : SECTORS_10_MB + SECTORS_20_MB + 1,
      sec_in_part : SECTORS_20_MB + 2
    }};

static unsigned int def_log_part_br_abs_start_sector[] = {
    SECTORS_10_MB + SECTORS_20_MB + 1,
    SECTORS_10_MB + SECTORS_20_MB + SECTORS_10_MB + 2,
};

static const PartTable def_log_part_table[] = {
    {{
       boot_type : 0x00,
       start_head : 0,
       start_sec : 1,
       start_cyl_hi : 0,
       start_cyl : 0,
       part_type : 0x83,
       end_sec : sec4size(SECTORS_10_MB - 1) + 1,
       end_head : head4size(SECTORS_10_MB - 1),
       end_cyl_hi : (cyl4size(SECTORS_10_MB - 1) >> 8) & 0x3,
       end_cyl : cyl4size(SECTORS_10_MB - 1) & 0xFF,
       abs_start_sec : 0x1,
       sec_in_part : SECTORS_10_MB
     },
     {
       boot_type : 0x00,
       start_head : sec4size(SECTORS_10_MB) + 1,
       start_sec : head4size(SECTORS_10_MB),
       start_cyl_hi : (cyl4size(SECTORS_10_MB) >> 8) & 0x3,
       start_cyl : cyl4size(SECTORS_10_MB) & 0xFF,
       part_type : 0x05,
       end_sec : sec4size(SECTORS_10_MB + SECTORS_10_MB - 1) + 1,
       end_head : head4size(SECTORS_10_MB + SECTORS_10_MB - 1),
       end_cyl_hi : (cyl4size(SECTORS_10_MB + SECTORS_10_MB - 1) >> 8) & 0x3,
       end_cyl : cyl4size(SECTORS_10_MB + SECTORS_10_MB - 1) & 0xFF,
       abs_start_sec : SECTORS_10_MB + 1,
       sec_in_part : SECTORS_10_MB
     }},
    {{
      boot_type : 0x00,
      start_head : sec4size(SECTORS_10_MB) + 1,
      start_sec : head4size(SECTORS_10_MB),
      start_cyl_hi : (cyl4size(SECTORS_10_MB) >> 8) & 0x3,
      start_cyl : cyl4size(SECTORS_10_MB) & 0xFF,
      part_type : 0x83,
      end_sec : sec4size(SECTORS_10_MB + SECTORS_10_MB - 1) + 1,
      end_head : head4size(SECTORS_10_MB + SECTORS_10_MB - 1),
      end_cyl_hi : (cyl4size(SECTORS_10_MB + SECTORS_10_MB - 1) >> 8) & 0x3,
      end_cyl : cyl4size(SECTORS_10_MB + SECTORS_10_MB - 1) & 0xFF,
      abs_start_sec : SECTORS_10_MB + 1,
      sec_in_part : SECTORS_10_MB
    }}};

static void copy_mbr(u8 *disk)
{
    memset(disk, 0x0, MBR_SIZE);
    *(unsigned long *)(disk + MBR_DISK_SIGNATURE_OFFSET) = 0x36E5756D;
    memcpy(disk + PARTITION_TABLE_OFFSET, &def_part_table, PARTITION_TABLE_SIZE);
    *(unsigned short *)(disk + MBR_SIGNATURE_OFFSET) = MBR_SIGNATURE;
}

static void copy_br(u8 *disk, int abs_start_sector, const PartTable *part_table)
{
    disk += (abs_start_sector * SECTOR_SIZE);
    memset(disk, 0x0, BR_SIZE);
    memcpy(disk + PARTITION_TABLE_OFFSET, part_table,
           PARTITION_TABLE_SIZE);
    *(unsigned short *)(disk + BR_SIGNATURE_OFFSET) = BR_SIGNATURE;
}

void copy_mbr_n_br(u8 *disk)
{
    int i;

    copy_mbr(disk);
    for (i = 0; i < ARRAY_SIZE(def_log_part_table); i++)
    {
        copy_br(disk, def_log_part_br_abs_start_sector[i], &def_log_part_table[i]);
    }
}

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

static blk_status_t queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data* bd)
{
    unsigned int nr_bytes = 0;
    blk_status_t status = BLK_STS_OK;
    struct request *rq = bd->rq;

    /* Start request serving procedure */
    blk_mq_start_request(rq);

    if (rb_transfer(rq, &nr_bytes) != 0) {
        status = BLK_STS_IOERR;
    }

    /* Notify kernel about processed nr_bytes */
    if (blk_update_request(rq, status, nr_bytes)) {
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

int device_setup(void)
{
    major = register_blkdev(major, DEVICE_NAME);
    device.data = vmalloc(SIZE);
    copy_mbr_n_br(device.data);

    if (!device.data) {
        pr_alert(DEVICE_NAME ": Failed to allocate device IO buffer\n");
        unregister_blkdev(major, DEVICE_NAME);
        return -ENOMEM;
    }

    device.queue = blk_mq_init_sq_queue(&device.tag_set, &mq_ops, 128, BLK_MQ_F_SHOULD_MERGE);

    if (!device.queue) {
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

    device.gdisk->fops = &fops;
    device.gdisk->queue = device.queue;
    device.gdisk->private_data = &device;

    /* Set device name as it will be represented in /dev */
    sprintf(device.gdisk->disk_name, DEVICE_NAME);

    pr_info(DEVICE_NAME ": Adding disk %s\n", device.gdisk->disk_name);

    /* Set device capacity */
    set_capacity(device.gdisk, SECTORS);

    /* Notify kernel about new disk device */
    add_disk(device.gdisk);

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
