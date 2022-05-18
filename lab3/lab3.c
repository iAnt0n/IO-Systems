#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/moduleparam.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/proc_fs.h>

#define HISTORY_DATA_LEN 2048
static char msg[HISTORY_DATA_LEN];
static struct proc_dir_entry * proc_entry;

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

static const struct proc_ops proc_file_ops = {
    .proc_read = proc_read
};


static char * parent_if_name = "lo";
module_param(parent_if_name, charp, 0664);

static char * my_if_name = "virt";
module_param(my_if_name, charp, 0664);

static char * dest_ip = "127.0.0.11";
module_param(dest_ip, charp, 0664);

static struct net_device * my_interface = NULL;

struct priv {
    struct net_device_stats stats;
    struct net_device * parent;
};

static char frame_dest_ip_equals(struct sk_buff * skb, const char * target_ip) {
    struct iphdr * ip = (struct iphdr *) skb_network_header(skb);

    __be32 target = in_aton(target_ip);

	if (ip->version == 4 && ip->daddr == target) {
        return 1;
    }

    return 0;
}

static rx_handler_result_t handle_frame(struct sk_buff **pskb) {
   if (my_interface) {
        struct priv * priv = netdev_priv(my_interface);

        struct iphdr * ip = (struct iphdr *) skb_network_header(*pskb);

        if (frame_dest_ip_equals(*pskb, dest_ip)) {
            priv->stats.rx_packets++;
            priv->stats.rx_bytes += (*pskb)->len;

            char result[100];
            sprintf(result, "RX: src %pI4, dest %pI4\n", &ip->saddr, &ip->daddr);
            strcat(msg, result);
            pr_info("%s: %s", THIS_MODULE->name, result);
        }
    }
    return RX_HANDLER_PASS; 
} 

static int open(struct net_device *dev) {
    netif_start_queue(dev);
    pr_info("%s: device %s opened", THIS_MODULE->name, dev->name);
    return 0; 
} 

static int stop(struct net_device *dev) {
    netif_stop_queue(dev);
    pr_info("%s: device %s closed", THIS_MODULE->name, dev->name);
    return 0; 
} 

static netdev_tx_t start_xmit(struct sk_buff * skb, struct net_device * dev) {
    struct priv *priv = netdev_priv(dev);

    struct iphdr * ip = (struct iphdr *) skb_network_header(skb);

    if (frame_dest_ip_equals(skb, dest_ip)) {
        priv->stats.tx_packets++;
        priv->stats.tx_bytes += skb->len;
        
        char result[100];
        sprintf(result, "RX: src %pI4, dest %pI4\n", &ip->saddr, &ip->daddr);
        strcat(msg, result);
        pr_info("%s: %s", THIS_MODULE->name, result);
    }

    if (priv->parent) {
        skb->dev = priv->parent;
        skb->priority = 1;
        dev_queue_xmit(skb);
    }

    return NETDEV_TX_OK;
}

static struct net_device_stats * get_stats(struct net_device * dev) {
    struct priv * priv = (struct priv *) netdev_priv( dev );
    return &priv->stats;
}

static struct net_device_ops net_device_ops = {
    .ndo_open = open,
    .ndo_stop = stop,
    .ndo_get_stats = get_stats,
    .ndo_start_xmit = start_xmit
};

static void setup(struct net_device * dev) {
    ether_setup(dev);
    dev->netdev_ops = &net_device_ops;
} 

int __init vni_init(void) {
    proc_entry = proc_create(THIS_MODULE->name, 0444, NULL, &proc_file_ops);

    if (!proc_entry) {
        return -1;
    }

    my_interface = alloc_netdev(sizeof(struct priv), my_if_name, NET_NAME_UNKNOWN, setup);

    if (!my_interface) {
        pr_err("%s: failed to allocate new device\n", THIS_MODULE->name);
        return -ENOMEM;
    }

    struct priv * priv = netdev_priv(my_interface);
    priv->parent = dev_get_by_name(&init_net, parent_if_name); //parent interface

    if (!priv->parent) {
        pr_err("%s: no such net device: %s\n", THIS_MODULE->name, parent_if_name);
        free_netdev(my_interface);
        return -ENODEV;
    }

    //copy IP, MAC and other information
    memcpy(my_interface->dev_addr, priv->parent->dev_addr, ETH_ALEN);
    memcpy(my_interface->broadcast, priv->parent->broadcast, ETH_ALEN);
    
    if (dev_alloc_name(my_interface, my_interface->name) != 0) {
        pr_err("%s: failed to allocate device name\n", THIS_MODULE->name);
        free_netdev(my_interface);
        return -EINVAL;
    }

    if (register_netdev(my_interface) < 0) {
        pr_err("%s: failed to register device\n", THIS_MODULE->name);
        free_netdev(my_interface);
        return -EIO;
    }

    
    int rc;
    rtnl_lock();
    rc = netdev_rx_handler_register(priv->parent, &handle_frame, NULL);
    rtnl_unlock();

    if (rc < 0) {
        pr_err("%s: failed to register rx handler for device %s\n", THIS_MODULE->name, priv->parent->name);
        free_netdev(my_interface);
        return -EIO;
    }

    pr_info("%s: Module loaded: parent %s target ip %s\n", THIS_MODULE->name, parent_if_name, dest_ip);

    return 0;
}

void __exit vni_exit(void) {
    proc_remove(proc_entry);

    struct priv *priv = netdev_priv(my_interface);

    if (priv->parent) {
        rtnl_lock();
        netdev_rx_handler_unregister(priv->parent);
        rtnl_unlock();
        pr_info("%s: unregister rx handler for %s\n", THIS_MODULE->name, priv->parent->name);
    }

    unregister_netdev(my_interface);
    free_netdev(my_interface);
    pr_info("%s: Module unloaded\n", THIS_MODULE->name);
} 

module_init(vni_init);
module_exit(vni_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("anton");
MODULE_DESCRIPTION("io-lab3");
MODULE_VERSION("1.0");