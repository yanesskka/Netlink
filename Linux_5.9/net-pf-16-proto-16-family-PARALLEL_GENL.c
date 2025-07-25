#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/if_arp.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <linux/etherdevice.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>
#include <linux/notifier.h>
#include <linux/mutex.h>
// #include "genl_module.h"

MODULE_LICENSE("GPL");


static struct kobject *kobj_genl_test;
static struct device *dev_genl_test;
static struct kobject *kobj_parallel_genl;
static struct kobject *kobj_third_genl;

#define MAX_DATA_LEN 256

struct {
    char genl_test_message[MAX_DATA_LEN];
    char genl_test_info[MAX_DATA_LEN];
    u32 genl_test_value;
    char parallel_genl_message[MAX_DATA_LEN];
    char third_genl_message[MAX_DATA_LEN];
}

sysfs_data = {
    .genl_test_message = "default",
    .genl_test_info = "default",
    .genl_test_value = -20,
    .parallel_genl_message = "default",
    .third_genl_message = "default",
};

static ssize_t show_genl_test_info(struct device *dev, struct device_attribute *attr, char *buf)
{
        return sprintf(buf, "%s", sysfs_data.genl_test_info);
}

static ssize_t store_genl_test_info(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        snprintf(sysfs_data.genl_test_info, sizeof(sysfs_data.genl_test_info), "%.*s",
                (int)min(count, sizeof(sysfs_data.genl_test_info) - 1), buf);
        return count;
}

static ssize_t show_genl_test_message(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
        return sprintf(buf, "%s", sysfs_data.genl_test_message);
}
    
static ssize_t store_genl_test_message(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
        size_t len = min(count, sizeof(sysfs_data.genl_test_message) - 1);
        strncpy(sysfs_data.genl_test_message, buf, len);
        sysfs_data.genl_test_message[len] = '\0';
        return count;
}

static ssize_t show_genl_test_value(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d", sysfs_data.genl_test_value);
}

static ssize_t store_genl_test_value(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    int rt;
    rt = kstrtouint(buf, 0, &sysfs_data.genl_test_value);
    return count;
}

static ssize_t show_parallel_genl_message(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%s", sysfs_data.parallel_genl_message);
}

static ssize_t store_parallel_genl_message(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    size_t len = min(count, sizeof(sysfs_data.parallel_genl_message) - 1);
    strncpy(sysfs_data.parallel_genl_message, buf, len);
    sysfs_data.parallel_genl_message[len] = '\0';
    return count;
}

static ssize_t show_third_genl_message(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%s", sysfs_data.third_genl_message);
}

static ssize_t store_third_genl_message(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    size_t len = min(count, sizeof(sysfs_data.third_genl_message) - 1);
    strncpy(sysfs_data.third_genl_message, buf, len);
    sysfs_data.third_genl_message[len] = '\0';
    return count;
}

static struct device_attribute dev_attr_info_genl_test = __ATTR(some_info, 0664, show_genl_test_info, store_genl_test_info);

static struct kobj_attribute my_attr_str_genl_test = __ATTR(message, 0664, show_genl_test_message, store_genl_test_message);

static struct kobj_attribute my_attr_u32_genl_test = __ATTR(value, 0664, show_genl_test_value, store_genl_test_value);

static struct kobj_attribute my_attr_str_parallel_genl = __ATTR(message, 0664, show_parallel_genl_message, store_parallel_genl_message);

static struct kobj_attribute my_attr_str_third_genl = __ATTR(message, 0664, show_third_genl_message, store_third_genl_message);

static DEFINE_MUTEX(genl_mutex);
static DEFINE_MUTEX(sysfs_mutex);

#define MY_GENL_FAMILY_NAME "TEST_GENL"
#define MY_GENL_VERSION 1

#define PARALLEL_GENL_FAMILY_NAME "PARALLEL_GENL"

#define THIRD_GENL_FAMILY_NAME "THIRD_GENL"

#define LARGE_GENL_FAMILY_NAME "LARGE_GENL"

#define PATH_GENL_TEST_NUM "/sys/kernel/genl_test/value"
#define PATH_GENL_TEST_MES "/sys/kernel/genl_test/message"
#define PATH_GENL_TEST_DEV "/sys/kernel/genl_test/some_info"
#define PATH_PARALLEL_GENL_MES "/sys/kernel/parallel_genl/message"
#define PATH_THIRD_GENL_MES "/sys/kernel/third_genl/message"

// netlink attributes
enum {
    MY_GENL_ATTR_UNSPEC,
    MY_GENL_ATTR_DATA,
    MY_GENL_ATTR_VALUE,
    MY_GENL_ATTR_PATH,
    MY_GENL_ATTR_NESTED,
    __MY_GENL_ATTR_MAX,
};
#define MY_GENL_ATTR_MAX (__MY_GENL_ATTR_MAX - 1)

// supported commands
enum {
    MY_GENL_CMD_UNSPEC,
    MY_GENL_CMD_ECHO,
    MY_GENL_CMD_SET_VALUE,
    MY_GENL_CMD_GET_VALUE,
    MY_GENL_CMD_EVENT,
    MY_GENL_CMD_NO_ATTRS,
    __MY_GENL_CMD_MAX,
};
#define MY_GENL_CMD_MAX (__MY_GENL_CMD_MAX - 1)

enum {
	MY_GENL_SMALL_CMD_GET_NESTED,
    MY_GENL_SMALL_CMD_ERROR,
	__MY_GENL_SMALL_CMD_MAX,
};

#define MY_GENL_SMALL_CMD_MAX (__MY_GENL_SMALL_CMD_MAX - 1)


// Validation policy for attributes
static const struct nla_policy my_genl_policy[MY_GENL_ATTR_MAX + 1] = {
    [MY_GENL_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [MY_GENL_ATTR_DATA]  = {.type = NLA_STRING},
    [MY_GENL_ATTR_VALUE] = {.type = NLA_U32},
    [MY_GENL_ATTR_PATH] = {.type = NLA_STRING},
    [MY_GENL_ATTR_NESTED] = {.type = NLA_NESTED},
};

/* My netlink family */
static struct genl_family my_genl_family;

static struct genl_family my_genl_family_parallel;

static struct genl_family third_genl_family;

enum my_multicast_groups {
	MY_MCGRP_GENL,
};

static const struct genl_multicast_group genl_mcgrps[] = {
	[MY_MCGRP_GENL] = { .name = "MY_MCGRP_GENL", },
};

static int my_genl_pre_doit(const struct genl_ops *ops, struct sk_buff *skb, struct genl_info *info)
{
    mutex_lock(&genl_mutex);
    return 0;
}

static void my_genl_post_doit(const struct genl_ops *ops, struct sk_buff *skb, struct genl_info *info)
{
    mutex_unlock(&genl_mutex);
}

static void my_genl_mcast_msg(struct sk_buff *mcast_skb, struct genl_info *info)
{
    if (info) {
        genl_notify(&my_genl_family, mcast_skb, info, MY_MCGRP_GENL, GFP_KERNEL);
    }
    else {
        genlmsg_multicast(&my_genl_family, mcast_skb, 0, MY_MCGRP_GENL, GFP_KERNEL);
    }
}

// Functions for Generic Netlink
static int my_genl_echo(struct sk_buff *skb, struct genl_info *info) {
    struct sk_buff *msg;
	void *data;
	int ret;
    char *str;

	msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	data = genlmsg_put_reply(msg, info, &my_genl_family, 0, MY_GENL_CMD_ECHO);
    if (!data)
		goto error;

    str = "Hello to mcast groups!";
    
    strcpy(sysfs_data.genl_test_message, str);

	ret = nla_put_string(msg, MY_GENL_ATTR_DATA, str);
	if (ret < 0)
		goto error;

	genlmsg_end(msg, data);

	my_genl_mcast_msg(msg, info);

	return 0;

error:
	nlmsg_free(msg);
    return -EMSGSIZE;
}

static int my_genl_set_value(struct sk_buff *skb, struct genl_info *info) {
    struct sk_buff *msg;
    void *msg_head;
    struct nlattr *na_path;
    struct nlattr *na_value;
    char *sysfs_path;
    u32 new_value;
    int err;
    int code;
    struct netlink_ext_ack *extack;
    // struct nlattr *attr;
    struct nlmsghdr *nlh;
    u8 cookie[NETLINK_MAX_COOKIE_LEN] = "000001";

    if (!info->attrs[MY_GENL_ATTR_VALUE]) {
        printk(KERN_INFO "my_genl_set_value: Missing MY_GENL_ATTR_VALUE\n");
		return -EINVAL;
    }

    na_value = info->attrs[MY_GENL_ATTR_VALUE];
	new_value = nla_get_u32(na_value);

    if (new_value != 0 && new_value != 1) {
        printk(KERN_ERR "New value is incorrect\n");
        goto error;
    }

    na_path = info->attrs[MY_GENL_ATTR_PATH];
    if (!na_path) {
        printk(KERN_INFO "my_genl_set_value: Missing MY_GENL_ATTR_PATH\n");
		return -EINVAL;
    }
    sysfs_path = nla_data(na_path);

    sysfs_data.genl_test_value = new_value;

    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    msg_head = genlmsg_put(msg, info->snd_portid, info->snd_seq, &my_genl_family, 0, MY_GENL_CMD_SET_VALUE);
    if (!msg_head) {
        nlmsg_free(msg);
        return -ENOMEM;
    }

    if (nla_put_u32(msg, MY_GENL_ATTR_VALUE, new_value)) {
		genlmsg_cancel(msg, msg_head);
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, msg_head);

    err = netlink_unicast(skb->sk, msg, info->snd_portid, 0);
    if (err < 0) {
        printk(KERN_ERR "Error in netlink_sendskb, err=%d\n", err);
        nlmsg_free(msg);
        return err;
    }

    return 0;

    error:
        // sending error ACK
        code = -EINVAL;
        
        extack = kmalloc(sizeof(struct netlink_ext_ack), GFP_KERNEL);
        if (!extack) {
            printk(KERN_ERR "Failed to allocate memory for netlink_ext_ack\n");
            return -ENOMEM;
        }
       
        // netlink_ext_ack does not have : policy, miss_type, miss_nest fields
        
        extack->_msg = "Incorrect value from userspace";
        extack->bad_attr = na_value;
        // extack->policy = my_genl_policy;
        memcpy(extack->cookie, cookie, NETLINK_MAX_COOKIE_LEN);
        extack->cookie_len = strlen(cookie);
        // extack->miss_type = MY_GENL_ATTR_VALUE;
        // extack->miss_nest = attr;    // NULL;   
        
        nlh = nlmsg_hdr(skb);
        netlink_ack(skb, nlh, code, extack);
        printk(KERN_INFO "Message with TLV was sent\n");
        return -EINVAL;
}

static int my_genl_get_value(struct sk_buff *skb, struct genl_info *info) {
    struct sk_buff *msg;
    void *msg_head;
    struct nlattr *na_path;
    char *sysfs_path;
    u32 value;
    int err;
    int code;

    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    msg_head = genlmsg_put(msg, info->snd_portid, info->snd_seq, &my_genl_family, 0, MY_GENL_CMD_GET_VALUE);
    if (!msg_head) {
        nlmsg_free(msg);
        return -ENOMEM;
    }

    if (!info->attrs[MY_GENL_ATTR_PATH]) {
        nlmsg_free(msg);
		return -EINVAL;
    }
    genl_unlock();
    na_path = info->attrs[MY_GENL_ATTR_PATH];
    sysfs_path = nla_data(na_path);
    genl_lock();

    if (strcmp(sysfs_path, PATH_GENL_TEST_NUM) != 0) {
        printk(KERN_ERR "Incorrect path: %s\n", sysfs_path);
        goto socket_error;
    }

    value = sysfs_data.genl_test_value;

    if (nla_put_u32(msg, MY_GENL_ATTR_VALUE, value)) {
		genlmsg_cancel(msg, msg_head);
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, msg_head);

    if (info) {
        err = genlmsg_reply(msg, info);
        if (err != 0) {
            printk(KERN_ERR "Error in genlmsg_reply, err=%d\n", err);
            nlmsg_free(msg);
            return err;
        }

    }

    return 0;

    socket_error:
        code = -ENOENT;  // No such file or directory
        netlink_set_err(skb->sk, 0, MY_MCGRP_GENL, code);
        return -ENOENT;
}

static int my_genl_no_attrs(struct sk_buff *skb, struct genl_info *info) {
    struct sk_buff *msg;
    void *msg_head;
    int ret;
    char *str;

    msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;
    
    msg_head = genlmsg_put_reply(msg, info, &my_genl_family, 0, info->genlhdr->cmd);
    if(!msg_head)
        goto error;

    str = "Reply from function my_genl_no_attrs";

    strcpy(sysfs_data.genl_test_message, str);
    
    if (nla_put_string(msg, MY_GENL_ATTR_DATA, str)) {
        printk(KERN_ERR "Error with putting value to MY_GENL_ATTR_DATA");
        goto error;
    }

    genlmsg_end(msg, msg_head);
    return genlmsg_reply(msg, info);

    error:
        ret = -EMSGSIZE;
        nlmsg_free(msg);
        return ret;
}

// Generic Netlink operations
static const struct genl_ops my_genl_ops[] = {
    {
        .cmd = MY_GENL_CMD_ECHO,
        .flags = 0,
        // .policy = my_genl_policy,
        .doit = my_genl_echo,
        .dumpit = NULL,
    },
    {
        .cmd = MY_GENL_CMD_SET_VALUE,
        // .policy = my_genl_policy,
        .doit = my_genl_set_value,
        .flags = GENL_ADMIN_PERM,  
    },
    {
        .cmd = MY_GENL_CMD_GET_VALUE,
        .flags = 0,
        // .policy = my_genl_policy,
        .doit = my_genl_get_value,
        .dumpit = NULL,
    },
    {
        .cmd = MY_GENL_CMD_NO_ATTRS,
        .flags = 0,
        // .policy = NULL,
        .doit = my_genl_no_attrs,
        .dumpit = NULL,
    },
};

// genl_family struct
static struct genl_family my_genl_family = {
    .hdrsize = 0,
    .name = MY_GENL_FAMILY_NAME,
    .version = MY_GENL_VERSION,
    .maxattr = MY_GENL_ATTR_MAX,
    .netnsok = true,
    .pre_doit = my_genl_pre_doit,
    .post_doit = my_genl_post_doit,
    .ops = my_genl_ops,
    .n_ops = ARRAY_SIZE(my_genl_ops),
    .policy = my_genl_policy,
    .mcgrps = genl_mcgrps,
    .n_mcgrps = ARRAY_SIZE(genl_mcgrps),
};

// netlink attributes
enum {
    PARALLEL_GENL_ATTR_UNSPEC,
    PARALLEL_GENL_ATTR_DATA,
    PARALLEL_GENL_ATTR_BINARY,
    PARALLEL_GENL_ATTR_NAME,
    PARALLEL_GENL_ATTR_DESC,
    PARALLEL_GENL_ATTR_BITFIELD32,
    PARALLEL_GENL_ATTR_SIGN_NUM,
    PARALLEL_GENL_ATTR_ARRAY,
    PARALLEL_GENL_ATTR_NESTED,
    PARALLEL_GENL_ATTR_FLAG_NONBLOCK,
    PARALLEL_GENL_ATTR_FLAG_BLOCK,
    PARALLEL_GENL_ATTR_REJECT,
    PARALLEL_GENL_ATTR_PATH,
    __PARALLEL_GENL_ATTR_MAX,
};
#define PARALLEL_GENL_ATTR_MAX (__PARALLEL_GENL_ATTR_MAX - 1)

// supported commands
enum {
    PARALLEL_GENL_CMD_UNSPEC,
    PARALLEL_GENL_CMD_SEND,
    PARALLEL_GENL_CMD_DUMP_INFO,
    PARALLEL_GENL_CMD_SET_VALUE,
    PARALLEL_GENL_CMD_GET_VALUE,
    __PARALLEL_GENL_CMD_MAX,
};
#define PARALLEL_GENL_CMD_MAX (__PARALLEL_GENL_CMD_MAX - 1)

// Validation policy for attributes
static const struct nla_policy parallel_genl_policy[PARALLEL_GENL_ATTR_MAX + 1] = {
    [PARALLEL_GENL_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [PARALLEL_GENL_ATTR_DATA]  = {.type = NLA_STRING},
    [PARALLEL_GENL_ATTR_BINARY] = {.type = NLA_BINARY},
    [PARALLEL_GENL_ATTR_NAME] = {.type = NLA_NUL_STRING},    // \0 at the end of the string
    [PARALLEL_GENL_ATTR_DESC] = {.type = NLA_NUL_STRING},
    [PARALLEL_GENL_ATTR_BITFIELD32] = {.type = NLA_BITFIELD32},
    [PARALLEL_GENL_ATTR_SIGN_NUM] = {.type = NLA_S32},
    [PARALLEL_GENL_ATTR_ARRAY] = {.type = NLA_NESTED_ARRAY},
    [PARALLEL_GENL_ATTR_NESTED] = {.type = NLA_NESTED},
    [PARALLEL_GENL_ATTR_FLAG_NONBLOCK] = {.type = NLA_FLAG},
    [PARALLEL_GENL_ATTR_FLAG_BLOCK] = {.type = NLA_FLAG},
    [PARALLEL_GENL_ATTR_REJECT] = {.type = NLA_REJECT},
    [PARALLEL_GENL_ATTR_PATH] = {.type = NLA_STRING},
};

static int parallel_genl_send(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *reply;
	int ret;
    char *str;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	reply = genlmsg_put_reply(msg, info, &my_genl_family, 0, info->genlhdr->cmd);
	if (!reply)
		goto error;

    str = "NEW family - parallel_genl";

    strcpy(sysfs_data.parallel_genl_message, str);

    if (nla_put_string(msg, PARALLEL_GENL_ATTR_DATA, str)) {
        nlmsg_free(msg);
        printk(KERN_ERR "Error with putting value\n");
        return -EMSGSIZE;
    }

	genlmsg_end(msg, reply);

    if (nla_get_flag(info->attrs[PARALLEL_GENL_ATTR_FLAG_NONBLOCK])) goto overrun_nonblock;
    if (nla_get_flag(info->attrs[PARALLEL_GENL_ATTR_FLAG_BLOCK])) goto overrun_block;

	return genlmsg_reply(msg, info);

error:
	ret = -EMSGSIZE;
	nlmsg_free(msg);
	return ret;

overrun_nonblock:
    skb->sk->sk_sndtimeo = 1000;
    // printk(KERN_INFO "start overrun for nonblock socket in parallel_genl_send\n");
    
    ret = netlink_unicast(skb->sk, msg, info->snd_portid, 1);   // 1 неблокирующий сокет
    if (ret < 0) {
        // printk(KERN_ERR "Error in netlink_unicast, err=%d\n", ret);
        return ret;
    }
    // printk(KERN_INFO "netlink_unicast with overrun done");
    return 0;

overrun_block:
    // printk(KERN_INFO "socket timeo for block socket is %ld", skb->sk->sk_sndtimeo);
    // printk(KERN_INFO "start overrun for block socket in parallel_genl_send\n");
    
    ret = netlink_unicast(skb->sk, msg, info->snd_portid, 0);   // 0 блокирующий сокет
    if (ret < 0) {
        // printk(KERN_ERR "Error in netlink_unicast, err=%d\n", ret);
        return ret;
    }
    // printk(KERN_INFO "netlink_unicast with overrun done");
    return 0;
}

static int parallel_genl_set_str_value(struct sk_buff *skb, struct genl_info *info) {
    struct sk_buff *msg;
    void *msg_head;
    struct nlattr *na_path;
    struct nlattr *na_value;
    char *sysfs_path;
    char *new_value = NULL;
    int err;
    int data_len;

    if (!info->attrs[PARALLEL_GENL_ATTR_DATA]) {
        printk(KERN_INFO "my_genl_set_str_value: Missing PARALLEL_GENL_ATTR_DATA\n");
		return -EINVAL;
    }

    na_value = info->attrs[PARALLEL_GENL_ATTR_DATA];
    data_len = nla_len(na_value);
    
	new_value = kmalloc(data_len + 1, GFP_KERNEL);
    if (!new_value) {
        printk(KERN_ERR "parallel_genl_set_str_value: Out of memory\n");
        return -ENOMEM;
    }

    strncpy(new_value, nla_data(na_value), data_len);
    new_value[data_len] = '\0';

    na_path = info->attrs[PARALLEL_GENL_ATTR_PATH];
    if (!na_path) {
        printk(KERN_INFO "my_genl_set_str_value: Missing PARALLEL_GENL_ATTR_PATH\n");
		return -EINVAL;
    }
    sysfs_path = nla_data(na_path);

    strcpy(sysfs_data.parallel_genl_message, new_value);

    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    msg_head = genlmsg_put(msg, info->snd_portid, info->snd_seq, &my_genl_family_parallel, 0, PARALLEL_GENL_CMD_SET_VALUE);
    if (!msg_head) {
        nlmsg_free(msg);
        return -ENOMEM;
    }

    if (nla_put_string(msg, PARALLEL_GENL_ATTR_DATA, new_value)) {
		genlmsg_cancel(msg, msg_head);
        nlmsg_free(msg);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, msg_head);

    err = netlink_unicast(skb->sk, msg, info->snd_portid, 0);
    if (err < 0) {
        printk(KERN_ERR "Error in netlink_sendskb, err=%d\n", err);
        nlmsg_free(msg);
        return err;
    }

    kfree(new_value);
    return 0;
}

static int parallel_genl_get_str_value(struct sk_buff *skb, struct genl_info *info) {
    struct sk_buff *msg;
    void *msg_head;
    struct nlattr *na_path;
    char *sysfs_path;
    char *value;
    int err;
    int code;

    msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg)
        return -ENOMEM;

    msg_head = genlmsg_put(msg, info->snd_portid, info->snd_seq, &my_genl_family_parallel, 0, PARALLEL_GENL_CMD_GET_VALUE);
    if (!msg_head) {
        nlmsg_free(msg);
        return -ENOMEM;
    }

    if (!info->attrs[PARALLEL_GENL_ATTR_PATH]) {
        nlmsg_free(msg);
		return -EINVAL;
    }
    genl_unlock();
    na_path = info->attrs[PARALLEL_GENL_ATTR_PATH];
    sysfs_path = nla_data(na_path);
    genl_lock();

    if (strcmp(sysfs_path, PATH_PARALLEL_GENL_MES) != 0) {
        printk(KERN_ERR "Incorrect path: %s\n", sysfs_path);
        goto socket_error;
    }

    value = kmalloc(MAX_DATA_LEN, GFP_KERNEL);
    if (!value) {
        printk(KERN_ERR "parallel_genl_get_str_value: Out of memory\n");
        return -ENOMEM;
    }

    strcpy(value, sysfs_data.parallel_genl_message);

    if (nla_put_string(msg, PARALLEL_GENL_ATTR_DATA, value)) {
		genlmsg_cancel(msg, msg_head);
        nlmsg_free(msg);
        kfree(value);
        return -EMSGSIZE;
    }

    genlmsg_end(msg, msg_head);

    if (info) {
        err = genlmsg_reply(msg, info);
        if (err != 0) {
            printk(KERN_ERR "Error in genlmsg_reply, err=%d\n", err);
            nlmsg_free(msg);
            kfree(value);
            return err;
        }

    }
    kfree(value);

    return 0;

    socket_error:
        nlmsg_free(msg);
        code = -ENOENT;
        netlink_set_err(skb->sk, 0, MY_MCGRP_GENL, code);
        return -ENOENT;
}

struct parallel_data {
    char *name;
    char *desc;
};

struct parallel_data data[] = {
    {"TEST_GENL", "one"},
    {"PARALLEL_GENL", "two"},
    {"THIRD_GENL", "three"},
    {"LARGE_GENL", "four"},
};
#define DATA_SIZE ARRAY_SIZE(data)

static int parallel_genl_dump_start(struct netlink_callback *cb) {
    printk(KERN_INFO "Dump is started");
    return 0;
}

static int __parallel_genl_fill_info(struct parallel_data *info, struct sk_buff *msg)
{
    if (nla_put_string(msg, PARALLEL_GENL_ATTR_NAME, info->name) ||
        nla_put_string(msg, PARALLEL_GENL_ATTR_DESC, info->desc))
            return -EMSGSIZE;

    return 0;
}

static int __parallel_genl_dump_element(struct parallel_data *info, u32 portid, u32 seq, u32 flags, struct sk_buff *skb, u8 cmd)
{
    void *hdr;

    hdr = genlmsg_put(skb, portid, seq, &my_genl_family_parallel, flags, cmd);
    if (!hdr)
        return -ENOMEM;

    if (__parallel_genl_fill_info(info, skb) < 0)
        goto nla_put_failure;

    genlmsg_end(skb, hdr);
    return 0;

nla_put_failure:
    genlmsg_cancel(skb, hdr);
    return -EMSGSIZE;
}

static int parallel_genl_dump_info(struct sk_buff *skb, struct netlink_callback *cb)
{
    int ret;
    int idx = cb->args[0];   // index for current element

    for (;;) {
        if (idx >= DATA_SIZE) {  
            return 0;            // dump is over
        }

        // One element for msg
        ret = __parallel_genl_dump_element(&data[idx], NETLINK_CB(cb->skb).portid,
                cb->nlh->nlmsg_seq, NLM_F_MULTI, skb,
                PARALLEL_GENL_CMD_DUMP_INFO);

        if (ret) {
            printk(KERN_ERR "parallel_genl_dump_info: __parallel_genl_dump_element failed: %d\n", ret);
            return ret;
        }

        cb->args[0]++;   // next element
        idx++;
    }

    return ret;
}

static int parallel_genl_dump_done(struct netlink_callback *cb)
{
    printk(KERN_INFO "Dump is done");
	return 0;
}

// Generic Netlink operations
// no policy field in 5.9
static const struct genl_ops parallel_genl_ops[] = {
    {
        .cmd = PARALLEL_GENL_CMD_SEND,
        .flags = 0,
        // .policy = parallel_genl_policy,
        .doit = parallel_genl_send,
        .dumpit = NULL,
    },
    {
        .cmd = PARALLEL_GENL_CMD_DUMP_INFO,
        .flags = 0,
        // .policy = parallel_genl_policy,
        .start = parallel_genl_dump_start,
        .dumpit = parallel_genl_dump_info,
        .done = parallel_genl_dump_done,
    },
    {
        .cmd = PARALLEL_GENL_CMD_SET_VALUE,
        .flags = 0,
        // .policy = NULL,    // parallel_genl_policy,
        .doit = parallel_genl_set_str_value,
        .dumpit = NULL,
    },
    {
        .cmd = PARALLEL_GENL_CMD_GET_VALUE,
        .flags = GENL_UNS_ADMIN_PERM,
        // .policy = parallel_genl_policy,
        .doit = parallel_genl_get_str_value,
    },
};

enum my_multicast_many_groups_one {
	MCGRP_1,
    MCGRP_2,
    MCGRP_3,
    MCGRP_4,
    MCGRP_5,
    MCGRP_6,
    MCGRP_7,
    MCGRP_8,
    MCGRP_9,
    MCGRP_10,
    MCGRP_11,
    MCGRP_12,
    MCGRP_13,
    MCGRP_14,
    MCGRP_15,
    MCGRP_16,
    MCGRP_17,
    MCGRP_18,
    MCGRP_19,
    MCGRP_20,
    MCGRP_21,
    MCGRP_22,
    MCGRP_23,
    MCGRP_24,
    MCGRP_25,
    MCGRP_26,
    MCGRP_27,
    MCGRP_28,
    MCGRP_29,
    MCGRP_30,
    MCGRP_31,
    MCGRP_32,
    MCGRP_33,
    MCGRP_34,
    MCGRP_35,
    MCGRP_36,
    MCGRP_37,
    MCGRP_38,
    MCGRP_39,
    MCGRP_40,
    MCGRP_41,
    MCGRP_42,
    MCGRP_43,
    MCGRP_44,
    MCGRP_45,
    MCGRP_46,
    MCGRP_47,
    MCGRP_48,
    MCGRP_49,
    MCGRP_50,
    MCGRP_51,
    MCGRP_52,
    MCGRP_53,
    MCGRP_54,
    MCGRP_55,
    MCGRP_56,
    MCGRP_57,
    MCGRP_58,
    MCGRP_59,
    MCGRP_60,
    MCGRP_61,
    MCGRP_62,
    MCGRP_63,
    MCGRP_64,
    MCGRP_65,
    MCGRP_66,
    MCGRP_67,
    MCGRP_68,
    MCGRP_69,
    MCGRP_70,
    MCGRP_71,
    MCGRP_72,
    MCGRP_73,
    MCGRP_74,
    MCGRP_75,
    MCGRP_76,
    MCGRP_77,
    MCGRP_78,
    MCGRP_79,
    MCGRP_80,
    MCGRP_81,
    MCGRP_82,
    MCGRP_83,
    MCGRP_84,
    MCGRP_85,
    MCGRP_86,
    MCGRP_87,
    MCGRP_88,
    MCGRP_89,
    MCGRP_90,
    MCGRP_91,
    MCGRP_92,
    MCGRP_93,
    MCGRP_94,
    MCGRP_95,
    MCGRP_96,
    MCGRP_97,
    MCGRP_98,
    MCGRP_99,
    MCGRP_100,
    MCGRP_101,
    MCGRP_102,
    MCGRP_103,
    MCGRP_104,
    MCGRP_105,
    MCGRP_106,
    MCGRP_107,
    MCGRP_108,
    MCGRP_109,
    MCGRP_110,
    MCGRP_111,
    MCGRP_112,
    MCGRP_113,
    MCGRP_114,
    MCGRP_115,
    MCGRP_116,
    MCGRP_117,
    MCGRP_118,
    MCGRP_119,
    MCGRP_120,
    MCGRP_121,
    MCGRP_122,
    MCGRP_123,
    MCGRP_124,
    MCGRP_125,
    MCGRP_126,
    MCGRP_127,
    MCGRP_128,
    MCGRP_129,
    MCGRP_130,
    MCGRP_131,
    MCGRP_132,
    MCGRP_133,
    MCGRP_134,
    MCGRP_135,
    MCGRP_136,
    MCGRP_137,
    MCGRP_138,
    MCGRP_139,
    MCGRP_140,
    MCGRP_141,
    MCGRP_142,
    MCGRP_143,
    MCGRP_144,
    MCGRP_145,
    MCGRP_146,
    MCGRP_147,
    MCGRP_148,
    MCGRP_149,
    MCGRP_150,
    MCGRP_151,
    MCGRP_152,
    MCGRP_153,
    MCGRP_154,
    MCGRP_155,
    MCGRP_156,
    MCGRP_157,
    MCGRP_158,
    MCGRP_159,
    MCGRP_160,
    MCGRP_161,
    MCGRP_162,
    MCGRP_163,
    MCGRP_164,
    MCGRP_165,
    MCGRP_166,
    MCGRP_167,
    MCGRP_168,
    MCGRP_169,
    MCGRP_170,
    MCGRP_171,
    MCGRP_172,
    MCGRP_173,
    MCGRP_174,
    MCGRP_175,
    MCGRP_176,
    MCGRP_177,
    MCGRP_178,
    MCGRP_179,
    MCGRP_180,
    MCGRP_181,
    MCGRP_182,
    MCGRP_183,
    MCGRP_184,
    MCGRP_185,
    MCGRP_186,
    MCGRP_187,
    MCGRP_188,
    MCGRP_189,
    MCGRP_190,
    MCGRP_191,
    MCGRP_192,
    MCGRP_193,
    MCGRP_194,
    MCGRP_195,
    MCGRP_196,
    MCGRP_197,
    MCGRP_198,
    MCGRP_199,
};

static const struct genl_multicast_group genl_many_mcgrps_one[] = {
	[MCGRP_1] = { .name = "MCGRP_1", },
    [MCGRP_2] = { .name = "MCGRP_2", },
    [MCGRP_3] = { .name = "MCGRP_3", },
    [MCGRP_4] = { .name = "MCGRP_4", },
    [MCGRP_5] = { .name = "MCGRP_5", },
    [MCGRP_6] = { .name = "MCGRP_6", },
    [MCGRP_7] = { .name = "MCGRP_7", },
    [MCGRP_8] = { .name = "MCGRP_8", },
    [MCGRP_9] = { .name = "MCGRP_9", },
    [MCGRP_10] = { .name = "MCGRP_10", },
    [MCGRP_11] = { .name = "MCGRP_11", },
    [MCGRP_12] = { .name = "MCGRP_12", },
    [MCGRP_13] = { .name = "MCGRP_13", },
    [MCGRP_14] = { .name = "MCGRP_14", },
    [MCGRP_15] = { .name = "MCGRP_15", },
    [MCGRP_16] = { .name = "MCGRP_16", },
    [MCGRP_17] = { .name = "MCGRP_17", },
    [MCGRP_18] = { .name = "MCGRP_18", },
    [MCGRP_19] = { .name = "MCGRP_19", },
    [MCGRP_20] = { .name = "MCGRP_20", },
    [MCGRP_21] = { .name = "MCGRP_21", },
    [MCGRP_22] = { .name = "MCGRP_22", },
    [MCGRP_23] = { .name = "MCGRP_23", },
    [MCGRP_24] = { .name = "MCGRP_24", },
    [MCGRP_25] = { .name = "MCGRP_25", },
    [MCGRP_26] = { .name = "MCGRP_26", },
    [MCGRP_27] = { .name = "MCGRP_27", },
    [MCGRP_28] = { .name = "MCGRP_28", },
    [MCGRP_29] = { .name = "MCGRP_29", },
    [MCGRP_30] = { .name = "MCGRP_30", },
    [MCGRP_31] = { .name = "MCGRP_31", },
    [MCGRP_32] = { .name = "MCGRP_32", },
    [MCGRP_33] = { .name = "MCGRP_33", },
    [MCGRP_34] = { .name = "MCGRP_34", },
    [MCGRP_35] = { .name = "MCGRP_35", },
    [MCGRP_36] = { .name = "MCGRP_36", },
    [MCGRP_37] = { .name = "MCGRP_37", },
    [MCGRP_38] = { .name = "MCGRP_38", },
    [MCGRP_39] = { .name = "MCGRP_39", },
    [MCGRP_40] = { .name = "MCGRP_40", },
    [MCGRP_41] = { .name = "MCGRP_41", },
    [MCGRP_42] = { .name = "MCGRP_42", },
    [MCGRP_43] = { .name = "MCGRP_43", },
    [MCGRP_44] = { .name = "MCGRP_44", },
    [MCGRP_45] = { .name = "MCGRP_45", },
    [MCGRP_46] = { .name = "MCGRP_46", },
    [MCGRP_47] = { .name = "MCGRP_47", },
    [MCGRP_48] = { .name = "MCGRP_48", },
    [MCGRP_49] = { .name = "MCGRP_49", },
    [MCGRP_50] = { .name = "MCGRP_50", },
    [MCGRP_51] = { .name = "MCGRP_51", },
    [MCGRP_52] = { .name = "MCGRP_52", },
    [MCGRP_53] = { .name = "MCGRP_53", },
    [MCGRP_54] = { .name = "MCGRP_54", },
    [MCGRP_55] = { .name = "MCGRP_55", },
    [MCGRP_56] = { .name = "MCGRP_56", },
    [MCGRP_57] = { .name = "MCGRP_57", },
    [MCGRP_58] = { .name = "MCGRP_58", },
    [MCGRP_59] = { .name = "MCGRP_59", },
    [MCGRP_60] = { .name = "MCGRP_60", },
    [MCGRP_61] = { .name = "MCGRP_61", },
    [MCGRP_62] = { .name = "MCGRP_62", },
    [MCGRP_63] = { .name = "MCGRP_63", },
    [MCGRP_64] = { .name = "MCGRP_64", },
    [MCGRP_65] = { .name = "MCGRP_65", },
    [MCGRP_66] = { .name = "MCGRP_66", },
    [MCGRP_67] = { .name = "MCGRP_67", },
    [MCGRP_68] = { .name = "MCGRP_68", },
    [MCGRP_69] = { .name = "MCGRP_69", },
    [MCGRP_70] = { .name = "MCGRP_70", },
    [MCGRP_71] = { .name = "MCGRP_71", },
    [MCGRP_72] = { .name = "MCGRP_72", },
    [MCGRP_73] = { .name = "MCGRP_73", },
    [MCGRP_74] = { .name = "MCGRP_74", },
    [MCGRP_75] = { .name = "MCGRP_75", },
    [MCGRP_76] = { .name = "MCGRP_76", },
    [MCGRP_77] = { .name = "MCGRP_77", },
    [MCGRP_78] = { .name = "MCGRP_78", },
    [MCGRP_79] = { .name = "MCGRP_79", },
    [MCGRP_80] = { .name = "MCGRP_80", },
    [MCGRP_81] = { .name = "MCGRP_81", },
    [MCGRP_82] = { .name = "MCGRP_82", },
    [MCGRP_83] = { .name = "MCGRP_83", },
    [MCGRP_84] = { .name = "MCGRP_84", },
    [MCGRP_85] = { .name = "MCGRP_85", },
    [MCGRP_86] = { .name = "MCGRP_86", },
    [MCGRP_87] = { .name = "MCGRP_87", },
    [MCGRP_88] = { .name = "MCGRP_88", },
    [MCGRP_89] = { .name = "MCGRP_89", },
    [MCGRP_90] = { .name = "MCGRP_90", },
    [MCGRP_91] = { .name = "MCGRP_91", },
    [MCGRP_92] = { .name = "MCGRP_92", },
    [MCGRP_93] = { .name = "MCGRP_93", },
    [MCGRP_94] = { .name = "MCGRP_94", },
    [MCGRP_95] = { .name = "MCGRP_95", },
    [MCGRP_96] = { .name = "MCGRP_96", },
    [MCGRP_97] = { .name = "MCGRP_97", },
    [MCGRP_98] = { .name = "MCGRP_98", },
    [MCGRP_99] = { .name = "MCGRP_99", },
    [MCGRP_100] = { .name = "MCGRP_100", },
    [MCGRP_101] = { .name = "MCGRP_101", },
    [MCGRP_102] = { .name = "MCGRP_102", },
    [MCGRP_103] = { .name = "MCGRP_103", },
    [MCGRP_104] = { .name = "MCGRP_104", },
    [MCGRP_105] = { .name = "MCGRP_105", },
    [MCGRP_106] = { .name = "MCGRP_106", },
    [MCGRP_107] = { .name = "MCGRP_107", },
    [MCGRP_108] = { .name = "MCGRP_108", },
    [MCGRP_109] = { .name = "MCGRP_109", },
    [MCGRP_110] = { .name = "MCGRP_100", },
    [MCGRP_111] = { .name = "MCGRP_111", },
    [MCGRP_112] = { .name = "MCGRP_112", },
    [MCGRP_113] = { .name = "MCGRP_113", },
    [MCGRP_114] = { .name = "MCGRP_114", },
    [MCGRP_115] = { .name = "MCGRP_115", },
    [MCGRP_116] = { .name = "MCGRP_116", },
    [MCGRP_117] = { .name = "MCGRP_117", },
    [MCGRP_118] = { .name = "MCGRP_118", },
    [MCGRP_119] = { .name = "MCGRP_119", },
    [MCGRP_120] = { .name = "MCGRP_120", },
    [MCGRP_121] = { .name = "MCGRP_121", },
    [MCGRP_122] = { .name = "MCGRP_122", },
    [MCGRP_123] = { .name = "MCGRP_123", },
    [MCGRP_124] = { .name = "MCGRP_124", },
    [MCGRP_125] = { .name = "MCGRP_125", },
    [MCGRP_126] = { .name = "MCGRP_126", },
    [MCGRP_127] = { .name = "MCGRP_127", },
    [MCGRP_128] = { .name = "MCGRP_128", },
    [MCGRP_129] = { .name = "MCGRP_129", },
    [MCGRP_130] = { .name = "MCGRP_130", },
    [MCGRP_131] = { .name = "MCGRP_131", },
    [MCGRP_132] = { .name = "MCGRP_132", },
    [MCGRP_133] = { .name = "MCGRP_133", },
    [MCGRP_134] = { .name = "MCGRP_134", },
    [MCGRP_135] = { .name = "MCGRP_135", },
    [MCGRP_136] = { .name = "MCGRP_136", },
    [MCGRP_137] = { .name = "MCGRP_137", },
    [MCGRP_138] = { .name = "MCGRP_138", },
    [MCGRP_139] = { .name = "MCGRP_139", },
    [MCGRP_140] = { .name = "MCGRP_140", },
    [MCGRP_141] = { .name = "MCGRP_141", },
    [MCGRP_142] = { .name = "MCGRP_142", },
    [MCGRP_143] = { .name = "MCGRP_143", },
    [MCGRP_144] = { .name = "MCGRP_144", },
    [MCGRP_145] = { .name = "MCGRP_145", },
    [MCGRP_146] = { .name = "MCGRP_146", },
    [MCGRP_147] = { .name = "MCGRP_147", },
    [MCGRP_148] = { .name = "MCGRP_148", },
    [MCGRP_149] = { .name = "MCGRP_149", },
    [MCGRP_150] = { .name = "MCGRP_150", },
    [MCGRP_151] = { .name = "MCGRP_151", },
    [MCGRP_152] = { .name = "MCGRP_152", },
    [MCGRP_153] = { .name = "MCGRP_153", },
    [MCGRP_154] = { .name = "MCGRP_154", },
    [MCGRP_155] = { .name = "MCGRP_155", },
    [MCGRP_156] = { .name = "MCGRP_156", },
    [MCGRP_157] = { .name = "MCGRP_157", },
    [MCGRP_158] = { .name = "MCGRP_158", },
    [MCGRP_159] = { .name = "MCGRP_159", },
    [MCGRP_160] = { .name = "MCGRP_160", },
    [MCGRP_161] = { .name = "MCGRP_161", },
    [MCGRP_162] = { .name = "MCGRP_162", },
    [MCGRP_163] = { .name = "MCGRP_163", },
    [MCGRP_164] = { .name = "MCGRP_164", },
    [MCGRP_165] = { .name = "MCGRP_165", },
    [MCGRP_166] = { .name = "MCGRP_166", },
    [MCGRP_167] = { .name = "MCGRP_167", },
    [MCGRP_168] = { .name = "MCGRP_168", },
    [MCGRP_169] = { .name = "MCGRP_169", },
    [MCGRP_170] = { .name = "MCGRP_170", },
    [MCGRP_171] = { .name = "MCGRP_171", },
    [MCGRP_172] = { .name = "MCGRP_172", },
    [MCGRP_173] = { .name = "MCGRP_173", },
    [MCGRP_174] = { .name = "MCGRP_174", },
    [MCGRP_175] = { .name = "MCGRP_175", },
    [MCGRP_176] = { .name = "MCGRP_176", },
    [MCGRP_177] = { .name = "MCGRP_177", },
    [MCGRP_178] = { .name = "MCGRP_178", },
    [MCGRP_179] = { .name = "MCGRP_179", },
    [MCGRP_180] = { .name = "MCGRP_180", },
    [MCGRP_181] = { .name = "MCGRP_181", },
    [MCGRP_182] = { .name = "MCGRP_182", },
    [MCGRP_183] = { .name = "MCGRP_183", },
    [MCGRP_184] = { .name = "MCGRP_184", },
    [MCGRP_185] = { .name = "MCGRP_185", },
    [MCGRP_186] = { .name = "MCGRP_186", },
    [MCGRP_187] = { .name = "MCGRP_187", },
    [MCGRP_188] = { .name = "MCGRP_188", },
    [MCGRP_189] = { .name = "MCGRP_189", },
    [MCGRP_190] = { .name = "MCGRP_190", },
    [MCGRP_191] = { .name = "MCGRP_191", },
    [MCGRP_192] = { .name = "MCGRP_192", },
    [MCGRP_193] = { .name = "MCGRP_193", },
    [MCGRP_194] = { .name = "MCGRP_194", },
    [MCGRP_195] = { .name = "MCGRP_195", },
    [MCGRP_196] = { .name = "MCGRP_196", },
    [MCGRP_197] = { .name = "MCGRP_197", },
    [MCGRP_198] = { .name = "MCGRP_198", },
    [MCGRP_199] = { .name = "MCGRP_199", },
};

enum my_multicast_many_groups_two {
	MCGRP_TWO_1,
    MCGRP_TWO_2,
    MCGRP_TWO_3,
    MCGRP_TWO_4,
    MCGRP_TWO_5,
    MCGRP_TWO_6,
    MCGRP_TWO_7,
    MCGRP_TWO_8,
    MCGRP_TWO_9,
    MCGRP_TWO_10,
    MCGRP_TWO_11,
    MCGRP_TWO_12,
    MCGRP_TWO_13,
    MCGRP_TWO_14,
    MCGRP_TWO_15,
    MCGRP_TWO_16,
    MCGRP_TWO_17,
    MCGRP_TWO_18,
    MCGRP_TWO_19,
    MCGRP_TWO_20,
    MCGRP_TWO_21,
    MCGRP_TWO_22,
    MCGRP_TWO_23,
    MCGRP_TWO_24,
    MCGRP_TWO_25,
    MCGRP_TWO_26,
    MCGRP_TWO_27,
    MCGRP_TWO_28,
    MCGRP_TWO_29,
    MCGRP_TWO_30,
    MCGRP_TWO_31,
    MCGRP_TWO_32,
    MCGRP_TWO_33,
    MCGRP_TWO_34,
    MCGRP_TWO_35,
    MCGRP_TWO_36,
    MCGRP_TWO_37,
    MCGRP_TWO_38,
    MCGRP_TWO_39,
    MCGRP_TWO_40,
    MCGRP_TWO_41,
    MCGRP_TWO_42,
    MCGRP_TWO_43,
    MCGRP_TWO_44,
    MCGRP_TWO_45,
    MCGRP_TWO_46,
    MCGRP_TWO_47,
    MCGRP_TWO_48,
    MCGRP_TWO_49,
    MCGRP_TWO_50,
    MCGRP_TWO_51,
    MCGRP_TWO_52,
    MCGRP_TWO_53,
    MCGRP_TWO_54,
    MCGRP_TWO_55,
    MCGRP_TWO_56,
    MCGRP_TWO_57,
    MCGRP_TWO_58,
    MCGRP_TWO_59,
    MCGRP_TWO_60,
    MCGRP_TWO_61,
    MCGRP_TWO_62,
    MCGRP_TWO_63,
    MCGRP_TWO_64,
    MCGRP_TWO_65,
    MCGRP_TWO_66,
    MCGRP_TWO_67,
    MCGRP_TWO_68,
    MCGRP_TWO_69,
};

static const struct genl_multicast_group genl_many_mcgrps_two[] = {
	[MCGRP_TWO_1] = { .name = "MCGRP_TWO_1", },
    [MCGRP_TWO_2] = { .name = "MCGRP_TWO_2", },
    [MCGRP_TWO_3] = { .name = "MCGRP_TWO_3", },
    [MCGRP_TWO_4] = { .name = "MCGRP_TWO_4", },
    [MCGRP_TWO_5] = { .name = "MCGRP_TWO_5", },
    [MCGRP_TWO_6] = { .name = "MCGRP_TWO_6", },
    [MCGRP_TWO_7] = { .name = "MCGRP_TWO_7", },
    [MCGRP_TWO_8] = { .name = "MCGRP_TWO_8", },
    [MCGRP_TWO_9] = { .name = "MCGRP_TWO_9", },
    [MCGRP_TWO_10] = { .name = "MCGRP_TWO_10", },
    [MCGRP_TWO_11] = { .name = "MCGRP_TWO_11", },
    [MCGRP_TWO_12] = { .name = "MCGRP_TWO_12", },
    [MCGRP_TWO_13] = { .name = "MCGRP_TWO_13", },
    [MCGRP_TWO_14] = { .name = "MCGRP_TWO_14", },
    [MCGRP_TWO_15] = { .name = "MCGRP_TWO_15", },
    [MCGRP_TWO_16] = { .name = "MCGRP_TWO_16", },
    [MCGRP_TWO_17] = { .name = "MCGRP_TWO_17", },
    [MCGRP_TWO_18] = { .name = "MCGRP_TWO_18", },
    [MCGRP_TWO_19] = { .name = "MCGRP_TWO_19", },
    [MCGRP_TWO_20] = { .name = "MCGRP_TWO_20", },
    [MCGRP_TWO_21] = { .name = "MCGRP_TWO_21", },
    [MCGRP_TWO_22] = { .name = "MCGRP_TWO_22", },
    [MCGRP_TWO_23] = { .name = "MCGRP_TWO_23", },
    [MCGRP_TWO_24] = { .name = "MCGRP_TWO_24", },
    [MCGRP_TWO_25] = { .name = "MCGRP_TWO_25", },
    [MCGRP_TWO_26] = { .name = "MCGRP_TWO_26", },
    [MCGRP_TWO_27] = { .name = "MCGRP_TWO_27", },
    [MCGRP_TWO_28] = { .name = "MCGRP_TWO_28", },
    [MCGRP_TWO_29] = { .name = "MCGRP_TWO_29", },
    [MCGRP_TWO_30] = { .name = "MCGRP_TWO_30", },
    [MCGRP_TWO_31] = { .name = "MCGRP_TWO_31", },
    [MCGRP_TWO_32] = { .name = "MCGRP_TWO_32", },
    [MCGRP_TWO_33] = { .name = "MCGRP_TWO_33", },
    [MCGRP_TWO_34] = { .name = "MCGRP_TWO_34", },
    [MCGRP_TWO_35] = { .name = "MCGRP_TWO_35", },
    [MCGRP_TWO_36] = { .name = "MCGRP_TWO_36", },
    [MCGRP_TWO_37] = { .name = "MCGRP_TWO_37", },
    [MCGRP_TWO_38] = { .name = "MCGRP_TWO_38", },
    [MCGRP_TWO_39] = { .name = "MCGRP_TWO_39", },
    [MCGRP_TWO_40] = { .name = "MCGRP_TWO_40", },
    [MCGRP_TWO_41] = { .name = "MCGRP_TWO_41", },
    [MCGRP_TWO_42] = { .name = "MCGRP_TWO_42", },
    [MCGRP_TWO_43] = { .name = "MCGRP_TWO_43", },
    [MCGRP_TWO_44] = { .name = "MCGRP_TWO_44", },
    [MCGRP_TWO_45] = { .name = "MCGRP_TWO_45", },
    [MCGRP_TWO_46] = { .name = "MCGRP_TWO_46", },
    [MCGRP_TWO_47] = { .name = "MCGRP_TWO_47", },
    [MCGRP_TWO_48] = { .name = "MCGRP_TWO_48", },
    [MCGRP_TWO_49] = { .name = "MCGRP_TWO_49", },
    [MCGRP_TWO_50] = { .name = "MCGRP_TWO_50", },
    [MCGRP_TWO_51] = { .name = "MCGRP_TWO_51", },
    [MCGRP_TWO_52] = { .name = "MCGRP_TWO_52", },
    [MCGRP_TWO_53] = { .name = "MCGRP_TWO_53", },
    [MCGRP_TWO_54] = { .name = "MCGRP_TWO_54", },
    [MCGRP_TWO_55] = { .name = "MCGRP_TWO_55", },
    [MCGRP_TWO_56] = { .name = "MCGRP_TWO_56", },
    [MCGRP_TWO_57] = { .name = "MCGRP_TWO_57", },
    [MCGRP_TWO_58] = { .name = "MCGRP_TWO_58", },
    [MCGRP_TWO_59] = { .name = "MCGRP_TWO_59", },
    [MCGRP_TWO_60] = { .name = "MCGRP_TWO_60", },
    [MCGRP_TWO_61] = { .name = "MCGRP_TWO_61", },
    [MCGRP_TWO_62] = { .name = "MCGRP_TWO_62", },
    [MCGRP_TWO_63] = { .name = "MCGRP_TWO_63", },
    [MCGRP_TWO_64] = { .name = "MCGRP_TWO_64", },
    [MCGRP_TWO_65] = { .name = "MCGRP_TWO_65", },
    [MCGRP_TWO_66] = { .name = "MCGRP_TWO_66", },
    [MCGRP_TWO_67] = { .name = "MCGRP_TWO_67", },
    [MCGRP_TWO_68] = { .name = "MCGRP_TWO_68", },
    [MCGRP_TWO_69] = { .name = "MCGRP_TWO_69", },
};

// second genl_family struct
// no resv_start_op field in 5.9
static struct genl_family my_genl_family_parallel = {
    .hdrsize = 0,
    .name = PARALLEL_GENL_FAMILY_NAME,
    .version = 1,
    .maxattr = PARALLEL_GENL_ATTR_MAX,
    .netnsok = true,
    .parallel_ops = true,
    .ops = parallel_genl_ops,
    .n_ops = ARRAY_SIZE(parallel_genl_ops),
    // .policy = parallel_genl_policy,                // needs to delete policy from family to test reject policy
    // .resv_start_op = PARALLEL_GENL_CMD_DUMP_INFO + 1,
    .mcgrps = genl_many_mcgrps_two,
    .n_mcgrps = ARRAY_SIZE(genl_many_mcgrps_two),
};

// netlink attributes
enum {
    THIRD_GENL_ATTR_UNSPEC,
    THIRD_GENL_ATTR_DATA,
    THIRD_GENL_ATTR_FLAG,
    __THIRD_GENL_ATTR_MAX,
};
#define THIRD_GENL_ATTR_MAX (__THIRD_GENL_ATTR_MAX - 1)


// supported commands
enum {
    THIRD_GENL_CMD_UNSPEC,
    THIRD_GENL_CMD_ECHO,
    __THIRD_GENL_CMD_MAX,
};
#define THIRD_GENL_CMD_MAX (__THIRD_GENL_CMD_MAX - 1)

// Validation policy for attributes
static const struct nla_policy third_genl_policy[THIRD_GENL_ATTR_MAX + 1] = {
    [THIRD_GENL_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [THIRD_GENL_ATTR_DATA]  = {.type = NLA_STRING},
    [THIRD_GENL_ATTR_FLAG] = {.type = NLA_FLAG},
};

// Functions for third Generic Netlink
static int third_genl_echo(struct sk_buff *skb, struct genl_info *info) {
    struct sk_buff *msg;
	void *data;
	int ret;
    char *str;

	msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	data = genlmsg_put_reply(msg, info, &my_genl_family, 0, THIRD_GENL_CMD_ECHO);
    if (!data)
		goto error;

    str = "Hello from THIRD_GENL!";
    strcpy(sysfs_data.third_genl_message, str);

	ret = nla_put_string(msg, THIRD_GENL_ATTR_DATA, str);
	if (ret < 0)
		goto error;

    ret = nla_put_flag(msg, THIRD_GENL_ATTR_FLAG);
	if (ret < 0)
		goto error;

	genlmsg_end(msg, data);

    genlmsg_reply(msg, info);
	// my_genl_mcast_msg(msg, info);

	return 0;

error:
	nlmsg_free(msg);
    return -EMSGSIZE;
}

// Generic Netlink operations
// no policy field in 5.9
static const struct genl_ops third_genl_ops[] = {
    {
        .cmd = THIRD_GENL_CMD_ECHO,
        .flags = 0,
        // .policy = third_genl_policy,
        .doit = third_genl_echo,
        .dumpit = NULL,
    },
};

// third genl_family struct
// no policy field in 5.9
static struct genl_family third_genl_family = {
    .hdrsize = 0,
    .name = THIRD_GENL_FAMILY_NAME,
    .version = 1,
    .maxattr = THIRD_GENL_ATTR_MAX,
    .netnsok = true,
    .ops = third_genl_ops,
    .n_ops = ARRAY_SIZE(third_genl_ops),
    // .policy = third_genl_policy,
};

// supported commands
enum {
    LARGE_GENL_CMD_UNSPEC,
    LARGE_GENL_CMD_ECHO,
    __LARGE_GENL_CMD_MAX,
};
#define LARGE_GENL_CMD_MAX (__LARGE_GENL_CMD_MAX - 1)


static int large_genl_echo(struct sk_buff *skb, struct genl_info *info) {
    return 0; 
}

// Generic Netlink operations
static const struct genl_ops large_genl_ops[] = {
    {
        .cmd = LARGE_GENL_CMD_ECHO,
        .flags = 0,
        .doit = large_genl_echo,
        .dumpit = NULL,
    },
};

// large genl_family struct
static struct genl_family large_genl_family = {
    .hdrsize = 0,
    .name = LARGE_GENL_FAMILY_NAME,
    .version = 1,
    .maxattr = 1,
    .netnsok = true,
    .ops = large_genl_ops,
    .n_ops = ARRAY_SIZE(large_genl_ops),
    .mcgrps = genl_many_mcgrps_one,
    .n_mcgrps = ARRAY_SIZE(genl_many_mcgrps_one),
};

// incorrect name for genl_family struct
static struct genl_family incorrect_genl_family = {
    .hdrsize = 0,
    .name = MY_GENL_FAMILY_NAME,   // such family already exists
    .version = MY_GENL_VERSION,
    .maxattr = MY_GENL_ATTR_MAX,
    .netnsok = true,
    .ops = my_genl_ops,
    .n_ops = ARRAY_SIZE(my_genl_ops),
    .policy = my_genl_policy,
};

enum {
    INCORRECT_OP_WITH_NULL,
};

// Generic Netlink operations
// no policy field in 5.9
static const struct genl_ops incorrect_ops_with_null[] = {
    {
        .cmd = INCORRECT_OP_WITH_NULL,
        .flags = 0,
        // .policy = my_genl_policy,  // random policy
        .doit = NULL,              // doit and dumpit are NULL --> kernel will send -EINVAL
        .dumpit = NULL,
    },
};

// incorrect ops for genl_family struct
static struct genl_family incorrect_ops_genl_family = {
    .hdrsize = 0,
    .name = "INCORRECT",
    .version = 1,
    .maxattr = 1,
    .netnsok = true,
    .ops = incorrect_ops_with_null,      // ops contain NULL
    .n_ops = ARRAY_SIZE(incorrect_ops_with_null),
    .policy = my_genl_policy,            // random policy
};

static int ntf_genl_event(struct notifier_block * nb, unsigned long state, void *_notify)
{
	return NOTIFY_OK;
}

static struct notifier_block genl_notifier = {
	.notifier_call  = ntf_genl_event,
};

static int __init init_netlink(void)
{
	int rc;

	printk(KERN_INFO "My module: initializing Netlink\n");

	rc = genl_register_family(&my_genl_family);
	if (rc) {
        printk(KERN_ERR "Failed to register Generic Netlink family\n");
		goto failure_1;
    }

    rc = genl_register_family(&my_genl_family_parallel);
	if (rc) {
        printk(KERN_ERR "Failed to register Generic Netlink family\n");
		goto failure_2;
    }

    rc = genl_register_family(&large_genl_family);
    if (rc) {
        printk(KERN_ERR "Failed to register Generic Netlink family\n");
		goto failure_3;
    }

    rc = genl_register_family(&third_genl_family);
    if (rc) {
        printk(KERN_ERR "Failed to register Generic Netlink family\n");
		goto failure_4;
    }

	return 0;
failure_4:
    genl_unregister_family(&large_genl_family);
failure_3:
    genl_unregister_family(&my_genl_family_parallel);
failure_2:
    genl_unregister_family(&my_genl_family);
failure_1:
	pr_debug("My module: error occurred in %s\n", __func__);
	return rc;
}

static int __init incorrect_ops_netlink(void) {
    int ret;
    ret = genl_register_family(&incorrect_ops_genl_family);
    if (ret != -EINVAL)
        return ret;
    return 0;
}

static int __init incorrect_init_netlink(void)
{
	int rc;

	printk(KERN_INFO "My module: initializing incorrect Netlink\n");

	rc = genl_register_family(&incorrect_genl_family);
	if (rc) {
        printk(KERN_ERR "Failed to register Generic Netlink family\n");
		goto failure;
    }

	return 0;

failure:
	pr_debug("My module: error occurred in %s\n", __func__);
	return -EINVAL;
}

static int __init init_sysfs_third_genl(void) {
    int ret;

    kobj_third_genl = kobject_create_and_add("third_genl", kernel_kobj);
    
    if (!kobj_third_genl) {
            printk(KERN_ERR "Failed to create kobject\n");
            return -ENOMEM;
    }  

    ret = sysfs_create_file(kobj_third_genl, &my_attr_str_third_genl.attr);
    if (ret) {
            printk(KERN_ERR "Failed to create sysfs file\n");
            goto err_sysfs;
    }

    return 0;
    err_sysfs:
        kobject_put(kobj_third_genl);
        return ret;
}

static int __init init_sysfs_parallel_genl(void) {
    int ret;

    kobj_parallel_genl = kobject_create_and_add("parallel_genl", kernel_kobj);
    
    if (!kobj_parallel_genl) {
            printk(KERN_ERR "Failed to create kobject\n");
            return -ENOMEM;
    }  

    ret = sysfs_create_file(kobj_parallel_genl, &my_attr_str_parallel_genl.attr);
    if (ret) {
            printk(KERN_ERR "Failed to create sysfs file\n");
            goto err_sysfs;
    }

    return 0;
    err_sysfs:
        kobject_put(kobj_parallel_genl);
        return ret;
}

static int __init init_sysfs_genl_test(void) {
    int ret;

    kobj_genl_test = kobject_create_and_add("genl_test", kernel_kobj);
    dev_genl_test = kobj_to_dev(kobj_genl_test);
    
    if (!kobj_genl_test) {
        printk(KERN_ERR "Failed to create kobject\n");
        return -ENOMEM;
    }  

    ret = sysfs_create_file(kobj_genl_test, &my_attr_u32_genl_test.attr);
    if (ret) {
        printk(KERN_ERR "Failed to create sysfs file 1\n");
        goto err_sysfs;
    }

    ret = sysfs_create_file(kobj_genl_test, &my_attr_str_genl_test.attr);
    if (ret) {
        printk(KERN_ERR "Failed to create sysfs file 2\n");
        goto err_sysfs_2;
    }

    ret = device_create_file(dev_genl_test, &dev_attr_info_genl_test);
    if (ret) {
        printk(KERN_ERR "Failed to create device file\n");
        goto err_device;
    };

    return 0;
    err_device:
        sysfs_remove_file(kobj_genl_test, &my_attr_str_genl_test.attr);
    err_sysfs_2:
        sysfs_remove_file(kobj_genl_test, &my_attr_u32_genl_test.attr);
    err_sysfs:
        kobject_put(kobj_genl_test);
        return ret;
}

static int __init my_sysfs_init(void) {
    int ret;

    ret = init_sysfs_genl_test();
    if (ret)
        goto err_sysfs;

    ret = init_sysfs_parallel_genl();
    if (ret)
        goto err_sysfs;

    ret = init_sysfs_third_genl();
    if (ret)
        goto err_sysfs;

    ret = incorrect_ops_netlink();
    if (ret)
        goto err_sysfs;

    ret = init_netlink();
    if (ret == -ENOMEM)
        printk(KERN_INFO "here was fault injection -- good behavior");
    if (ret)
        goto err_sysfs;
    printk(KERN_INFO "New families is registered\n");

    ret = incorrect_init_netlink();
    if (ret)
        printk(KERN_ERR "Error occured - predicted behaviour\n");;
    printk(KERN_INFO "Error is correct\n");

    ret = genl_unregister_family(&incorrect_genl_family);
    if (ret) {
        printk(KERN_ERR "Error occured - predicted behaviour\n");
    }
    printk(KERN_INFO "Error is correct\n");

    ret = netlink_register_notifier(&genl_notifier);
    if (ret)
        goto err_family;

    return 0;

    // err_notifier:
        netlink_unregister_notifier(&genl_notifier);
    err_family:
        genl_unregister_family(&my_genl_family);
        genl_unregister_family(&my_genl_family_parallel);
        genl_unregister_family(&third_genl_family);
        genl_unregister_family(&large_genl_family);
    err_sysfs:
        sysfs_remove_file(kobj_genl_test, &my_attr_u32_genl_test.attr);
        sysfs_remove_file(kobj_genl_test, &my_attr_str_genl_test.attr);
        device_remove_file(dev_genl_test, &dev_attr_info_genl_test);
        kobject_put(kobj_genl_test);

        sysfs_remove_file(kobj_parallel_genl, &my_attr_str_parallel_genl.attr);
        kobject_put(kobj_parallel_genl);
        
        sysfs_remove_file(kobj_third_genl, &my_attr_str_third_genl.attr);
        kobject_put(kobj_third_genl);
        return ret;
}

static void __exit my_sysfs_exit(void) {
    netlink_unregister_notifier(&genl_notifier);
    genl_unregister_family(&my_genl_family);
    genl_unregister_family(&my_genl_family_parallel);
    genl_unregister_family(&third_genl_family);
    genl_unregister_family(&large_genl_family);

    sysfs_remove_file(kobj_genl_test, &my_attr_u32_genl_test.attr);
    sysfs_remove_file(kobj_genl_test, &my_attr_str_genl_test.attr);
    device_remove_file(dev_genl_test, &dev_attr_info_genl_test);
    kobject_put(kobj_genl_test);

    sysfs_remove_file(kobj_parallel_genl, &my_attr_str_parallel_genl.attr);
    kobject_put(kobj_parallel_genl);
    
    sysfs_remove_file(kobj_third_genl, &my_attr_str_third_genl.attr);
    kobject_put(kobj_third_genl);
    printk(KERN_INFO "Module is exited\n");
}

module_init(my_sysfs_init);
module_exit(my_sysfs_exit);
