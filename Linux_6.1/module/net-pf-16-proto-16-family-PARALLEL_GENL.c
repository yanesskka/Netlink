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
#include <linux/kstrtox.h>
#include <linux/etherdevice.h>
#include <net/genetlink.h>
#include <net/rtnetlink.h>
#include <linux/notifier.h>
#include <linux/mutex.h>

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
        return sysfs_emit(buf, "%s", sysfs_data.genl_test_info);
}

static ssize_t store_genl_test_info(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
        snprintf(sysfs_data.genl_test_info, sizeof(sysfs_data.genl_test_info), "%.*s",
                (int)min(count, sizeof(sysfs_data.genl_test_info) - 1), buf);
        return count;
}

static ssize_t show_genl_test_message(struct kobject *kobj, struct kobj_attribute *attr, char *buf) 
{
        return sprintf(buf, "%s", sysfs_data.genl_test_message);
}
    
static ssize_t store_genl_test_message(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) 
{
        size_t len = min(count, sizeof(sysfs_data.genl_test_message) - 1);
        strncpy(sysfs_data.genl_test_message, buf, len);
        sysfs_data.genl_test_message[len] = '\0';
        return count;
}

static ssize_t show_genl_test_value(struct kobject *kobj, struct kobj_attribute *attr, char *buf) 
{
    return sprintf(buf, "%d", sysfs_data.genl_test_value);
}

static ssize_t store_genl_test_value(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) 
{
    int rt;
    rt = kstrtouint(buf, 0, &sysfs_data.genl_test_value);
    return count;
}

static ssize_t show_parallel_genl_message(struct kobject *kobj, struct kobj_attribute *attr, char *buf) 
{
    return sprintf(buf, "%s", sysfs_data.parallel_genl_message);
}

static ssize_t store_parallel_genl_message(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) 
{
    size_t len = min(count, sizeof(sysfs_data.parallel_genl_message) - 1);
    strncpy(sysfs_data.parallel_genl_message, buf, len);
    sysfs_data.parallel_genl_message[len] = '\0';
    return count;
}

static ssize_t show_third_genl_message(struct kobject *kobj, struct kobj_attribute *attr, char *buf) 
{
    return sprintf(buf, "%s", sysfs_data.third_genl_message);
}

static ssize_t store_third_genl_message(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) 
{
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

#define MY_GENL_FAMILY_NAME "TEST_GENL"
#define MY_GENL_VERSION 1

#define PARALLEL_GENL_FAMILY_NAME "PARALLEL_GENL"

#define PATH_GENL_TEST_NUM "/sys/kernel/genl_test/value"
#define PATH_GENL_TEST_MES "/sys/kernel/genl_test/message"
#define PATH_GENL_TEST_DEV "/sys/kernel/genl_test/some_info"
#define PATH_PARALLEL_GENL_MES "/sys/kernel/parallel_genl/message"

// TEST_GENL
enum {
    MY_GENL_ATTR_UNSPEC,
    MY_GENL_ATTR_DATA,
    MY_GENL_ATTR_VALUE,
    MY_GENL_ATTR_PATH,
    MY_GENL_ATTR_NESTED,
    __MY_GENL_ATTR_MAX,
};
#define MY_GENL_ATTR_MAX (__MY_GENL_ATTR_MAX - 1)

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
	MY_GENL_SMALL_CMD_GET,
    MY_GENL_SMALL_CMD_ERROR,
	__MY_GENL_SMALL_CMD_MAX,
};

#define MY_GENL_SMALL_CMD_MAX (__MY_GENL_SMALL_CMD_MAX - 1)

static const struct nla_policy my_genl_policy[MY_GENL_ATTR_MAX + 1] = {
    [MY_GENL_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [MY_GENL_ATTR_DATA]  = {.type = NLA_STRING},
    [MY_GENL_ATTR_VALUE] = {.type = NLA_U32, .validation_type = NLA_VALIDATE_RANGE, .min = 0, .max = 100},
    [MY_GENL_ATTR_PATH] = {.type = NLA_STRING},
    [MY_GENL_ATTR_NESTED] = {.type = NLA_NESTED},
};

/* netlink families */
static struct genl_family my_genl_family;

static struct genl_family my_genl_family_parallel;

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

// Functions for Generic Netlink TEST_GENL family
static int my_genl_echo(struct sk_buff *skb, struct genl_info *info) 
{
    struct sk_buff *msg;
	void *data;
	int ret;
    char *str;

    if (info->nlhdr->nlmsg_flags & NLM_F_ECHO) {

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

    }

	return 0;

error:
	nlmsg_free(msg);
    return -EMSGSIZE;
}

static int my_genl_set_value(struct sk_buff *skb, struct genl_info *info) 
{
    struct sk_buff *msg;
    void *msg_head;
    struct nlattr *na_path;
    struct nlattr *na_value;
    char *sysfs_path;
    u32 new_value;
    int err;
    int code;
    struct netlink_ext_ack *extack;
    struct nlattr *attr;
    struct nlmsghdr *nlh;

    if (!info->attrs[MY_GENL_ATTR_VALUE]) {
        printk(KERN_INFO "my_genl_set_value: Missing MY_GENL_ATTR_VALUE\n");
		return -EINVAL;
    }

    na_value = info->attrs[MY_GENL_ATTR_VALUE];
	new_value = nla_get_u32(na_value);

    if (new_value != 0 && new_value != 1) {
        printk(KERN_ERR "my_genl_set_value: New value is incorrect\n");
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
        printk(KERN_ERR "my_genl_set_value: Error in netlink_unicast, err=%d\n", err);
        nlmsg_free(msg);
        return err;
    }

    return 0;

error:
    // sending error ACK
    code = -EINVAL;
    
    extack = kmalloc(sizeof(*extack), GFP_KERNEL);
    if (!extack) {
        printk(KERN_ERR "my_genl_set_value: Failed to allocate memory for netlink_ext_ack\n");
        return -ENOMEM;
    }
    
    char cookie[NETLINK_MAX_COOKIE_LEN] = "000001";
    extack->_msg = "Incorrect value from userspace";
    extack->bad_attr = na_value;
    extack->policy = my_genl_policy;
    extack->cookie_len = strlen(cookie);
    extack->miss_type = MY_GENL_ATTR_VALUE;
    extack->miss_nest = attr; 
    
    nlh = nlmsg_hdr(skb);
    netlink_ack(skb, nlh, code, extack);
    printk(KERN_INFO "my_genl_set_value: Message with TLV was sent\n");
    return -EINVAL;
}

static int my_genl_get_value(struct sk_buff *skb, struct genl_info *info) 
{
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
        printk(KERN_ERR "my_genl_get_value: Incorrect path: %s\n", sysfs_path);
        goto error;
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
            printk(KERN_ERR "my_genl_get_value: Error in genlmsg_reply, err=%d\n", err);
            nlmsg_free(msg);
            return err;
        }

    }

    return 0;

error:
    code = -EINVAL;
    netlink_set_err(skb->sk, 0, MY_MCGRP_GENL, code);
    return -EINVAL;
}

static int my_genl_no_attrs(struct sk_buff *skb, struct genl_info *info) 
{
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
        printk(KERN_ERR "my_genl_no_attrs: Error with putting value to MY_GENL_ATTR_DATA");
        goto error;
    }

    genlmsg_end(msg, msg_head);
    return genlmsg_reply(msg, info);

error:
    ret = -EMSGSIZE;
    nlmsg_free(msg);
    return ret;
}

// Generic Netlink operations for TEST_GENL family
static const struct genl_ops my_genl_ops[] = {
    {
        .cmd = MY_GENL_CMD_ECHO,
        .flags = 0,
        .policy = my_genl_policy,
        .doit = my_genl_echo,
        .dumpit = NULL,
    },
    {
        .cmd = MY_GENL_CMD_SET_VALUE,
        .policy = my_genl_policy,
        .doit = my_genl_set_value,
        .flags = GENL_ADMIN_PERM,  
    },
    {
        .cmd = MY_GENL_CMD_GET_VALUE,
        .flags = 0,
        .policy = my_genl_policy,
        .doit = my_genl_get_value,
        .dumpit = NULL,
    },
    {
        .cmd = MY_GENL_CMD_NO_ATTRS,
        .flags = 0,
        .policy = NULL,
        .doit = my_genl_no_attrs,
        .dumpit = NULL,
    },
};

static int my_genl_small_cmd_get(struct sk_buff *skb, struct genl_info *info)
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

    str = "IT'S ME from kernel";

    strcpy(sysfs_data.genl_test_message, str);

    if (nla_put_string(msg, MY_GENL_ATTR_DATA, str)) {
        nlmsg_free(msg);
        printk(KERN_ERR "my_genl_small_cmd_get: Error with putting value to MY_GENL_ATTR_DATA\n");
        return -EMSGSIZE;
    }

	genlmsg_end(msg, reply);
	return genlmsg_reply(msg, info);

error:
    ret = -EMSGSIZE;
    nlmsg_free(msg);
    return ret;
}

static const struct genl_small_ops my_genl_small_ops[] = {
    {
		.cmd = MY_GENL_SMALL_CMD_GET,
		.doit = my_genl_small_cmd_get,
	},
};

// genl_family struct for TEST_GENL family
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
    .small_ops = my_genl_small_ops,
	.n_small_ops = ARRAY_SIZE(my_genl_small_ops),
    .policy = my_genl_policy,
    .mcgrps = genl_mcgrps,
    .n_mcgrps = ARRAY_SIZE(genl_mcgrps),
};

// PARALLEL_GENL family
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

enum {
    PARALLEL_GENL_CMD_UNSPEC,
    PARALLEL_GENL_CMD_SEND,
    PARALLEL_GENL_CMD_DUMP_INFO,
    PARALLEL_GENL_CMD_SET_VALUE,
    PARALLEL_GENL_CMD_GET_VALUE,
    __PARALLEL_GENL_CMD_MAX,
};
#define PARALLEL_GENL_CMD_MAX (__PARALLEL_GENL_CMD_MAX - 1)

static const struct nla_policy parallel_genl_policy[PARALLEL_GENL_ATTR_MAX + 1] = {
    [PARALLEL_GENL_ATTR_UNSPEC] = {.type = NLA_UNSPEC},
    [PARALLEL_GENL_ATTR_DATA]  = {.type = NLA_STRING},
    [PARALLEL_GENL_ATTR_BINARY] = {.type = NLA_BINARY},
    [PARALLEL_GENL_ATTR_NAME] = {.type = NLA_NUL_STRING},
    [PARALLEL_GENL_ATTR_DESC] = {.type = NLA_NUL_STRING},
    [PARALLEL_GENL_ATTR_BITFIELD32] = {.type = NLA_BITFIELD32},
    [PARALLEL_GENL_ATTR_SIGN_NUM] = {.type = NLA_S32, .validation_type = NLA_VALIDATE_RANGE, .min = -100, .max = 100},
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
        printk(KERN_ERR "parallel_genl_send: Error with putting value to PARALLEL_GENL_ATTR_DATA\n");
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
    ret = netlink_unicast(skb->sk, msg, info->snd_portid, 1);
    if (ret < 0) {
        return ret;
    }
    return 0;

overrun_block:
    ret = netlink_unicast(skb->sk, msg, info->snd_portid, 0);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

static int parallel_genl_set_str_value(struct sk_buff *skb, struct genl_info *info) 
{
    struct sk_buff *msg;
    void *msg_head;
    struct nlattr *na_path;
    struct nlattr *na_value;
    char *sysfs_path;
    char *new_value = NULL;
    int err;
    int data_len;

    if (!info->attrs[PARALLEL_GENL_ATTR_DATA]) {
        printk(KERN_INFO "parallel_genl_set_str_value: Missing PARALLEL_GENL_ATTR_DATA\n");
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
        printk(KERN_INFO "parallel_genl_set_str_value: Missing PARALLEL_GENL_ATTR_PATH\n");
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
        printk(KERN_ERR "parallel_genl_set_str_value: Error in netlink_unicast, err=%d\n", err);
        nlmsg_free(msg);
        return err;
    }

    kfree(new_value);
    return 0;
}

static int parallel_genl_get_str_value(struct sk_buff *skb, struct genl_info *info) 
{
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
        printk(KERN_ERR "parallel_genl_get_str_value: Incorrect path: %s\n", sysfs_path);
        goto error;
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
            printk(KERN_ERR "parallel_genl_get_str_value: Error in genlmsg_reply, err=%d\n", err);
            nlmsg_free(msg);
            kfree(value);
            return err;
        }

    }
    kfree(value);

    return 0;

error:
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

static int parallel_genl_dump_start(struct netlink_callback *cb) 
{
    printk(KERN_INFO "parallel_genl_dump_start: Dump is started");
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
    int idx = cb->args[0];

    for (;;) {
        if (idx >= DATA_SIZE) {  
            return 0;            
        }

        ret = __parallel_genl_dump_element(&data[idx], NETLINK_CB(cb->skb).portid,
                cb->nlh->nlmsg_seq, NLM_F_MULTI, skb,
                PARALLEL_GENL_CMD_DUMP_INFO);

        if (ret) {
            printk(KERN_ERR "parallel_genl_dump_info: __parallel_genl_dump_element failed: %d\n", ret);
            return ret;
        }

        cb->args[0]++; 
        idx++;
    }

    return ret;
}

static int parallel_genl_dump_done(struct netlink_callback *cb)
{
    printk(KERN_INFO "parallel_genl_dump_done: Dump is done");
	return 0;
}

// Generic Netlink operations for PARALLEL_GENL family
static const struct genl_ops parallel_genl_ops[] = {
    {
        .cmd = PARALLEL_GENL_CMD_SEND,
        .flags = 0,
        .policy = parallel_genl_policy,
        .doit = parallel_genl_send,
        .dumpit = NULL,
    },
    {
        .cmd = PARALLEL_GENL_CMD_DUMP_INFO,
        .flags = 0,
        .policy = parallel_genl_policy,
        .start = parallel_genl_dump_start,
        .dumpit = parallel_genl_dump_info,
        .done = parallel_genl_dump_done,
    },
    {
        .cmd = PARALLEL_GENL_CMD_SET_VALUE,
        .flags = 0,
        .policy = NULL,
        .doit = parallel_genl_set_str_value,
        .dumpit = NULL,
    },
    {
        .cmd = PARALLEL_GENL_CMD_GET_VALUE,
        .flags = GENL_UNS_ADMIN_PERM,
        .policy = parallel_genl_policy,
        .doit = parallel_genl_get_str_value,
    },
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

// genl_family struct for PARALLEL_GENL family
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
    .resv_start_op = PARALLEL_GENL_CMD_DUMP_INFO + 1,
    .mcgrps = genl_many_mcgrps_two,
    .n_mcgrps = ARRAY_SIZE(genl_many_mcgrps_two),
};

static int __init init_netlink(void)
{
	int rc;

	printk(KERN_INFO "init_netlink: My module. Initializing Netlink\n");

	rc = genl_register_family(&my_genl_family);
	if (rc) {
        printk(KERN_ERR "init_netlink: Failed to register Generic Netlink family\n");
		goto failure_1;
    }

    rc = genl_register_family(&my_genl_family_parallel);
	if (rc) {
        printk(KERN_ERR "init_netlink: Failed to register Generic Netlink family\n");
		goto failure_2;
    }

	return 0;

failure_2:
    genl_unregister_family(&my_genl_family);
failure_1:
	pr_debug("init_netlink: My module. Error occurred in %s\n", __func__);
	return rc;
}

static int __init init_sysfs_third_genl(void) 
{
    int ret;

    kobj_third_genl = kobject_create_and_add("third_genl", kernel_kobj);
    
    if (!kobj_third_genl) {
            printk(KERN_ERR "init_sysfs_third_genl: Failed to create kobject\n");
            return -ENOMEM;
    }  

    ret = sysfs_create_file(kobj_third_genl, &my_attr_str_third_genl.attr);
    if (ret) {
            printk(KERN_ERR "init_sysfs_third_genl: Failed to create sysfs file\n");
            goto err_sysfs;
    }

    return 0;

err_sysfs:
    kobject_put(kobj_third_genl);
    return ret;
}

static int __init init_sysfs_parallel_genl(void) 
{
    int ret;

    kobj_parallel_genl = kobject_create_and_add("parallel_genl", kernel_kobj);
    
    if (!kobj_parallel_genl) {
            printk(KERN_ERR "init_sysfs_parallel_genl: Failed to create kobject\n");
            return -ENOMEM;
    }  

    ret = sysfs_create_file(kobj_parallel_genl, &my_attr_str_parallel_genl.attr);
    if (ret) {
            printk(KERN_ERR "init_sysfs_parallel_genl: Failed to create sysfs file\n");
            goto err_sysfs;
    }

    return 0;

err_sysfs:
    kobject_put(kobj_parallel_genl);
    return ret;
}

static int __init init_sysfs_genl_test(void) 
{
    int ret;

    kobj_genl_test = kobject_create_and_add("genl_test", kernel_kobj);
    dev_genl_test = kobj_to_dev(kobj_genl_test);
    
    if (!kobj_genl_test) {
        printk(KERN_ERR "init_sysfs_genl_test: Failed to create kobject\n");
        return -ENOMEM;
    }  

    ret = sysfs_create_file(kobj_genl_test, &my_attr_u32_genl_test.attr);
    if (ret) {
        printk(KERN_ERR "init_sysfs_genl_test: Failed to create sysfs file 1\n");
        goto err_sysfs;
    }

    ret = sysfs_create_file(kobj_genl_test, &my_attr_str_genl_test.attr);
    if (ret) {
        printk(KERN_ERR "init_sysfs_genl_test: Failed to create sysfs file 2\n");
        goto err_sysfs_2;
    }

    ret = device_create_file(dev_genl_test, &dev_attr_info_genl_test);
    if (ret) {
        printk(KERN_ERR "init_sysfs_genl_test: Failed to create device file\n");
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

static int __init module_netlink_init(void) 
{
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

    ret = init_netlink();
    if (ret)
        goto err_sysfs;
    printk(KERN_INFO "my_sysfs_init: New families are registered\n");

    return 0;

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

static void __exit module_netlink_exit(void) 
{
    genl_unregister_family(&my_genl_family);
    genl_unregister_family(&my_genl_family_parallel);

    sysfs_remove_file(kobj_genl_test, &my_attr_u32_genl_test.attr);
    sysfs_remove_file(kobj_genl_test, &my_attr_str_genl_test.attr);
    device_remove_file(dev_genl_test, &dev_attr_info_genl_test);
    kobject_put(kobj_genl_test);

    sysfs_remove_file(kobj_parallel_genl, &my_attr_str_parallel_genl.attr);
    kobject_put(kobj_parallel_genl);
    
    sysfs_remove_file(kobj_third_genl, &my_attr_str_third_genl.attr);
    kobject_put(kobj_third_genl);
    printk(KERN_INFO "my_sysfs_exit: Module is exited\n");
}

module_init(module_netlink_init);
module_exit(module_netlink_exit);
