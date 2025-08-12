// SPDX-License-Identifier: GPL-2.0
/*
 * Generic Netlink and Netlink test cases
 *
 * This test suite validates various aspects of Generic Netlink and Netlink communication
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h> 
#include <ctype.h>
#include <sys/wait.h>
#include <time.h>
#include <inttypes.h>
#include <signal.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include <linux/genetlink.h>

#include "../kselftest_harness.h"

#define MY_GENL_FAMILY_NAME "TEST_GENL"
#define MY_GENL_CMD_UNSPEC 0
#define MY_GENL_CMD_ECHO 1
#define MY_GENL_CMD_SET_VALUE 2
#define MY_GENL_CMD_GET_VALUE 3
#define MY_GENL_CMD_EVENT 4
#define MY_GENL_CMD_NO_ATTRS 5

#define MY_GENL_SMALL_CMD_GET 0

#define MY_GENL_ATTR_UNSPEC 0
#define MY_GENL_ATTR_DATA 1
#define MY_GENL_ATTR_VALUE 2
#define MY_GENL_ATTR_PATH 3
#define MY_GENL_ATTR_NESTED 4
#define MY_GENL_ATTR_MAX 4

#define THIRD_GENL_FAMILY_NAME "THIRD_GENL"

#define THIRD_GENL_CMD_ECHO 1

#define THIRD_GENL_ATTR_UNSPEC 0
#define THIRD_GENL_ATTR_DATA 1
#define THIRD_GENL_ATTR_FLAG 2
#define THIRD_GENL_ATTR_MAX 2

#define PATH_GENL_TEST_NUM "/sys/kernel/genl_test/value"
#define PATH_GENL_TEST_MES "/sys/kernel/genl_test/message"
#define PATH_GENL_TEST_DEV "/sys/kernel/genl_test/some_info"
#define PATH_PARALLEL_GENL_MES "/sys/kernel/parallel_genl/message"
#define PATH_THIRD_GENL_MES "/sys/kernel/third_genl/message"

#define MY_MCGRP_NAME "MY_MCGRP_GENL"

#define GENL_CTRL "nlctrl"
#define CTRL_ATTR_POLICY_MAX (__CTRL_ATTR_POLICY_DUMP_MAX - 1)

#define PARALLEL_GENL_FAMILY_NAME "PARALLEL_GENL"
#define PARALLEL_GENL_ATTR_UNSPEC 0
#define PARALLEL_GENL_CMD_SEND 1
#define PARALLEL_GENL_CMD_DUMP_INFO 2
#define PARALLEL_GENL_CMD_SET_VALUE 3
#define PARALLEL_GENL_CMD_GET_VALUE 4

#define PARALLEL_GENL_ATTR_DATA 1
#define PARALLEL_GENL_ATTR_BINARY 2
#define PARALLEL_GENL_ATTR_NAME 3
#define PARALLEL_GENL_ATTR_DESC 4
#define PARALLEL_GENL_ATTR_FLAG_NONBLOCK 9
#define PARALLEL_GENL_ATTR_FLAG_BLOCK 10
#define PARALLEL_GENL_ATTR_PATH 12
#define PARALLEL_GENL_ATTR_MAX 12

#define LARGE_GENL_FAMILY_NAME "LARGE_GENL"

/**
 * Callback data structures - used to pass data between test cases and message handlers
 */

struct callback_data_ctrl {
    int family_id;
    char *family_name;
    int op;
    struct expected_policies *expected_policy;
    int family_index;
};

static int elem = 0;

static int id_elem = 0;

struct ctrl_policy {
    int id;
    uint32_t field;
    uint32_t type;
    int value;
};

struct ctrl_policy expected_parallel_policy[] = {
    {1, CTRL_ATTR_OP_POLICY, CTRL_ATTR_POLICY_DO, 0},
    {2, CTRL_ATTR_OP_POLICY, CTRL_ATTR_POLICY_DUMP, 0},
    {3, CTRL_ATTR_OP_POLICY, CTRL_ATTR_POLICY_DO, 1},
    {4, CTRL_ATTR_OP_POLICY, CTRL_ATTR_POLICY_DO, 0},
    {5, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 11},
    {6, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 10},
    {7, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 12},
    {8, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 12},
    {9, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 15},
    {9, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_BITFIELD32_MASK, 0},
    {10, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 8},
    {10, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_MIN_VALUE_S, -100},
    {10, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_MAX_VALUE_S, 100},
    {11, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 14},
    {12, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 13},
    {13, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 1},
    {14, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 1},
    {15, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 11},    
};

struct ctrl_policy expected_genl_cmd_get_value_policy[] = {
    {1, CTRL_ATTR_OP_POLICY, CTRL_ATTR_POLICY_DO, 0},
    {2, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 11},
    {3, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 4},
    {3, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_MIN_VALUE_U, 0},
    {3, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_MAX_VALUE_U, 100},
    {4, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 11},
    {5, CTRL_ATTR_POLICY, NL_POLICY_TYPE_ATTR_TYPE, 13},
};

struct expected_policies {
    struct ctrl_policy *policy;
    int count;
    int matched;
};

struct expected_policies parallel_policy = {
    .policy = expected_parallel_policy,
    .count = sizeof(expected_parallel_policy)/sizeof(expected_parallel_policy[0]),
    .matched = 0,
};

struct expected_policies genl_cmd_get_value_policy = {
    .policy = expected_genl_cmd_get_value_policy,
    .count = sizeof(expected_genl_cmd_get_value_policy)/sizeof(expected_genl_cmd_get_value_policy[0]),
    .matched = 0,
};

int validate_cb_ctrl(struct nl_msg *msg, void *arg) 
{
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[CTRL_ATTR_MAX + 1];
    int ret = 0;
    int family_id = -40;
    char *family_name = NULL;

    ret = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, CTRL_ATTR_MAX, NULL); 
    if (ret < 0) {
        printf("Failed to parse attributes: %d\n", ret);
        return NL_STOP; 
    }

    struct callback_data_ctrl *data_ctrl = (struct callback_data_ctrl*)arg;
    switch (gnlh->cmd) {
        case CTRL_CMD_NEWFAMILY:
            if (attrs[CTRL_ATTR_FAMILY_ID]) {
                if (data_ctrl->family_name) {
                    family_name = nla_get_string(attrs[CTRL_ATTR_FAMILY_NAME]);
                    if (!strcmp(family_name, data_ctrl->family_name)) {
                        family_id = nla_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
                        data_ctrl->family_id = family_id;
                    }
                }
            }
            if (attrs[CTRL_ATTR_FAMILY_NAME]) {
                if (data_ctrl->family_id) {
                    if (!data_ctrl->family_name) {
                        family_name = nla_get_string(attrs[CTRL_ATTR_FAMILY_NAME]);
                        data_ctrl->family_name = family_name;
                    }
                }
            }
            data_ctrl->family_index++;
            return NL_OK;
        case CTRL_CMD_GETPOLICY:
            ;
            struct ctrl_policy *exp = &data_ctrl->expected_policy->policy[elem];
            if (attrs[CTRL_ATTR_FAMILY_ID]) {
                family_id = nla_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
                data_ctrl->family_id = family_id;
            }

            if (attrs[CTRL_ATTR_OP_POLICY]) {
                struct nlattr *nla;
                int rem;
  
                nla_for_each_nested(nla, attrs[CTRL_ATTR_OP_POLICY], rem) {
                    struct nlattr *tb[CTRL_ATTR_POLICY_MAX + 1] = {NULL};
                    
                    int err = nla_parse_nested(tb, CTRL_ATTR_POLICY_MAX, nla, NULL);
                    if (err < 0) {
                        printf("Failed to parse nested policy attributes: %d\n", err);
                        continue;
                    } 

                    if (tb[CTRL_ATTR_POLICY_DO]) { 
                        uint32_t do_id = nla_get_u32(tb[CTRL_ATTR_POLICY_DO]);
                        if (exp->field == CTRL_ATTR_OP_POLICY && exp->type == CTRL_ATTR_POLICY_DO && exp->value == do_id) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }
                    
                    if (tb[CTRL_ATTR_POLICY_DUMP]) {
                        uint32_t dump_id = nla_get_u32(tb[CTRL_ATTR_POLICY_DUMP]);
                        if (exp->field == CTRL_ATTR_OP_POLICY && exp->type == CTRL_ATTR_POLICY_DUMP && exp->value == dump_id) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }  
                }
                id_elem++;
            }

            if (attrs[CTRL_ATTR_POLICY]) {
                struct nlattr *policy_attr;
                int rem;

                nla_for_each_nested(policy_attr, attrs[CTRL_ATTR_POLICY], rem) {
                    struct nlattr *tb[NL_POLICY_TYPE_ATTR_MAX + 1] = {NULL};

                    int err = nla_parse_nested(tb, NL_POLICY_TYPE_ATTR_MAX, nla_data(policy_attr), NULL);
                    if (err < 0) {
                        printf("Failed to parse nested policy attributes: %d\n", err);
                        continue;
                    }

                    if (tb[NL_POLICY_TYPE_ATTR_TYPE]) {  // types are defined in enum netlink_attribute_type in kernel
                        uint32_t value1 = nla_get_u32(tb[NL_POLICY_TYPE_ATTR_TYPE]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_TYPE && exp->value == value1) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }

                    if (tb[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]) {
                        int64_t value2 = nla_get_s64(tb[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_MIN_VALUE_S && exp->value == value2) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }
                    
                    if (tb[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]) {
                        int64_t value3 = nla_get_s64(tb[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_MAX_VALUE_S && exp->value == value3) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }

                    if (tb[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]) {
                        uint64_t value4 = nla_get_u64(tb[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_MIN_VALUE_U && exp->value == value4) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }
                    
                    if (tb[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]) {
                        uint64_t value5 = nla_get_u64(tb[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_MAX_VALUE_U && exp->value == value5) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                        }
                    }  
                    if (tb[NL_POLICY_TYPE_ATTR_MIN_LENGTH]) {
                        uint32_t value6 = nla_get_u32(tb[NL_POLICY_TYPE_ATTR_MIN_LENGTH]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_MIN_LENGTH && exp->value == value6) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }
                    
                    if (tb[NL_POLICY_TYPE_ATTR_MAX_LENGTH]) {
                        uint32_t value7 = nla_get_u32(tb[NL_POLICY_TYPE_ATTR_MAX_LENGTH]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_MAX_LENGTH && exp->value == value7) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }    
                    if (tb[NL_POLICY_TYPE_ATTR_POLICY_IDX]) {
                        uint32_t value8 = nla_get_u32(tb[NL_POLICY_TYPE_ATTR_POLICY_IDX]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_POLICY_IDX && exp->value == value8) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }
                    
                    if (tb[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]) {
                        uint32_t value9 = nla_get_u32(tb[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE && exp->value == value9) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }    
                    if (tb[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK]) {
                        uint32_t value10 = nla_get_u32(tb[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_BITFIELD32_MASK && exp->value == value10) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }
                    
                    if (tb[NL_POLICY_TYPE_ATTR_PAD]) {
                        uint64_t value11 = nla_get_u64(tb[NL_POLICY_TYPE_ATTR_PAD]);
                        if (exp->field == CTRL_ATTR_POLICY && exp->type == NL_POLICY_TYPE_ATTR_PAD && exp->value == value11) {
                            data_ctrl->expected_policy->matched++;
                            elem++;
                            if (elem != id_elem) {
                                exp = &data_ctrl->expected_policy->policy[elem];
                            }
                        }
                    }    
                }
                id_elem++;
            }
            return NL_OK;
        default:
            printf("Unknown command: %u\n", gnlh->cmd);
            break;
    }
    return NL_OK;
}

struct nl_sock *socket_alloc_and_conn() 
{
    struct nl_sock *socket;

    socket = nl_socket_alloc();
    if (!socket) {
        fprintf(stderr, "Failed to allocate socket\n");
        return NULL;
    }

    if (genl_connect(socket)) {
        fprintf(stderr, "Failed to connect to generic netlink through socket\n");
        nl_socket_free(socket);
        return NULL;
    }
    return socket;
}

int my_genl_ctrl_resolve(char *family_name) 
{
    struct nl_sock *ctrl_sock;
    int genl_ctrl_family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb_ctrl;
    int err = -100;

    struct callback_data_ctrl cb_ctrl_data;
    cb_ctrl_data.family_name = family_name;

    ctrl_sock = socket_alloc_and_conn();
    if (!ctrl_sock) {
        fprintf(stderr, "socket for genl_ctrl is NULL\n");
        return -ENOMEM;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    if (genl_ctrl_family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", genl_ctrl_family_id);
        err = genl_ctrl_family_id;
        return err;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return -ENOMEM;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_REQUEST | NLM_F_DUMP, CTRL_CMD_GETFAMILY, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return -ENOMEM;
    }

    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, family_name) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_FAMILY_NAME attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return -EMSGSIZE;
    }

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return -ENOMEM;
    }

    err = nl_cb_set(cb_ctrl, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_ctrl, &cb_ctrl_data);
    if (err < 0) {
        printf("Error setting callback\n");
        goto error;
    }

    err = nl_send_auto(ctrl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(ctrl_sock, cb_ctrl);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }

    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return cb_ctrl_data.family_id;
    error:
        nlmsg_free(msg);
        nl_cb_put(cb_ctrl);
        nl_socket_free(ctrl_sock);
        return err;
}

/*
 * Test cases
 */

 /**
 * TEST(capture_start) - Starts Netlink traffic capture using nlmon interface
 * 
 * Creates a virtual nlmon interface, enables it and starts packet capture
 * with tcpdump. Captured packets are saved to 'genetlink.pcap' file.
 * 
 * Note:
 * - Requires root privileges
 * - Creates temporary interface 'nlmon0'
 * - Runs tcpdump in background
 * - Adds small delay to ensure capture starts
 */

TEST (capture_start) 
{
    printf("Running Test: starting Netlink traffic capture...\n");

    // Only root can monitor Netlink traffic
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    char command[256];
    int result;

    snprintf(command, sizeof(command), "ip link add nlmon0 type nlmon");
    result = system(command);
    ASSERT_EQ(WEXITSTATUS(result), 0);
    if (result == -1) {
        perror("system");
        return;
    }

    snprintf(command, sizeof(command), "ip link set nlmon0 up");
    result = system(command);
    ASSERT_EQ(WEXITSTATUS(result), 0);
    if (result == -1) {
        perror("system");
        return;
    }

    snprintf(command, sizeof(command), "tcpdump -i nlmon0 -w genetlink.pcap &");
    result = system(command);
    ASSERT_EQ(WEXITSTATUS(result), 0);
    if (result == -1) {
        perror("system");
        return;
    }

    printf("nlmon is up. Starting netlink process...\n");

    sleep(2);

    printf("Starting Netlink tests...\n");

}

 /**
 * TEST(open_netlink_file) - Verifies correct reading of Netlink socket information
 * 
 * Tests the /proc/net/netlink interface by:
 * 1. Creating a test Netlink socket
 * 2. Reading the proc file before and after socket creation
 * 3. Verifying the socket count changes as expected
 *
 * The test checks that:
 * - /proc/net/netlink is accessible
 * - Entries are properly added/removed
 * - Uses kernel's netlink_seq_ops mechanism
 */

TEST (open_netlink_file) 
{
    FILE *file;
    char line[256];
    int cnt = 0;

    printf("Running Test: opening and reading /proc/net/netlink file...\n");

    struct nl_sock *sock;
    sock = socket_alloc_and_conn();

    file = fopen("/proc/net/netlink", "r");
    ASSERT_NE(NULL, file);
    if (file == NULL) {
        perror("fopen");
        return;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        cnt++;
    }
    
    nl_socket_free(sock);

    fclose(file);

    file = fopen("/proc/net/netlink", "r");
    ASSERT_NE(NULL, file);
    if (file == NULL) {
        perror("fopen");
        return;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        cnt--;
    }
    EXPECT_EQ(cnt, 1);

    fclose(file);
}


/**
 * TEST(genl_ctrl_one_family) - test resolving a single family
 *
 * Validates that Netlink controller correctly resolves family id
 * Test with a single message request
 */

 /**
 * TEST(genl_ctrl_one_family) - Tests resolution of single Generic Netlink family
 *
 * Validates that:
 * 1. Controller correctly resolves family ID for given family name
 * 2. Family ID obtained through direct query matches cached resolution
 * 3. Callback correctly processes controller response
 *
 * Test flow:
 * 1. Creates control socket
 * 2. Sends GETFAMILY request for target family
 * 3. Validates response through callback
 * 4. Compares with direct resolution result
 */

TEST(genl_ctrl_one_family)
{
    struct nl_sock *ctrl_sock;
    int genl_ctrl_family_id;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb_ctrl;
    int err = 0;

    struct callback_data_ctrl cb_ctrl_data;
    cb_ctrl_data.family_id = -30;
    cb_ctrl_data.family_name = NULL;
    cb_ctrl_data.op = -100;

    printf("Running Test: getting family via genl_ctrl...\n");

    ctrl_sock = socket_alloc_and_conn();
    EXPECT_NE(NULL, ctrl_sock);
    if (!ctrl_sock) {
        fprintf(stderr, "socket for genl_ctrl is NULL\n");
        return;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    EXPECT_GT(genl_ctrl_family_id, 0);
    if (genl_ctrl_family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", genl_ctrl_family_id);
        err = genl_ctrl_family_id;
        return;
    }

    msg = nlmsg_alloc();
    EXPECT_NE(NULL, msg);
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_REQUEST, CTRL_CMD_GETFAMILY, 0);
    EXPECT_NE(NULL, user_hdr);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, PARALLEL_GENL_FAMILY_NAME) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_FAMILY_NAME attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        ASSERT_EQ(0, 1);
        return;
    }
    cb_ctrl_data.family_name = PARALLEL_GENL_FAMILY_NAME;

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    EXPECT_NE(NULL, cb_ctrl);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    err = nl_cb_set(cb_ctrl, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_ctrl, &cb_ctrl_data);
    EXPECT_EQ(err, 0);
    if (err < 0) {
        printf("Error setting callback\n");
        goto error;
    }

    err = nl_send_auto(ctrl_sock, msg);
    EXPECT_GE(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(ctrl_sock, cb_ctrl);
    EXPECT_EQ(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }
    my_genl_ctrl_resolve(PARALLEL_GENL_FAMILY_NAME);
    family_id = genl_ctrl_resolve(socket_alloc_and_conn(), PARALLEL_GENL_FAMILY_NAME);
    EXPECT_GT(cb_ctrl_data.family_id, 0);
    EXPECT_GT(family_id, 0);
    EXPECT_EQ(cb_ctrl_data.family_id, family_id);

error:
    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return;
}

 /**
 * TEST(genl_ctrl_family) - Tests dumping all registered Generic Netlink families
 *
 * Verifies that:
 * 1. Controller correctly responds to family dump request
 * 2. No errors occur during dump operation
 *
 * Test flow:
 * 1. Creates control socket and resolves genl_ctrl family
 * 2. Sends GETFAMILY dump request with NLM_F_DUMP flag
 * 3. Checks for operation success
 */

TEST (genl_ctrl_family) 
{
    struct nl_sock *ctrl_sock;
    int genl_ctrl_family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb_ctrl;
    int err = 0;

    struct callback_data_ctrl cb_ctrl_data;
    cb_ctrl_data.family_id = -30;
    cb_ctrl_data.family_name = NULL;
    cb_ctrl_data.op = -100;
    cb_ctrl_data.family_index = 0;

    printf("Running Test: getting families via genl_ctrl...\n");

    ctrl_sock = socket_alloc_and_conn();
    EXPECT_NE(NULL, ctrl_sock);
    if (!ctrl_sock) {
        fprintf(stderr, "socket for genl_ctrl is NULL\n");
        return;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    EXPECT_GT(genl_ctrl_family_id, 0);
    if (genl_ctrl_family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", genl_ctrl_family_id);
        err = genl_ctrl_family_id;
        return;
    }

    msg = nlmsg_alloc();
    EXPECT_NE(NULL, msg);
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_DUMP, CTRL_CMD_GETFAMILY, 0);
    EXPECT_NE(NULL, user_hdr);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    EXPECT_NE(NULL, cb_ctrl);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    err = nl_cb_set(cb_ctrl, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_ctrl, &cb_ctrl_data);
    EXPECT_EQ(err, 0);
    if (err < 0) {
        printf("Error setting callback\n");
        goto error;
    }

    err = nl_send_auto(ctrl_sock, msg);
    EXPECT_GE(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(ctrl_sock, cb_ctrl);
    EXPECT_EQ(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }
    EXPECT_GE(cb_ctrl_data.family_index, 4);
    
error:
    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return;
}

 /**
 * TEST(genl_ctrl_policy) - Validates Generic Netlink policy retrieval mechanism
 *
 * Tests that:
 * 1. Policy information can be retrieved by family ID and name
 * 2. Operation-specific policies can be retrieved
 * 3. Retrieved policies match expected structures
 *
 * Test sequence:
 * 1. Retrieves general policy for PARALLEL_GENL family
 * 2. Retrieves operation-specific policy for MY_GENL_CMD_GET_VALUE
 * 3. Validates policy contents through callback
 */

TEST (genl_ctrl_policy) 
{
    struct nl_sock *ctrl_sock;
    int genl_ctrl_family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb_ctrl;
    int err = 0;

    struct callback_data_ctrl cb_ctrl_data;
    cb_ctrl_data.family_id = -30;
    cb_ctrl_data.family_name = NULL;
    cb_ctrl_data.op = -100;
    cb_ctrl_data.expected_policy = &parallel_policy;
    cb_ctrl_data.expected_policy->matched = 0;

    printf("Running Test: getting policy via genl_ctrl...\n");

    ctrl_sock = socket_alloc_and_conn();
    EXPECT_NE(NULL, ctrl_sock);
    if (!ctrl_sock) {
        fprintf(stderr, "sockets for genl_ctrl and parallel_genl are NULL\n");
        return;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    EXPECT_GT(genl_ctrl_family_id, 0);
    if (genl_ctrl_family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", genl_ctrl_family_id);
        nl_socket_free(ctrl_sock);
        return;
    }

    printf("Start first message with family id and family name\n");
    msg = nlmsg_alloc();
    EXPECT_NE(NULL, msg);
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_DUMP, CTRL_CMD_GETPOLICY, 0);
    EXPECT_NE(NULL, user_hdr);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    if (nla_put_u16(msg, CTRL_ATTR_FAMILY_ID, genl_ctrl_resolve(ctrl_sock, PARALLEL_GENL_FAMILY_NAME)) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_FAMILY_ID attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        ASSERT_EQ(0, 1);
        return;
    }
    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, PARALLEL_GENL_FAMILY_NAME) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_FAMILY_NAME attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        ASSERT_EQ(0, 1);
        return;
    }

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    EXPECT_NE(NULL, cb_ctrl);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    err = nl_cb_set(cb_ctrl, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_ctrl, &cb_ctrl_data);
    EXPECT_EQ(err, 0);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n",  nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(ctrl_sock, msg);
    EXPECT_GE(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(ctrl_sock, cb_ctrl);
    EXPECT_EQ(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }
    EXPECT_EQ(cb_ctrl_data.expected_policy->matched, cb_ctrl_data.expected_policy->count);

    printf("[OK] [1/2]\n");

    cb_ctrl_data.expected_policy = &genl_cmd_get_value_policy;
    cb_ctrl_data.expected_policy->matched = 0;
    elem = 0;
    id_elem = 0;

    nlmsg_free(msg);

    printf("Start second message with family name and ctrl_attr_op\n");
    msg = nlmsg_alloc();
    EXPECT_NE(NULL, msg);
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        nl_cb_put(cb_ctrl);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_DUMP, CTRL_CMD_GETPOLICY, 0);
    EXPECT_NE(NULL, user_hdr);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        goto error;
    }

    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, MY_GENL_FAMILY_NAME) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_FAMILY_NAME attribute: %s\n", strerror(errno));
        EXPECT_EQ(0, 1);
        goto error;
    }

    if (nla_put_u32(msg, CTRL_ATTR_OP, MY_GENL_CMD_GET_VALUE) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_OP attribute: %s\n", strerror(errno));
        EXPECT_EQ(0, 1);
        goto error;
    }
    
    err = nl_send_auto(ctrl_sock, msg);
    EXPECT_GE(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(ctrl_sock, cb_ctrl);
    EXPECT_EQ(err, 0);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }
    
    EXPECT_EQ(cb_ctrl_data.expected_policy->matched, cb_ctrl_data.expected_policy->count);
    printf("[OK] [2/2]\n");

    cb_ctrl_data.expected_policy->matched = 0;
    elem = 0;
    id_elem = 0;

error:
    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return;
}

 /**
 * TEST(capture_end) - Terminates Netlink traffic monitoring session
 *
 * Performs controlled shutdown of nlmon capture interface by:
 * 1. Stopping tcpdump capture process
 * 2. Bringing down nlmon interface
 * 3. Deleting nlmon interface
 *
 * Test Procedure:
 * 1. Privilege Check:
 *    - Verifies root privileges (required for nlmon operations)
 *    - Gracefully skips if not root
 *
 * 2. Capture Termination:
 *    - Stops tcpdump process (2-second delay for cleanup)
 *    - Brings nlmon0 interface down
 *    - Deletes nlmon0 interface
 *    - Validates each operation succeeds
 *
 * 3. Cleanup Verification:
 *    - Checks system command exit statuses
 *    - Provides detailed error reporting
 *
 * Key Validations:
 * - Proper termination of monitoring session
 * - Correct interface teardown
 * - Root privilege enforcement
 * - System command error handling
 *
 * Expected Behavior:
 * - tcpdump process should terminate successfully
 * - nlmon0 interface should deactivate cleanly
 * - Interface should be removable
 * - Non-root execution should skip gracefully
 *
 * Security Considerations:
 * - Requires root for network interface control
 * - Ensures complete capture session cleanup
 * - Verifies proper resource release
 *
 * Note:
 * - Should be paired with capture_start test
 * - Includes 2-second delay for process stabilization
 * - Provides status feedback through printf
 */

TEST (capture_end) 
{
    printf("Running Test: stopping Netlink traffic capture...\n");

    // Only root can monitor Netlink traffic
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}
    
    char command[256];
    int result;

    sleep(2);
    
    snprintf(command, sizeof(command), "pkill tcpdump");
    result = system(command);
    ASSERT_EQ(WEXITSTATUS(result), 0);
    if (result == -1) {
        perror("system");
        return;
    }

    snprintf(command, sizeof(command), "ip link set nlmon0 down");
    result = system(command);
    ASSERT_EQ(WEXITSTATUS(result), 0);
    if (result == -1) {
        perror("system");
        return;
    }

    snprintf(command, sizeof(command), "ip link delete nlmon0 type nlmon");
    result = system(command);
    ASSERT_EQ(WEXITSTATUS(result), 0);
    if (result == -1) {
        perror("system");
        return;
    }

    printf("The capturing is over\n");
}

TEST_HARNESS_MAIN