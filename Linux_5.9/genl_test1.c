#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h> 
#include <ctype.h>
#include <sys/wait.h>
#include <time.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>


#include "../kselftest_harness.h"

#define MY_GENL_FAMILY_NAME "TEST_GENL"
#define MY_GENL_CMD_UNSPEC 0
#define MY_GENL_CMD_ECHO 1
#define MY_GENL_CMD_SET_VALUE 2
#define MY_GENL_CMD_GET_VALUE 3
#define MY_GENL_CMD_EVENT 4
#define MY_GENL_CMD_NO_ATTRS 5

#define MY_GENL_SMALL_CMD_GET_NESTED 0
// #define MY_GENL_SMALL_CMD_ERROR 1

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

#define SOME_RANDOM_CMD 99

// struct for callback function of TEST_GENL
struct callback_data {
    int int_value;
    char *message;
    char *some_info;
};

struct callback_data_parallel_dump {
    char *name;
    char *desc;
};

struct callback_data_parallel_dump data_check[] = {
    {"TEST_GENL", "one"},
    {"PARALLEL_GENL", "two"},
    {"THIRD_GENL", "three"},
    {"LARGE_GENL", "four"},
};
#define DATA_SIZE (sizeof(data_check) / sizeof(data_check[0]))

static int elems = 0;

// struct for callback function of genl_ctrl
struct callback_data_ctrl {
    int family_id;
    char *family_name;
    int op;
};

// struct for callback function of THIRD_GENL
struct callback_data_third {
    char *message;
    int flag;
};

int validate_cb_parallel(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[PARALLEL_GENL_ATTR_MAX + 1];
    int ret = 0;
    int int_value = 30;
    char *message = NULL;
   
    ret = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, PARALLEL_GENL_ATTR_MAX, NULL);  

    if (ret < 0) {
        printf("Failed to parse attributes: %d\n", ret);
        return NL_STOP; 
    }

    struct callback_data *data = (struct callback_data*)arg;
    switch (gnlh->cmd) {
        case PARALLEL_GENL_CMD_SEND:
            if (attrs[PARALLEL_GENL_ATTR_DATA]) {
                message = nla_get_string(attrs[PARALLEL_GENL_ATTR_DATA]);
                data->message = strdup(message); // strdup for safe allocation and copying
                if (data->message == NULL) {
                    perror("strdup failed"); // memory allocation failure
                    return NL_SKIP;
                }
                // data->message = message;
                // printf("Received  value: %s\n", data->message);
            }
            else {
                printf("Attribute not found.\n");
                return NL_SKIP;
            }
            return NL_OK;
        case PARALLEL_GENL_CMD_GET_VALUE:
            if (attrs[PARALLEL_GENL_ATTR_DATA]) {
                message = nla_get_string(attrs[PARALLEL_GENL_ATTR_DATA]);
                data->message = strdup(message); // strdup for safe allocation and copying
                if (data->message == NULL) {
                    perror("strdup failed"); // memory allocation failure
                    return NL_SKIP;
                }
                // printf("Received  value: %s\n", data->message);
            }
            return NL_OK;
    }
}

int validate_cb_parallel_dump(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[PARALLEL_GENL_ATTR_MAX + 1];
    int ret = 0;
    char *name;
    char *desc;
   
    ret = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, PARALLEL_GENL_ATTR_MAX, NULL);  

    if (ret < 0) {
        printf("Failed to parse attributes: %d\n", ret);
        return NL_STOP; 
    }

    struct callback_data_parallel_dump *data = (struct callback_data_parallel_dump*)arg;
    switch (gnlh->cmd) {
        case PARALLEL_GENL_CMD_DUMP_INFO:
            if (attrs[PARALLEL_GENL_ATTR_NAME]) {
                name = nla_get_string(attrs[PARALLEL_GENL_ATTR_NAME]);
                data->name = strdup(name); // strdup for safe allocation and copying
                if (data->name == NULL) {
                    perror("strdup failed"); // memory allocation failure
                    free(data);
                    return NL_SKIP;
                }
                // EXPECT_STREQ(data->name,data_check[elems].name);

                if (strcmp(data->name,data_check[elems].name))
                    printf("[FAILED]\n");
            }
            if (attrs[PARALLEL_GENL_ATTR_DESC]) {
                desc = nla_get_string(attrs[PARALLEL_GENL_ATTR_DESC]);
                data->desc = strdup(desc); // strdup for safe allocation and copying
                if (data->desc == NULL) {
                    perror("strdup failed"); // memory allocation failure
                    return NL_SKIP;
                }
                if (strcmp(data->desc,data_check[elems].desc))
                    printf("[FAILED]\n");
            }
        elems++;
        if (elems == DATA_SIZE) {
            elems = 0;
            printf("[OK]\n");
        }
        return NL_OK;
    }
}

int validate_cb_third(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[PARALLEL_GENL_ATTR_MAX + 1];
    int ret = 0;
    int int_value = 30;
    int flag = -1;
    char *message = NULL;
   
    ret = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, PARALLEL_GENL_ATTR_MAX, NULL);  

    if (ret < 0) {
        printf("Failed to parse attributes: %d\n", ret);
        return NL_STOP; 
    }

    struct callback_data_third *data = (struct callback_data_third*)arg;
    switch (gnlh->cmd) {
        case THIRD_GENL_CMD_ECHO:
            if (attrs[THIRD_GENL_ATTR_DATA]) {
                message = nla_get_string(attrs[THIRD_GENL_ATTR_DATA]);
                data->message = strdup(message);
                if (data->message == NULL) {
                    perror("strdup failed");
                    return NL_SKIP;
                }
                // printf("Received  value: %s\n", data->message);
            }
            if (attrs[THIRD_GENL_ATTR_FLAG]) {
                flag = nla_get_flag(attrs[THIRD_GENL_ATTR_FLAG]);
                data->flag = flag;
                // printf("Received flag: %d\n", data->flag);
            }
            return NL_OK;
    }
}

int validate_cb(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[MY_GENL_ATTR_MAX + 1];
    int ret = 0;
    int int_value = 30;

    ret = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, MY_GENL_ATTR_MAX, NULL); 

    if (ret < 0) {
        printf("Failed to parse attributes: %d\n", ret);
        return NL_STOP; 
    }

    struct callback_data *data = (struct callback_data*)arg;

    switch (gnlh->cmd) {
        case MY_GENL_CMD_GET_VALUE:
            if (attrs[MY_GENL_ATTR_VALUE]) {
                if (nla_len(attrs[MY_GENL_ATTR_VALUE]) >= sizeof(int)) {
                    int_value = nla_get_u32(attrs[MY_GENL_ATTR_VALUE]);
                    data->int_value = int_value; // Store the received value
                    printf("Received integer value: %d\n", data->int_value);
                } else {
                    fprintf(stderr, "MY_GENL_ATTR_VALUE has incorect size");
                    return NL_STOP;
                }
            }
            return NL_OK;

        case MY_GENL_CMD_SET_VALUE:
            if (attrs[MY_GENL_ATTR_VALUE]) {
                if (nla_len(attrs[MY_GENL_ATTR_VALUE]) >= sizeof(int)) {
                    int_value = nla_get_u32(attrs[MY_GENL_ATTR_VALUE]);
                    data->int_value = int_value; // Store the received value
                    // printf("Received integer value: %d\n", data->int_value);
                } else {
                    fprintf(stderr, "MY_GENL_ATTR_VALUE has incorect size");
                    return NL_STOP;
                }
            }
            return NL_OK;

        case MY_GENL_CMD_ECHO:
            if (attrs[MY_GENL_ATTR_DATA]) {
                char *message = nla_get_string(attrs[MY_GENL_ATTR_DATA]);
                data->message = strdup(message);
                if (data->message == NULL) {
                    perror("strdup failed");
                    return NL_SKIP;
                }
                // data->message = message;
                // printf("Received message : %s\n", data->message);
            }
            else {
                printf("Attribute not found.\n");
                return NL_SKIP;
            }
            return NL_OK;

        case MY_GENL_SMALL_CMD_GET_NESTED:
            if (attrs[MY_GENL_ATTR_DATA]) {
                char *message = nla_get_string(attrs[MY_GENL_ATTR_DATA]);
                data->message = strdup(message);
                if (data->message == NULL) {
                    perror("strdup failed");
                    return NL_SKIP;
                }
                // printf("Received message : %s\n", data->message);
            }
            return NL_OK;
        default:
            printf("Unknown command: %u\n", gnlh->cmd);
            break;
    }
    return NL_OK;
}

static const struct nla_policy ctrl_policy_policy[] = {
	[CTRL_ATTR_FAMILY_ID]	= { .type = NLA_U16 },
	[CTRL_ATTR_FAMILY_NAME]	= { .type = NLA_NUL_STRING},
	[CTRL_ATTR_OP]		= { .type = NLA_U32 },
};

int validate_cb_ctrl(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *attrs[11 + 1];
    int ret = 0;
    int err = 0;
    struct genl_family *family;
    int family_id = -40;
    char *family_name = NULL;
    int op = -120;

    ret = genlmsg_parse(nlmsg_hdr(msg), 0, attrs, 11, NULL); 
    if (ret < 0) {
        printf("Failed to parse attributes: %d\n", ret);
        return NL_STOP; 
    }

    struct callback_data_ctrl *data_ctrl = (struct callback_data_ctrl*)arg;
    switch (gnlh->cmd) {
        case CTRL_CMD_NEWFAMILY:   // on cmd CTRL_CMD_GETFAMILY genl_ctrl fill info with CTRL_CMD_NEWFAMILY
            if (attrs[CTRL_ATTR_FAMILY_ID]) {
                family_id = nla_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
                data_ctrl->family_id = family_id;
                // printf("Received family id: %d\n", data_ctrl->family_id);
            }
            if (attrs[CTRL_ATTR_FAMILY_NAME]) {
                family_name = nla_get_string(attrs[CTRL_ATTR_FAMILY_NAME]);
                data_ctrl->family_name = family_name;
                // printf("Received family name: %s \n", data_ctrl->family_name);
            }
            else {
                printf("Attribute not found.\n");
                return NL_SKIP;
            }
            printf("For family id - %d - received family name: %s \n", data_ctrl->family_id, data_ctrl->family_name);
            return NL_OK;
        case CTRL_CMD_GETPOLICY:
            if (attrs[CTRL_ATTR_FAMILY_ID]) {
                family_id = nla_get_u16(attrs[CTRL_ATTR_FAMILY_ID]);
                data_ctrl->family_id = family_id;
                printf("Received family id: %d\n", data_ctrl->family_id);
            }
            if (attrs[CTRL_ATTR_FAMILY_NAME]) {
                family_name = nla_get_string(attrs[CTRL_ATTR_FAMILY_NAME]);
                data_ctrl->family_name = family_name;
                printf("Received family name: %s \n", data_ctrl->family_name);
            }
            if (attrs[CTRL_ATTR_OP]) {
                op = nla_get_u32(attrs[CTRL_ATTR_OP]);
                data_ctrl->op = op;
                printf("op = %d\n", data_ctrl->op);
            }
            // Dynamic parsing of attributes
            for (int i = 0; i < CTRL_ATTR_MAX; ++i) {
                if (attrs[i]) {
                    struct nlattr *nested_attrs[CTRL_ATTR_MAX + 1];

                    err = nla_parse_nested(nested_attrs, CTRL_ATTR_MAX, attrs[i], ctrl_policy_policy); 
                    if (err) {
                        fprintf(stderr, "Error parsing nested policy attributes for attribute %d\n", i);
                        continue;
                    }
                    
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_UNSPEC]) {
                        uint64_t value14 = nla_get_u32(nested_attrs[NL_POLICY_TYPE_ATTR_UNSPEC]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_UNSPEC] %ld for %d\n", value14, i);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_TYPE]) {
                        uint64_t value3 = nla_get_u32(nested_attrs[NL_POLICY_TYPE_ATTR_TYPE]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_TYPE] %ld for %d\n", value3, i);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]) {
                        uint64_t value1 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]  %lu\n", value1);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]) {
                        uint64_t value2 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_U] %lu\n", value2);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]) {
                        uint64_t value4 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_S]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_S] %ld for %d\n", value4, i);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]) {
                        uint64_t value5 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_S]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_S] %ld for %d\n", value5, i);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]) {
                        uint64_t value6 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_U]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MIN_VALUE_U] %ld\n", value6);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]) {
                        uint64_t value7 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_U]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MAX_VALUE_U] %ld\n", value7);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MIN_LENGTH]) {
                        uint64_t value8 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MIN_LENGTH]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MIN_LENGTH] %ld\n", value8);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MAX_LENGTH]) {
                        uint64_t value9 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MAX_LENGTH]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MAX_LENGTH] %ld\n", value9);
                    }
                    // if (nested_attrs[NL_POLICY_TYPE_ATTR_POLICY_IDX]) {
                    //     uint64_t value10 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_POLICY_IDX]);
                    //     printfltp/testcases/kernel/containers/netns("nested_attrs[NL_POLICY_TYPE_ATTR_POLICY_IDX] %ld\n", value10);
                    // }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]) {
                        uint64_t value11 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE] %ld\n", value11);
                    }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK]) {
                        uint64_t value12 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_BITFIELD32_MASK] %ld\n", value12);
                    }
                    // if (nested_attrs[NL_POLICY_TYPE_ATTR_PAD]) {
                    //     uint64_t value13 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_PAD]);
                    //     printf("nested_attrs[NL_POLICY_TYPE_ATTR_PAD] %ld\n", value13);
                    // }
                    if (nested_attrs[NL_POLICY_TYPE_ATTR_MASK]) {
                        uint64_t value14 = nla_get_u64(nested_attrs[NL_POLICY_TYPE_ATTR_MASK]);
                        printf("nested_attrs[NL_POLICY_TYPE_ATTR_MASK] %ld\n", value14);
                    }
                }
            }
            return NL_OK;
        default:
            printf("Unknown command: %u\n", gnlh->cmd);
            break;
    }
    return NL_OK;
}

#define BUFFER_SIZE 256

// Read string from sysfs
int read_string_from_sysfs(const char *path, char *buffer, size_t buffer_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Error opening %s for reading sysfs: %s\n", path, strerror(errno));
        return -errno;
    }

    ssize_t len = read(fd, buffer, buffer_size - 1);
    if (len < 0) {
        fprintf(stderr, "Error reading to %s: %s\n", path, strerror(errno));
        close(fd);
        return -errno;
    }

    buffer[len] = '\0';
    close(fd);
    return 0; 
}

// Read integer from sysfs
int read_int_from_sysfs(const char *path, int *value) {
    char buffer[BUFFER_SIZE];
    int ret;

    ret = read_string_from_sysfs(path, buffer, sizeof(buffer));

    if (ret != 0) {
        return ret;
    }

    char *endptr;
    long val = strtol(buffer, &endptr, 10);   // string to number
    if (endptr == buffer) {
        fprintf(stderr, "Conversion error: %s\n", strerror(errno));
        return -errno;
    }

    *value = (int)val;
    return 0;
}


// Write string to sysfs
int write_string_to_sysfs(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Error opening %s for writing sysfs: %s\n", path, strerror(errno));
        return -errno;
    }

    ssize_t len = write(fd, value, strlen(value));
    if (len < 0) {
        fprintf(stderr, "Error writing to %s: %s\n", path, strerror(errno));
        close(fd);
        return -errno;
    }

    close(fd);
    return 0;
}

// Write integer to sysfs
int write_int_to_sysfs(const char *path, int value) {
    char buffer[32];

    int ret = snprintf(buffer, sizeof(buffer), "%d", value);   // int to string

    if (ret < 0 || ret >= sizeof(buffer)) {
        fprintf(stderr, "Conversion error: %s\n", strerror(errno));
        return -errno;
    }
    
    return write_string_to_sysfs(path, buffer); 
}

struct nl_sock *socket_alloc_and_conn() {
    struct nl_sock *socket;
    // Allocate socket
    socket = nl_socket_alloc();
    if (!socket) {
        fprintf(stderr, "Failed to allocate socket\n");
        return NULL;
    }

    // Connect to generic netlink
    if (genl_connect(socket)) {
        fprintf(stderr, "Failed to connect to generic netlink through socket\n");
        nl_socket_free(socket);
        return NULL;
    }
    return socket;
}

int my_genl_ctrl_resolve(char *family_name) {
    struct nl_sock *ctrl_sock;
    int genl_ctrl_family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb_ctrl;
    int err = 0;

    struct callback_data_ctrl cb_ctrl_data;

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

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_REQUEST, CTRL_CMD_GETFAMILY, 0);
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

TEST (capture_start) 
{
    printf("Running Test: starting Netlink traffic capture...\n");

    // Only root can monitor Netlink trafic
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    char command[256];
    int result;

    // adding nlmon interface
    snprintf(command, sizeof(command), "ip link add nlmon0 type nlmon");
    result = system(command);
    if (result == -1) {
        perror("system");
        return;
    }

    // setting nlmon
    snprintf(command, sizeof(command), "ip link set nlmon0 up");
    result = system(command);
    if (result == -1) {
        perror("system");
        return;
    }

    // starting tcpdump execution with writing to the file
    snprintf(command, sizeof(command), "tcpdump -i nlmon0 -w genl_test1.pcap &");
    result = system(command);
    if (result == -1) {
        perror("system");
        return;
    }

    printf("nlmon is up. Starting netlink process...\n");

    sleep(2); // time is needed

    printf("Starting Netlink test...\n");

}

TEST (open_netlink_file) 
{
    FILE *file;
    char line[256];

    printf("Running Test: opening and reading /proc/net/netlink file...\n");

    // Open /proc/net/netlink
    file = fopen("/proc/net/netlink", "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }

    // Read and show lines from file
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }

    // Close file
    fclose(file);
}

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
    if (!ctrl_sock) {
        fprintf(stderr, "socket for genl_ctrl is NULL\n");
        return;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    if (genl_ctrl_family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", genl_ctrl_family_id);
        err = genl_ctrl_family_id;
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_REQUEST, CTRL_CMD_GETFAMILY, 0);
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
        return;
    }

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
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
    family_id = my_genl_ctrl_resolve(PARALLEL_GENL_FAMILY_NAME);
    EXPECT_EQ(cb_ctrl_data.family_id, family_id);

error:
    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return;
}

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

    printf("Running Test: getting families via genl_ctrl...\n");

    ctrl_sock = socket_alloc_and_conn();
    if (!ctrl_sock) {
        fprintf(stderr, "socket for genl_ctrl is NULL\n");
        return;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    if (genl_ctrl_family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", genl_ctrl_family_id);
        err = genl_ctrl_family_id;
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_DUMP, CTRL_CMD_GETFAMILY, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
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
    printf("[OK]\n");
error:
    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return;
}

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

    printf("Running Test: getting policy via genl_ctrl...\n");

    ctrl_sock = socket_alloc_and_conn();
    if (!ctrl_sock) {
        fprintf(stderr, "sockets for genl_ctrl and parallel_genl are NULL\n");
        return;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    if (genl_ctrl_family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", genl_ctrl_family_id);
        err = genl_ctrl_family_id;
        nl_socket_free(ctrl_sock);
        return;
    }

    printf("Start first message with family id and family name\n");
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_DUMP, CTRL_CMD_GETPOLICY, 0);
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
        return;
    }
    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, PARALLEL_GENL_FAMILY_NAME) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_FAMILY_NAME attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    err = nl_cb_set(cb_ctrl, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_ctrl, &cb_ctrl_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n",  nl_geterror(err));
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

    printf("[OK] [1/2]\n");

    nlmsg_free(msg);

    printf("Start second message with family name and ctrl_attr_op\n");
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        nl_cb_put(cb_ctrl);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_DUMP, CTRL_CMD_GETPOLICY, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        goto error;
    }

    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, MY_GENL_FAMILY_NAME) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_FAMILY_NAME attribute: %s\n", strerror(errno));
        goto error;
    }

    if (nla_put_u32(msg, CTRL_ATTR_OP, MY_GENL_CMD_GET_VALUE) < 0) {
        fprintf(stderr, "Failed to add CTRL_ATTR_OP attribute: %s\n", strerror(errno));
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

    printf("[OK] [2/2]\n");
error:
    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return;
}

TEST (resolve_large_family_id) {
    int family_id;

    family_id = my_genl_ctrl_resolve(LARGE_GENL_FAMILY_NAME);
    ASSERT_TRUE(family_id > 0);
}

// operation is from small ops -- it does not exist in 5.9
// TEST (genl_small_nested_value) 
// {
//     struct nl_sock *sock;
//     int family_id;
//     struct nl_msg *msg;
//     struct genlmsghdr *user_hdr;
//     struct nl_cb *cb;
//     int err = 0;

//     struct callback_data cb_data;
//     cb_data.int_value = -30;
//     cb_data.message = NULL;

//     printf("Running Test: getting value...\n");

//     // Only root can write to sysfs (needs for testing)
// 	if (geteuid()) {
// 		SKIP(return, "test requires root");
// 		return;
// 	}

//     sock = socket_alloc_and_conn();
//     if (!sock) {
//         fprintf(stderr, "socket is NULL\n");
//         return;
//     }

//     family_id = genl_ctrl_resolve(sock, MY_GENL_FAMILY_NAME);
//     if (family_id < 0) {
//         fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", family_id);
//         nl_socket_free(sock);
//         err = family_id;
//         return;
//     }
  
//     msg = nlmsg_alloc();
//     if (!msg) {
//         fprintf(stderr, "Failed to allocate message\n");
//         nl_socket_free(sock);
//         return;
//     }

//     user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, MY_GENL_SMALL_CMD_GET_NESTED, 0);
//     if (!user_hdr) {
//         fprintf(stderr, "Failed to genlmsg_put\n");
//         nlmsg_free(msg);
//         nl_socket_free(sock);
//         return;
//     }

//     cb = nl_cb_alloc(NL_CB_DEFAULT);
//     if (!cb) {
//         fprintf(stderr, "Failed to allocate callback\n");
//         nlmsg_free(msg);
//         nl_socket_free(sock);
//         return;
//     }

//     char *str = malloc(BUFFER_SIZE);

//     err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
//     if (err < 0) {
//         fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
//         goto error;
//     }

//     err = nl_send_auto(sock, msg);
//     if (err < 0) {
//         fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
//         goto error;
//     }

//     err = nl_recvmsgs(sock, cb);
//     if (err < 0) {
//         fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
//         goto error;
//     }

//     err = read_string_from_sysfs(PATH_GENL_TEST_MES, str, BUFFER_SIZE);
//     if (err) {
//         fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
//         goto error;
//     }

//     EXPECT_STREQ(str, cb_data.message);

//     err = write_string_to_sysfs(PATH_GENL_TEST_MES, "default");  // reset
//     if (err) {
//         fprintf(stderr, "Failed to write to sysfs: %s\n", strerror(err));
//         goto error;
//     }

// error:
//     free(str);
//     nlmsg_free(msg);
//     nl_cb_put(cb);
//     nl_socket_free(sock);
//     return;
// }

TEST (genl_parallel) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err = 0;

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: genl_parallel...\n");

    // Only root can write to sysfs (needs for testing)
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = genl_ctrl_resolve(sock, PARALLEL_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", family_id);
        nl_socket_free(sock);
        err = family_id;
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, PARALLEL_GENL_CMD_SEND, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    char *str = malloc(BUFFER_SIZE);

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_parallel, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }

    err = read_string_from_sysfs(PATH_PARALLEL_GENL_MES, str, BUFFER_SIZE);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    EXPECT_STREQ(str, cb_data.message);

    err = write_string_to_sysfs(PATH_PARALLEL_GENL_MES, "default");  // reset
    if (err) {
        fprintf(stderr, "Failed to write to sysfs: %s\n", strerror(err));
        goto error;
    }

error:
    free(str);
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    return;
}

TEST (genl_parallel_dump) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err = 0;

    struct callback_data_parallel_dump cb_data;

    printf("Running Test: doing parallel dump wuth genl_parallel_dump...\n");
    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = genl_ctrl_resolve(sock, PARALLEL_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", family_id);
        nl_socket_free(sock);
        err = family_id;
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_DUMP, PARALLEL_GENL_CMD_DUMP_INFO, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    char *str = malloc(BUFFER_SIZE);

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_parallel_dump, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }

    // callback function determines whether the test is successful

error:
    free(str);
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    return;
}

static struct nl_msg* genl_generate_messages(int family_id, int nonblock) {
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    char *data;
    int err;

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        return NULL;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, PARALLEL_GENL_CMD_SEND, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        return NULL;
    }

    if (nonblock) {
        if (nla_put_flag(msg, PARALLEL_GENL_ATTR_FLAG_NONBLOCK) < 0) {
            fprintf(stderr, "Failed to add PARALLEL_GENL_ATTR_FLAG_NONBLOCK flag attribute: %s\n", strerror(errno));
            nlmsg_free(msg);
            return NULL;
        }
    } else {
        if (nla_put_flag(msg, PARALLEL_GENL_ATTR_FLAG_BLOCK) < 0) {
            fprintf(stderr, "Failed to add PARALLEL_GENL_ATTR_FLAG_BLOCK flag attribute: %s\n", strerror(errno));
            nlmsg_free(msg);
            return NULL;
        }
    }

    int data_size = 4068;  // 4068
    data = malloc(data_size);
    if (!data) {
        fprintf(stderr, "Failed to allocate data buffer\n");
        nlmsg_free(msg);
        return NULL;
    }
    memset(data, 1, data_size);

    err = nla_put(msg, PARALLEL_GENL_ATTR_BINARY, data_size, data);
    if (err < 0) {
        fprintf(stderr, "Failed to add PARALLEL_GENL_ATTR_BINARY attribute: %s\n", strerror(errno));
        free(data);
        nlmsg_free(msg);
        return NULL;
    }

    return msg;
}

TEST (incorrect_genl_parallel_with_flag_nonblock_sock) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err = 0;

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: trying to overflow buffer for nonblock socket...\n");

    // Only root can write to sysfs (needs for testing)
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = genl_ctrl_resolve(sock, PARALLEL_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", family_id);
        nl_socket_free(sock);
        err = family_id;
        return;
    }

    err = nl_socket_set_buffer_size(sock, 5000, 5000);
    if (err < 0) {
        fprintf(stderr, "Failed to change socket buffer size: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_parallel, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }
    
    for (int i = 0; i < 20; i++) {
        msg = genl_generate_messages(family_id, 1);
        if (!msg) {
            fprintf(stderr, "Failed to create message\n");
            goto error;
        }
        err = nl_send_auto(sock, msg);
        if (err < 0) {
            fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
            goto error;
        }
    }

    err = nl_recvmsgs(sock, cb);
    if (err < 0) {
        EXPECT_EQ(err, -NLE_NOMEM);   // -NLE_NOMEM  -ENOMEM
    }

error:
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    return;
}


TEST (incorrect_genl_parallel_with_flag_block_sock_one) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err = 0;

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: trying to overflow buffer for block socket first try...\n");

    // Only root can write to sysfs (needs for testing)
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = genl_ctrl_resolve(sock, PARALLEL_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %d\n", family_id);
        nl_socket_free(sock);
        err = family_id;
        return;
    }

    err = nl_socket_set_buffer_size(sock, 1000, 1000);
    if (err < 0) {
        fprintf(stderr, "Failed to change socket buffer size: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_parallel, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }
    
    for (int i = 0; i < 5; i++) {
        msg = genl_generate_messages(family_id, 0);
        if (!msg) {
            fprintf(stderr, "Failed to create message\n");
            goto error;
        }
        err = nl_send_auto(sock, msg);
        if (err < 0) {
            fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
            goto error;
        }
    }

    err = nl_recvmsgs(sock, cb);
    printf("err = %d %s\n", err, nl_geterror(err));
    if (err < 0) {
        EXPECT_EQ(err, -NLE_NOMEM);   // -NLE_NOMEM  -ENOMEM
    }

error:
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    return;
}

TEST (incorrect_genl_parallel_with_flag_block_sock_two) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err;
    int sock_fd;

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: trying to overflow buffer for block socket second try...\n");

    // Only root can write to sysfs (needs for testing)
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    sock_fd = nl_socket_get_fd(sock);
    if (sock_fd < 0) {
        fprintf(stderr, "Failed to get socket file descriptor\n");
        err = sock_fd;
        nl_socket_free(sock);
        return;
    }

    family_id = genl_ctrl_resolve(sock, PARALLEL_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %s\n", nl_geterror(err));
        err = family_id;
        nl_socket_free(sock);
        return;
    }

    err = nl_socket_set_buffer_size(sock, 1000, 1000);
    if (err < 0) {
        fprintf(stderr, "Failed to change socket buffer size: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nl_socket_free(sock);
        return;
    }

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_parallel, &cb_data);
    if (err < 0) {
        printf("Error setting callback: %s\n", nl_geterror(err));
        nl_cb_put(cb);
        nl_socket_free(sock);
        return;
    }
    
    send_again:
        msg = genl_generate_messages(family_id, 0);  // 0
        if (!msg) {
            printf("Failed to create message\n");
            goto error;
        }
        err = nl_send_auto(sock, msg);
        if (err < 0) {
            fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
            goto error;
        }

        err = nl_recvmsgs(sock, cb);
        if (err < 0) {
            goto check_err;
        }
        goto check_err;

        nl_socket_free(sock);
    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        return;

    check_err:
        if (err < 0) {
            EXPECT_EQ(err, -NLE_NOMEM);
            goto error;
        } else {
            if (err == 0) goto send_again;
        }
}

TEST (genl_test_get_value) 
{
    struct nl_sock *nl_sock;
    struct genl_family *family;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err = 0;
    int int_value = -10;
    struct genlmsghdr *user_hdr;

    printf("Running Test: getting value from sysfs via Netlink message...\n");

    // Allocate socket and connect to generic netlink
    nl_sock = socket_alloc_and_conn();
    if (!nl_sock) {
        return;
    }

    // Resolve family ID
    family_id = genl_ctrl_resolve(nl_sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        nl_socket_free(nl_sock);
        err = family_id;
        return;
    }

    // Resolve the multicast group ID
    mcgrp_id = genl_ctrl_resolve_grp(nl_sock, MY_GENL_FAMILY_NAME, MY_MCGRP_NAME);
    if (mcgrp_id < 0) {
        nl_socket_free(nl_sock);
        err = mcgrp_id;
        return;
    }

    // Add membership to the multicast group
    err = nl_socket_add_membership(nl_sock, mcgrp_id);
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    // Alloc a message
    msg = nlmsg_alloc();
    if (!msg) {
        nl_socket_free(nl_sock);
        return;
    }

    // Create a message
    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, MY_GENL_CMD_GET_VALUE, 0);
    if (!user_hdr) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    // Add the attribute to the message
    if (nla_put_string(msg, MY_GENL_ATTR_PATH, PATH_GENL_TEST_NUM) < 0) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    // Alloc a callback
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }
    
    // Create a struct to hold the data
    struct callback_data cb_data;
    // Initial values
    cb_data.int_value = 20;
    cb_data.message = NULL;

    // Set up callback
    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {
        goto error;
    }

    // Send a message
    err = nl_send_auto(nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        nl_cb_put(cb);
        return;
    }

    err = nl_recvmsgs(nl_sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        nl_cb_put(cb);
        return;
    }

    err = read_int_from_sysfs(PATH_GENL_TEST_NUM, &int_value);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    EXPECT_EQ(int_value, cb_data.int_value);

    err = write_int_to_sysfs(PATH_GENL_TEST_NUM, -20);  // reset
    if (err) {
        fprintf(stderr, "Failed to write to sysfs: %s\n", strerror(err));
        goto error;
    }

error:
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(nl_sock);
    return;
}

TEST (genl_test_echo) 
{
    struct nl_sock *sock;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err = 0;
    int sock_fd;
    int cap_ack = 1;
    int optval;
    socklen_t optlen = sizeof(optval);

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: getting message that was sent to mcast groups...\n");

    // Only root can write to sysfs (needs for testing)
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    sock = socket_alloc_and_conn();
    if (!sock) {
        return;
    }

    sock_fd = nl_socket_get_fd(sock);
    if (sock_fd < 0) {
        nl_socket_free(sock);
        err = sock_fd;
        return;
    }

    err = setsockopt(sock_fd, SOL_NETLINK,  NETLINK_CAP_ACK, &cap_ack, sizeof(cap_ack));
    if (err < 0) {
        nl_socket_free(sock);
        return;
    }

    err = getsockopt(sock_fd, SOL_NETLINK, NETLINK_CAP_ACK, &optval, &optlen);
    if (err < 0) {
        nl_socket_free(sock);
        return;
    }

    family_id = genl_ctrl_resolve(sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        nl_socket_free(sock);
        err = family_id;
        return;
    }

    mcgrp_id = genl_ctrl_resolve_grp(sock, MY_GENL_FAMILY_NAME, MY_MCGRP_NAME);
    if (mcgrp_id < 0) {
        err = mcgrp_id;
        fprintf(stderr, "Failed to resolve multicast group: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    err = nl_socket_add_membership(sock, mcgrp_id);
    if (err < 0) {
        fprintf(stderr, "Failed to add membership: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        nl_socket_free(sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_ECHO, MY_GENL_CMD_ECHO, 0);
    if (!user_hdr) {
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    char *str = malloc(BUFFER_SIZE);

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {
        goto error;
    }
    
    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        free(str);
        nlmsg_free(msg);
        nl_cb_put(cb);
        return;
    }

    err = nl_recvmsgs(sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        free(str);
        nlmsg_free(msg);
        nl_cb_put(cb);
        return;
    }

    err = read_string_from_sysfs(PATH_GENL_TEST_MES, str, BUFFER_SIZE);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    EXPECT_STREQ(str, cb_data.message);

    err = write_string_to_sysfs(PATH_GENL_TEST_MES, "default");
    if (err) {
        fprintf(stderr, "Failed to write to sysfs: %s\n", strerror(err));
        goto error;
    }

error:
    free(str);
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    return;
}

TEST (genl_test_set_value) 
{
    struct nl_sock *nl_sock;
    struct genl_family *family;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err = 0;
    int int_value;
    int sock_fd;
    int up = 1;
    struct genlmsghdr *user_hdr;

    int optval;
    socklen_t optlen = sizeof(optval);

    printf("Running Test: sending correct value for sysfs to genl_test...\n");

    // Only root can write to sysfs (needs for testing)
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    nl_sock = socket_alloc_and_conn();
    if (!nl_sock) {
        return;
    }

    sock_fd = nl_socket_get_fd(nl_sock);
    if (sock_fd < 0) {
        err = sock_fd;
        nl_socket_free(nl_sock);
        return;
    }

    err = setsockopt(sock_fd, SOL_NETLINK,  NETLINK_GET_STRICT_CHK, &up, sizeof(up));
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    err = getsockopt(sock_fd, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &optval, &optlen);
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    family_id = genl_ctrl_resolve(nl_sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        nl_socket_free(nl_sock);
        err = family_id;
        return;
    }
    // printf("Resolved family ID: %d\n", family_id);

    mcgrp_id = genl_ctrl_resolve_grp(nl_sock, MY_GENL_FAMILY_NAME, MY_MCGRP_NAME);
    if (mcgrp_id < 0) {
        nl_socket_free(nl_sock);
        err = mcgrp_id;
        return;
    }

    err = nl_socket_add_membership(nl_sock, mcgrp_id);
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        nl_socket_free(nl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, MY_GENL_CMD_SET_VALUE, 0);
    if (!user_hdr) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    if (nla_put_string(msg, MY_GENL_ATTR_PATH, PATH_GENL_TEST_NUM) < 0) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    if (nla_put_u32(msg, MY_GENL_ATTR_VALUE, 1) < 0) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }
    
    // Create a struct to hold the data
    struct callback_data cb_data;
    cb_data.int_value = 74;
    cb_data.message = NULL;

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {  
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        nl_cb_put(cb);
        return;
    }

    err = nl_recvmsgs(nl_sock, cb);
    if (err < 0) {
        if (geteuid() != 0) {
            // fprintf(stderr, "Needs to have CAP_NET_ADMIN\n");
            EXPECT_EQ(err, -NLE_PERM);
        }
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        nlmsg_free(msg);
        nl_cb_put(cb);
        return;
    }

    err = read_int_from_sysfs(PATH_GENL_TEST_NUM, &int_value);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    EXPECT_EQ(int_value, cb_data.int_value);

    err = write_int_to_sysfs(PATH_GENL_TEST_NUM, -20);
    if (err) {
        fprintf(stderr, "Failed to write to sysfs: %s\n", strerror(err));
        goto error;
    }

error:
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(nl_sock);
    return;
}

TEST (incorrect_genl_test_set_value) 
{
    struct nl_sock *nl_sock;
    struct genl_family *family;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err;
    int int_value;
    int sock_fd;
    int ext_ack = 1; // Enable extended acknowledgments
    int broadcast_error = 1;


    int optval;
    socklen_t optlen = sizeof(optval);

    printf("Running Test: sending incorrect value for sysfs to genl_test...\n");

    // Allocate socket and connect to generic netlink
    nl_sock = socket_alloc_and_conn();
    if (!nl_sock) {
        printf("socket for my_genl is NULL\n");
        return;
    }

    // It's important while testing messages with TLV - socket flag NETLINK_EXT_ACK
    sock_fd = nl_socket_get_fd(nl_sock);
    if (sock_fd < 0) {
        fprintf(stderr, "Failed to get socket file descriptor\n");
        err = sock_fd;
        nl_socket_free(nl_sock);
        return;
    }

    err = setsockopt(sock_fd, SOL_NETLINK,  NETLINK_EXT_ACK, &ext_ack, sizeof(ext_ack));
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    err = getsockopt(sock_fd, SOL_NETLINK, NETLINK_EXT_ACK, &optval, &optlen);
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    EXPECT_EQ(optval, 1);

    err = setsockopt(sock_fd, SOL_NETLINK,  NETLINK_BROADCAST_ERROR, &broadcast_error, sizeof(broadcast_error));
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    err = getsockopt(sock_fd, SOL_NETLINK, NETLINK_BROADCAST_ERROR, &optval, &optlen);
    if (err < 0) {
        nl_socket_free(nl_sock);
        return;
    }

    EXPECT_EQ(optval, 1);

    // Resolve family ID
    family_id = genl_ctrl_resolve(nl_sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    // Resolve the multicast group ID
    mcgrp_id = genl_ctrl_resolve_grp(nl_sock, MY_GENL_FAMILY_NAME, MY_MCGRP_NAME);
    if (mcgrp_id < 0) {
        err = mcgrp_id;
        fprintf(stderr, "Failed to resolve multicast group: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    // Add membership to the multicast group
    err = nl_socket_add_membership(nl_sock, mcgrp_id);
    if (err < 0) {
        fprintf(stderr, "Failed to add membership: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    // Create message
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(nl_sock);
        return;
    }

    struct genlmsghdr *user_hdr;
    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, MY_GENL_CMD_SET_VALUE, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    // Add the attribute
    if (nla_put_string(msg, MY_GENL_ATTR_PATH, PATH_GENL_TEST_NUM) < 0) {
        fprintf(stderr, "Failed to add MY_GENL_ATTR_PATH attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    if (nla_put_u32(msg, MY_GENL_ATTR_VALUE, 34) < 0) {
        fprintf(stderr, "Failed to add MY_GENL_ATTR_VALUE attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    // Set up callback
    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }
    
    // Create a struct to hold the data
    struct callback_data cb_data;
    cb_data.int_value = 74;
    cb_data.message = NULL;

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {  
        printf("Error setting callback\n");
        goto error;
    }

    err = nl_send_auto(nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    // nl_recvmsgs gets error code from error ACK from kernel
    err = nl_recvmsgs(nl_sock, cb);
    if (err < 0) {
        if (geteuid() != 0) {
            EXPECT_EQ(err, -NLE_PERM);  // operation needs CAP_NET_ADMIN
        }
        if (geteuid() == 0)
            EXPECT_EQ(err, -NLE_INVAL);     // convert kernel -EINVAL to libnl specific error code -NLE_INVAL 
    }

error:
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(nl_sock);
    return;
}

TEST (incorrect_family) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err;

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: trying to find id of incorrect Netlink family...\n");

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = genl_ctrl_resolve(sock, "SOME_RANDOM_NAME");
    if (family_id < 0) {
        err = family_id;
        EXPECT_EQ(err, -NLE_OBJ_NOTFOUND);
    }

    nl_socket_free(sock);
}

TEST (incorrect_family_id) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err;

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: trying to send a message to incorrect id of Netlink family (== non-existent cmd)...\n");

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = genl_ctrl_resolve(sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(sock);
        return;
    }

    // put incorrect id for Netlink message               // here
    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id + 1, 0, NLM_F_REQUEST, MY_GENL_CMD_NO_ATTRS, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }
    
    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    // waiting for "Operation not supported" error cuz for this family id - cmd does not exist
    err = nl_recvmsgs(sock, cb);
   
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    ASSERT_EQ(err, -NLE_OPNOTSUPP);
    return;

    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(sock);
        return;
}

TEST (incorrect_cmd) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err;

    struct callback_data cb_data;
    cb_data.int_value = -30;
    cb_data.message = NULL;

    printf("Running Test: trying to send incorrect == non-existent cmd...\n");

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = genl_ctrl_resolve(sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, SOME_RANDOM_CMD, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }
    
    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    // waiting for "Operation not supported" error cuz for this family id - cmd does not exist
    err = nl_recvmsgs(sock, cb);
    if (err < 0) {
        EXPECT_EQ(err, -NLE_OPNOTSUPP);
    }

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    return;

    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(sock);
        return;
}

TEST (incorrect_ctrl_family_name) 
{
    struct nl_sock *ctrl_sock;
    int genl_ctrl_family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb_ctrl;
    int err;

    struct callback_data_ctrl cb_ctrl_data;
    cb_ctrl_data.family_id = -30;
    cb_ctrl_data.family_name = NULL;
    cb_ctrl_data.op = -100;

    printf("Running Test: sending invalid family name to genl_ctrl...\n");

    ctrl_sock = socket_alloc_and_conn();
    if (!ctrl_sock) {
        fprintf(stderr, "socket for genl_ctrl is NULL\n");
        return;
    }

    genl_ctrl_family_id = genl_ctrl_resolve(ctrl_sock, GENL_CTRL);
    if (genl_ctrl_family_id < 0) {
        err = genl_ctrl_family_id;
        fprintf(stderr, "Failed to resolve family id for genl_ctrl: %s\n", nl_geterror(err));
        nl_socket_free(ctrl_sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(ctrl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_ctrl_family_id, 0, NLM_F_REQUEST, CTRL_CMD_GETFAMILY, 0);  // NLM_F_DUMP
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    if (nla_put_string(msg, CTRL_ATTR_FAMILY_NAME, "SOME_RANDOM_NAME") < 0) {
        fprintf(stderr, "Failed to add incorrect CTRL_ATTR_FAMILY_NAME attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    cb_ctrl = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb_ctrl) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(ctrl_sock);
        return;
    }

    err = nl_cb_set(cb_ctrl, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_ctrl, &cb_ctrl_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(ctrl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    // as we send incorrect family name to genl_ctrl the we expect "Invalid input data or parameter" error
    err = nl_recvmsgs(ctrl_sock, cb_ctrl);
    if (err < 0) {
        EXPECT_EQ(err, -NLE_INVAL);
    }

    nlmsg_free(msg);
    nl_cb_put(cb_ctrl);
    nl_socket_free(ctrl_sock);
    return;

    error:
        nlmsg_free(msg);
        nl_cb_put(cb_ctrl);
        nl_socket_free(ctrl_sock);
        return;
}

TEST (genl_test_get_value_sock_option) 
{
    struct nl_sock *nl_sock;
    struct genl_family *family;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err;
    int int_value;
    int no_enobufs_val = 1;   // Set NETLINK_NO_ENOBUFS
    int sock_fd;              // fd

    int optval;
    socklen_t optlen = sizeof(optval);

    printf("Running Test: sending message with NETLINK_NO_ENOBUFS socket option...\n");

    nl_sock = socket_alloc_and_conn();
    if (!nl_sock) {
        printf("socket for my_genl is NULL\n");
        return;
    }

    // get fd
    sock_fd = nl_socket_get_fd(nl_sock);
    if (sock_fd < 0) {
        err = sock_fd;
        fprintf(stderr, "Failed to get socket file descriptor: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    err = setsockopt(sock_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &no_enobufs_val, sizeof(no_enobufs_val));
    if (err < 0) {
        fprintf(stderr, "Failed to set NETLINK_NO_ENOBUFS: %s\n", strerror(errno));
        err = -errno; // get setsockopt error
        nl_socket_free(nl_sock);
        return;
    }

    err = getsockopt(sock_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &optval, &optlen);
    if (err < 0) {
        fprintf(stderr, "Failed to get NETLINK_NO_ENOBUFS: %s\n", strerror(errno));
        err = -errno; // get getsockopt error
        nl_socket_free(nl_sock);
        return;
    }

    EXPECT_EQ(optval, 1);

    family_id = genl_ctrl_resolve(nl_sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    // Resolve the multicast group ID
    mcgrp_id = genl_ctrl_resolve_grp(nl_sock, MY_GENL_FAMILY_NAME, MY_MCGRP_NAME);
    if (mcgrp_id < 0) {
        err = mcgrp_id;
        fprintf(stderr, "Failed to resolve multicast group: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    // Add membership to the multicast group
    err = nl_socket_add_membership(nl_sock, mcgrp_id);
    if (err < 0) {
        fprintf(stderr, "Failed to add membership: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(nl_sock);
        return;
    }

    struct genlmsghdr *user_hdr;
    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, MY_GENL_CMD_GET_VALUE, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    if (nla_put_string(msg, MY_GENL_ATTR_PATH, PATH_GENL_TEST_NUM) < 0) {
        fprintf(stderr, "Failed to add MY_GENL_ATTR_PATH attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }
    
    // Create a struct to hold the data
    struct callback_data cb_data;

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(nl_sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }

    err = read_int_from_sysfs(PATH_GENL_TEST_NUM, &int_value);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    EXPECT_EQ(int_value, cb_data.int_value);

    err = write_int_to_sysfs(PATH_GENL_TEST_NUM, -20);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(nl_sock);
    return;

    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(nl_sock);
        return;
}

TEST (incorrect_genl_test_ext_ack) 
{
    struct nl_sock *nl_sock;
    struct genl_family *family;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err;
    int int_value;
    int up;
    int sock_fd;

    int optval;
    socklen_t optlen = sizeof(optval);

    printf("Running Test: sending message with NETLINK_EXT_ACK socket option and incorrect path value...\n");

    nl_sock = socket_alloc_and_conn();
    if (!nl_sock) {
        fprintf(stderr, "socket for my_genl is NULL\n");
        return;
    }

    sock_fd = nl_socket_get_fd(nl_sock);
    if (sock_fd < 0) {
        err = sock_fd;
        fprintf(stderr, "Failed to get socket file descriptor: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    // Set extended ACK (NETLINK_EXT_ACK)
    up = 1;
    err = setsockopt(sock_fd, SOL_NETLINK, NETLINK_EXT_ACK, &up, sizeof(up));
    if (err < 0) {
        fprintf(stderr, "Failed to set NETLINK_EXT_ACK: %s", strerror(errno));
        err = -errno;
        nl_socket_free(nl_sock);
        return;
    }

    err = getsockopt(sock_fd, SOL_NETLINK, NETLINK_EXT_ACK, &optval, &optlen);
    if (err < 0) {
        fprintf(stderr, "Failed to get NETLINK_EXT_ACK: %s", strerror(errno));
        err = -errno;
        nl_socket_free(nl_sock);
        return;
    }

    EXPECT_EQ(optval, 1);

    family_id = genl_ctrl_resolve(nl_sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    mcgrp_id = genl_ctrl_resolve_grp(nl_sock, MY_GENL_FAMILY_NAME, MY_MCGRP_NAME);
    if (mcgrp_id < 0) {
        err = mcgrp_id;
        fprintf(stderr, "Failed to resolve multicast group: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    err = nl_socket_add_membership(nl_sock, mcgrp_id);
    if (err < 0) {
        fprintf(stderr, "Failed to add membership: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(nl_sock);
        return;
    }

    struct genlmsghdr *user_hdr;
    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, MY_GENL_CMD_GET_VALUE, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    if (nla_put_string(msg, MY_GENL_ATTR_PATH, "some/random/path") < 0) {
        fprintf(stderr, "Failed to add MY_GENL_ATTR_PATH attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }
    
    // Create a struct to hold the data
    struct callback_data cb_data;

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    // got -ENOENT from kernel "Object not found" error in libnl means -NLE_OBJ_NOTFOUND
    err = nl_recvmsgs(nl_sock, cb);
    if (err < 0) {
        EXPECT_EQ(err, -NLE_OBJ_NOTFOUND);
    }

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(nl_sock);
    return;

    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(nl_sock);
        return;
} 

TEST (genl_test_sock_listen_all_nsid) 
{    
    struct nl_sock *nl_sock;
    struct genl_family *family;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err;
    int int_value;
    int up;
    int sock_fd;

    int optval;
    socklen_t optlen = sizeof(optval);

    printf("Running Test: setting NETLINK_LISTEN_ALL_NSID option for socket...\n");

    // Only root can listen to different Netlink namespaces
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    nl_sock = socket_alloc_and_conn();
    if (!nl_sock) {
        printf("socket for my_genl is NULL\n");
        return;
    }

    err = nl_socket_set_buffer_size(nl_sock, 327680000, 3276800000);
    if (err < 0) {
        fprintf(stderr, "Failed to change socket buffer size: %s\n", strerror(err));
        nl_socket_free(nl_sock);
        return;
    }

    sock_fd = nl_socket_get_fd(nl_sock);
    if (sock_fd < 0) {
        err = sock_fd;
        fprintf(stderr, "Failed to get socket file descriptor: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    // NETLINK_LISTEN_ALL_NSID - listening all nsid
    up = 1;
    err = setsockopt(sock_fd, SOL_NETLINK, NETLINK_LISTEN_ALL_NSID, &up, sizeof(up));   // NETLINK_LISTEN_ALL_NSID needs to nave rights CAP_NET_BROADCAST
    if (err < 0) {
        if (geteuid() != 0) {
            EXPECT_EQ(err, -NLE_PERM);
            nl_socket_free(nl_sock);
            return;
        }
        fprintf(stderr, "Failed to set NETLINK_LISTEN_ALL_NSID: %s\n", strerror(err));
        nl_socket_free(nl_sock);
        return;
    }   // there are no function ops to getsockopt NETLINK_LISTEN_ALL_NSID therefore for that no checks can be done

    family_id = genl_ctrl_resolve(nl_sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    mcgrp_id = genl_ctrl_resolve_grp(nl_sock, MY_GENL_FAMILY_NAME, MY_MCGRP_NAME);
    if (mcgrp_id < 0) {
        err = mcgrp_id;
        fprintf(stderr, "Failed to resolve multicast group: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    err = nl_socket_add_membership(nl_sock, mcgrp_id);
    if (err < 0) {
        fprintf(stderr, "Failed to add membership: %s\n", nl_geterror(err));
        nl_socket_free(nl_sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(nl_sock);
        return;
    }

    struct genlmsghdr *user_hdr;
    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, MY_GENL_CMD_GET_VALUE, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    if (nla_put_string(msg, MY_GENL_ATTR_PATH, PATH_GENL_TEST_NUM) < 0) {
        fprintf(stderr, "Failed to add MY_GENL_ATTR_PATH attribute: %s\n", strerror(errno));
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }
    
    // Create a struct to hold the data
    struct callback_data cb_data;

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) { 
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(nl_sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }

    err = read_int_from_sysfs(PATH_GENL_TEST_NUM, &int_value);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    EXPECT_EQ(int_value, cb_data.int_value);

    err = write_int_to_sysfs(PATH_GENL_TEST_NUM, -20);
    if (err) {
        fprintf(stderr, "Failed to write to sysfs: %s\n", strerror(err));
        goto error;
    }

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(nl_sock);
    return;

    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(nl_sock);
        return;
} 

TEST (genl_third_echo) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err;

    struct callback_data_third cb_data;

    printf("Running Test: sending message to third_genl...\n");

    // Only root can write to sysfs (needs for testing)
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = my_genl_ctrl_resolve(THIRD_GENL_FAMILY_NAME);
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id for THIRD_GENL: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_ECHO, THIRD_GENL_CMD_ECHO, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    char *str = malloc(BUFFER_SIZE);

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_third, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }
    
    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(sock, cb);
    if (err < 0) {
        fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
        goto error;
    }
    
    err = read_string_from_sysfs(PATH_THIRD_GENL_MES, str, BUFFER_SIZE);
    if (err) {
        fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
        goto error;
    }

    EXPECT_STREQ(str, cb_data.message);

    err = write_string_to_sysfs(PATH_THIRD_GENL_MES, "default");
    if (err) {
        fprintf(stderr, "Failed to write to sysfs: %s\n", strerror(err));
        goto error;
    }

    free(str);
    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);
    return; 

    error:
        free(str);
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(sock);
        return;   
}

TEST (incorrect_genl_third_echo_flags_one) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err;

    struct callback_data_third cb_data;

    printf("Running Test: sending message with incorrect flags to third_genl...\n");

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = my_genl_ctrl_resolve("THIRD_GENL");
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id for THIRD_GENL: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_ECHO | NLM_F_DUMP | NLM_F_ATOMIC, THIRD_GENL_CMD_ECHO, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_third, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }
    
    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(sock, cb);

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);

    printf("Linux 5.9 will send -EOPNOTSUPP ------ Linux 6.1 will send -EINVAL");
    ASSERT_EQ(err, -NLE_INVAL);    // invalid flags were sent    // I get only -NLE_OPNOTSUPP

    return; 

    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(sock);
        return;   
}


TEST (incorrect_genl_third_echo_flags_two) 
{
    struct nl_sock *sock;
    int family_id;
    struct nl_msg *msg;
    struct genlmsghdr *user_hdr;
    struct nl_cb *cb;
    int err;

    struct callback_data_third cb_data;

    printf("Running Test: sending message with incorrect flags to third_genl...\n");

    sock = socket_alloc_and_conn();
    if (!sock) {
        fprintf(stderr, "socket is NULL\n");
        return;
    }

    family_id = my_genl_ctrl_resolve("THIRD_GENL");
    if (family_id < 0) {
        err = family_id;
        fprintf(stderr, "Failed to resolve family id for THIRD_GENL: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "Failed to allocate message\n");
        nl_socket_free(sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_ECHO | NLM_F_ATOMIC, THIRD_GENL_CMD_ECHO, 0);
    if (!user_hdr) {
        fprintf(stderr, "Failed to genlmsg_put\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(sock);
        return;
    }

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_third, &cb_data);
    if (err < 0) {
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }
    
    err = nl_send_auto(sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(sock, cb);

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(sock);

    ASSERT_EQ(err, -NLE_INVAL);    // invalid flags were sent

    return; 

    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(sock);
        return;   
}

TEST (new_socket_netlink_usersock)   // check result
{
    #define NETLINK_USERSOCK	2	// Reserved for user mode socket protocols
    int err;
    int sock_fd;

    struct nl_sock *sock;

    printf("Running Test: creating socket for user mode and checking it existence in the system...\n");

    sock = nl_socket_alloc();
    if (!sock) {
        fprintf(stderr, "Failed to allocate socket\n");
        return;
    }

    err = nl_connect(sock, NETLINK_USERSOCK);
    if (err) {
        fprintf(stderr, "Failed to connect to Netlink using NETLINK_USERSOCK: %s\n", nl_geterror(err));
        nl_socket_free(sock);
        return;
    }

    FILE *file;
    char line[256];
    char sk[20];
    int Eth, Pid;
    unsigned int Groups, Rmem, Wmem, Dump, Locks, Drops, Inode;

    int count_user_socks = 0;


    // Open /proc/net/netlink
    file = fopen("/proc/net/netlink", "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }

    // Skip header
    fgets(line, sizeof(line), file);

    // Parse line
    while(fgets(line, sizeof(line), file) != NULL) {
        if (!isxdigit(line[0])) break;  // check if the first column is 16-number value
        if (sscanf(line, "%19s %d %d %x %u %u %u %u %u %u", // limit sk len to 19 symbols
                    sk, &Eth, &Pid, &Groups, &Rmem, &Wmem, &Dump, &Locks, &Drops, &Inode) == 10) {
            // printf("SK: %s, Eth: %d, Pid: %d, Groups: %x, Inode: %u\n", sk, Eth, Pid, Groups, Inode);
            if (Eth == NETLINK_USERSOCK) count_user_socks += 1;
        } else {
            fprintf(stderr, "Failed to parse line: %s", line);
        }
    }

    // Close file
    fclose(file);
    
    nl_socket_free(sock);

    sleep(2);
    
    // Open /proc/net/netlink
    file = fopen("/proc/net/netlink", "r");
    if (file == NULL) {
        perror("fopen");
        return;
    }

    // Skip header
    fgets(line, sizeof(line), file);

    // Parse line
    while(fgets(line, sizeof(line), file) != NULL) {
        if (!isxdigit(line[0])) break;
        if (sscanf(line, "%19s %d %d %x %u %u %u %u %u %u", // limit sk len to 19 symbols
                    sk, &Eth, &Pid, &Groups, &Rmem, &Wmem, &Dump, &Locks, &Drops, &Inode) == 10) {
            // printf("SK: %s, Eth: %d, Pid: %d, Groups: %x, Inode: %u\n", sk, Eth, Pid, Groups, Inode);
            if (Eth == NETLINK_USERSOCK) count_user_socks -= 1;
        } else {
            fprintf(stderr, "Failed to parse line: %s", line);
        }
    }

    // Close file
    fclose(file);

    EXPECT_TRUE(count_user_socks == 1);

    return;
}

TEST (incorrect_parallel_genl_reject_policy_set_value) 
{
    struct nl_sock *nl_sock;
    struct genl_family *family;
    int family_id;
    int mcgrp_id;
    struct nl_msg *msg;
    struct nl_cb *cb;
    int err = 0;
    char *value;
    struct genlmsghdr *user_hdr;

    printf("Running Test: sending correct value for sysfs to pallel_genl to check reject policy...\n");

    nl_sock = socket_alloc_and_conn();
    if (!nl_sock) {
        return;
    }

    family_id = genl_ctrl_resolve(nl_sock, PARALLEL_GENL_FAMILY_NAME);
    if (family_id < 0) {
        nl_socket_free(nl_sock);
        err = family_id;
        return;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        nl_socket_free(nl_sock);
        return;
    }

    user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, PARALLEL_GENL_CMD_SET_VALUE, 0);
    if (!user_hdr) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    if (nla_put_string(msg, PARALLEL_GENL_ATTR_PATH, PATH_PARALLEL_GENL_MES) < 0) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    value = "value for reject";
    if (nla_put_string(msg, PARALLEL_GENL_ATTR_DATA, value) < 0) {
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        fprintf(stderr, "Failed to allocate callback\n");
        nlmsg_free(msg);
        nl_socket_free(nl_sock);
        return;
    }
    
    // Create a struct to hold the data
    struct callback_data cb_data;

    err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb, &cb_data);
    if (err < 0) {  
        fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_send_auto(nl_sock, msg);
    if (err < 0) {
        fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
        goto error;
    }

    err = nl_recvmsgs(nl_sock, cb);

    nlmsg_free(msg);
    nl_cb_put(cb);
    nl_socket_free(nl_sock);

    ASSERT_EQ(err, -NLE_INVAL);   // reject policy - all attributes were skipped  (in my code I send -EINVAL)

    return;
    error:
        nlmsg_free(msg);
        nl_cb_put(cb);
        nl_socket_free(nl_sock);
        return;
}

// TEST (parallel_genl_get_value_admin) 
// {
//     struct nl_sock *nl_sock;
//     int family_id;
//     struct nl_msg *msg;
//     struct nl_cb *cb;
//     int err = 0;
//     struct genlmsghdr *user_hdr;

//     printf("Running Test: getting value from sysfs of pallel_genl to check GENL_UNS_ADMIN_PERM...\n");

//     nl_sock = socket_alloc_and_conn();
//     if (!nl_sock) {
//         return;
//     }

//     family_id = genl_ctrl_resolve(nl_sock, PARALLEL_GENL_FAMILY_NAME);
//     if (family_id < 0) {
//         nl_socket_free(nl_sock);
//         err = family_id;
//         return;
//     }

//     msg = nlmsg_alloc();
//     if (!msg) {
//         nl_socket_free(nl_sock);
//         return;
//     }

//     user_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, PARALLEL_GENL_CMD_GET_VALUE, 0);   // PARALLEL_GENL_CMD_GET_VALUE
//     if (!user_hdr) {
//         nlmsg_free(msg);
//         nl_socket_free(nl_sock);
//         return;
//     }

//     if (nla_put_string(msg, PARALLEL_GENL_ATTR_PATH, PATH_PARALLEL_GENL_MES) < 0) {
//         nlmsg_free(msg);
//         nl_socket_free(nl_sock);
//         return;
//     }

//     cb = nl_cb_alloc(NL_CB_DEFAULT);
//     if (!cb) {
//         fprintf(stderr, "Failed to allocate callback\n");
//         nlmsg_free(msg);
//         nl_socket_free(nl_sock);
//         return;
//     }
    
//     // Create a struct to hold the data
//     struct callback_data cb_data;

//     err = nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, validate_cb_parallel, &cb_data);
//     if (err < 0) {  
//         fprintf(stderr, "Error setting callback: %s\n", nl_geterror(err));
//         goto error;
//     }

//     err = nl_send_auto(nl_sock, msg);
//     if (err < 0) {
//         fprintf(stderr, "Failed to send message: %s\n", nl_geterror(err));
//         goto error;
//     }

//     err = nl_recvmsgs(nl_sock, cb);
//     if (err < 0) {
//         if (geteuid() != 0) {
//             EXPECT_EQ(err, -NLE_PERM);
//             nlmsg_free(msg);
//             nl_cb_put(cb);
//             return;
//         }
//         fprintf(stderr, "Failed to receive message: %s\n", nl_geterror(err));
//         nlmsg_free(msg);
//         nl_cb_put(cb);
//         return;
//     }

//     char *str = malloc(BUFFER_SIZE);

//     err = read_string_from_sysfs(PATH_PARALLEL_GENL_MES, str, BUFFER_SIZE);
//     if (err) {
//         fprintf(stderr, "Failed to read from sysfs: %s\n", strerror(err));
//         free(str);
//         goto error;
//     }

//     EXPECT_STREQ(str, cb_data.message);
//     // if (strcmp(str, cb_data.message) == 0)
//     //     printf("[OK]\n");
//     // else {
//     //     free(str);
//     //     goto error;
//     // }

//     free(str);
//     nlmsg_free(msg);
//     nl_cb_put(cb);
//     nl_socket_free(nl_sock);
//     return;
//     error:
//         nlmsg_free(msg);
//         nl_cb_put(cb);
//         nl_socket_free(nl_sock);
//         return;
// }


TEST (connect_sock) 
{   
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    int family_id;
    struct nl_sock *sock;
    int err;

    printf("Running Test: using system calls to operate with Netlink socket...\n");

    sock = socket_alloc_and_conn();
    if (!sock) {
        return;
    }

    family_id = genl_ctrl_resolve(sock, MY_GENL_FAMILY_NAME);
    if (family_id < 0) {
        fprintf(stderr, "Failed to resolve family id for GENL_TEST: %d\n", family_id);
        nl_socket_free(sock);
        err = family_id;
        return;
    }

    nl_socket_free(sock);

    // Create Netlink socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (sock_fd < 0) {
        perror("socket()");
        err = sock_fd;
        return;
    }

    // Fill src_addr (for bind())
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    // Bind
    err = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if (err < 0) {
        perror("bind()");
        close(sock_fd);
        return;
    }

    // Fill dest_addr
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    // Call connect()
    err = connect(sock_fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0) {
        perror("connect()");
        close(sock_fd);
        return;
    }

    close(sock_fd);
    return;
}

TEST (netfilter_unbind_grp)
{
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    int family_id;
    struct nl_sock *sock;
    int err;
    int group_3, group_4;

    printf("Running Test: trying to unbind groups from releasing socket...\n");
    // NETLINK_NETFILTER in netlink_kernel_cfg has .unbind therefore this protocol was chosen to test calling unbind function

    // Only root can NETLINK_ADD_MEMBERSHIP and NETLINK_DROP_MEMBERSHIP
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}

    // Create Netlink socket
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    ASSERT_GE(sock_fd, 0);

    // Fill src_addr (for bind())
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    group_3 = NFNLGRP_NFTABLES;
    group_4 = NFNLGRP_NFTRACE;

    err = setsockopt(sock_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group_3, sizeof(group_3));
    EXPECT_EQ(err, 0);

    err = setsockopt(sock_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group_4, sizeof(group_4));
    EXPECT_EQ(err, 0);

    err = setsockopt(sock_fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, &group_3, sizeof(group_3));
    EXPECT_EQ(err, 0);

    err = setsockopt(sock_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group_3, sizeof(group_3));
    EXPECT_EQ(err, 0);

    // Bind
    err = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
    if (err < 0) {
        perror("bind()");
        close(sock_fd);
        return;
    }

    // Fill dest_addr
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;

    // Call connect()
    err = connect(sock_fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0) {
        perror("connect()");
        close(sock_fd);
        return;
    }

    close(sock_fd);
}

#define ITERATIONS 5000

void socket_worker(int iterations) {
    srand(time(NULL) ^ getpid());
    
    for (int i = 0; i < iterations; i++) {
        int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
        if (fd < 0) {
            perror("socket");
            continue;
        }

        struct sockaddr_nl addr = {
            .nl_family = AF_NETLINK,
            .nl_pid = getpid(),
            .nl_groups = 0,
        };

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(fd);
            continue;
        }

        // Short random delay
        struct timespec ts = {
            .tv_sec = 0,
            .tv_nsec = rand() % 1000
        };
        nanosleep(&ts, NULL);

        close(fd);
    }
}

TEST (netlink_grab_table_check_wait)
{
    printf("Running Test: making one process waiting a grab for a netlink table...\n");

    pid_t p1 = fork();
    if (p1 == 0) {
        socket_worker(ITERATIONS);
        exit(0);
    }

    pid_t p2 = fork();
    if (p2 == 0) {
        socket_worker(ITERATIONS);
        exit(0);
    }

    waitpid(p1, NULL, 0);
    waitpid(p2, NULL, 0);

    return;
}

TEST (capture_end) 
{
    printf("Running Test: stopping Netlink traffic capture...\n");

    // Only root can monitor Netlink trafic
	if (geteuid()) {
		SKIP(return, "test requires root");
		return;
	}
    
    char command[256];
    int result;

    sleep(2);
    
    // Stopping tcpdump
    snprintf(command, sizeof(command), "pkill tcpdump");
    result = system(command);
    if (result == -1) {
        perror("system");
        return;
    }

    // Resetting nlmon
    snprintf(command, sizeof(command), "ip link set nlmon0 down");
    result = system(command);
    if (result == -1) {
        perror("system");
        return;
    }

    // Deleting nlmon
    snprintf(command, sizeof(command), "ip link delete nlmon0 type nlmon");
    result = system(command);
    if (result == -1) {
        perror("system");
        return;
    }

    printf("The capturing is over\n");
}

TEST_HARNESS_MAIN