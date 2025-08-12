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