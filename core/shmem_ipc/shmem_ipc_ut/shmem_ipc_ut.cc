#include "shmem_ipc.h"

#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../shared_ring_queue.h"
#include "../shmem_ipc_permissions.h"
#include "debug.h"
#include "cptest.h"
#include "time_proxy.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_environment.h"

using namespace std;
using namespace testing;

const static string shmem_name = "shmem_ut";
const static uint16_t num_of_shmem_elem = 11;
const static size_t max_one_way_queue_name_length = 64;
const uint16_t max_num_of_data_segments = sizeof(DataSegment)/sizeof(uint16_t);
uint32_t uid = getuid();
uint32_t gid = getgid();

USE_DEBUG_FLAG(D_SHMEM);

void
debugFunc(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...)
{
    if (!Debug::evalFlags(Debug::DebugLevel::INFO, D_SHMEM)) return;

    va_list args;
    va_start(args, fmt);
    size_t len = vsnprintf(NULL, 0, fmt, args);
    va_end(args);
    vector<char> message(len + 1);
    va_start(args, fmt);
    vsnprintf(&message[0], len + 1, fmt, args);
    va_end(args);

    Debug(
        file,
        func,
        line_num,
        is_error ? Debug::DebugLevel::WARNING : Debug::DebugLevel::TRACE,
        D_SHMEM
    ).getStreamAggr() << message.data();
}

class SharedIPCTest : public Test
{
public:
    SharedIPCTest()
    {
        Debug::setNewDefaultStdout(&capture_debug);
        Debug::setUnitTestFlag(D_SHMEM, Debug::DebugLevel::TRACE);
        owners_queue = initIpc(shmem_name.c_str(), uid, gid, 1, num_of_shmem_elem, debugFunc);
        users_queue = initIpc(shmem_name.c_str(), uid, gid, 0, num_of_shmem_elem, debugFunc);
    }

    ~SharedIPCTest()
    {
        if(owners_queue != nullptr) destroyIpc(owners_queue, 1);
        if(users_queue != nullptr) destroyIpc(users_queue, 0);
        owners_queue = nullptr;
        users_queue = nullptr;
        Debug::setNewDefaultStdout(&cout);
    }

    SharedMemoryIPC *owners_queue = nullptr;
    SharedMemoryIPC *users_queue = nullptr;
    stringstream capture_debug;
    TimeProxyComponent time_proxy;
    MockMainLoop mock_mainloop;
    MockEnvironment env;
};

TEST_F(SharedIPCTest, init_owner_queue)
{
    EXPECT_NE(owners_queue, nullptr);
    EXPECT_FALSE(isCorruptedShmem(owners_queue, 1));

    EXPECT_NE(users_queue, nullptr);
    EXPECT_FALSE(isCorruptedShmem(users_queue, 0));
}

TEST_F(SharedIPCTest, basic_write_read_pop_transaction)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    const string message = "my basic_write_read_pop_transaction test data";
    const string respond = "my basic_write_read_pop_transaction test data";

    const char *read_data = nullptr;
    uint16_t read_bytes = 0;

    EXPECT_EQ(sendData(owners_queue, message.size(), message.c_str()), 0);
    EXPECT_TRUE(isDataAvailable(users_queue));
    EXPECT_EQ(receiveData(users_queue, &read_bytes, &read_data), 0);
    EXPECT_EQ(string(read_data, read_bytes), message);
    EXPECT_EQ(popData(users_queue), 0);
    EXPECT_FALSE(isDataAvailable(users_queue));

    EXPECT_EQ(sendData(users_queue, respond.size(), respond.c_str()), 0);
    EXPECT_TRUE(isDataAvailable(owners_queue));
    EXPECT_EQ(receiveData(owners_queue, &read_bytes, &read_data), 0);
    EXPECT_EQ(string(read_data, read_bytes), respond);
    EXPECT_EQ(popData(owners_queue), 0);
    EXPECT_FALSE(isDataAvailable(owners_queue));
}

TEST_F(SharedIPCTest, memory_dump)
{
    const string message = "my basic_write_read_pop_transaction test data";
    sendData(owners_queue, message.size(), message.c_str());

    dumpIpcMemory(owners_queue);

    EXPECT_THAT(capture_debug.str(), HasSubstr("Ipc memory dump:"));
}

TEST_F(SharedIPCTest, ilegal_ipc)
{
    ASSERT_NE(owners_queue, nullptr);
    ASSERT_NE(users_queue, nullptr);

    destroyIpc(owners_queue, 1);
    destroyIpc(users_queue, 0);

    owners_queue = initIpc("i/am/a/bad/shmem/path", uid, gid, 1, num_of_shmem_elem, debugFunc);
    users_queue = initIpc(shmem_name.c_str(), uid, gid, 0, max_num_of_data_segments + 1, debugFunc);

    EXPECT_EQ(owners_queue, nullptr);
    EXPECT_EQ(users_queue, nullptr);

    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Failed to open shared memory for '__cp_nano_rx_shared_memory_i/am/a/bad/shmem/path__'")
    );

    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Cannot create data segment with 2049 elements (max number of elements is 2048)")
    );
}

TEST_F(SharedIPCTest, multiple_write_read_pop_transactions)
{
    vector<string> data_to_write = {
        "my basic_write_read_pop_transaction test data0",
        "my basic_write_read_pop_transaction test data1",
        "my basic_write_read_pop_transaction test data2",
        "my basic_write_read_pop_transaction test data3",
        "my basic_write_read_pop_transaction test data4",
        "my basic_write_read_pop_transaction test data5",
        "my basic_write_read_pop_transaction test data6",
        "my basic_write_read_pop_transaction test data7",
        "my basic_write_read_pop_transaction test data8",
        "my basic_write_read_pop_transaction test data9"
    };
    for (const string &data : data_to_write) {
        EXPECT_EQ(sendData(users_queue, data.size(), data.c_str()), 0);
    }
    const char *read_buff = nullptr;
    uint16_t read_bytes = 0;
    vector<string> read_data;
    while (isDataAvailable(owners_queue)) {
        ASSERT_LT(read_data.size(), data_to_write.size());
        EXPECT_EQ(receiveData(owners_queue, &read_bytes, &read_buff), 0);
        read_data.push_back(string(read_buff, read_bytes));
        EXPECT_EQ(sendData(owners_queue, read_bytes, read_buff), 0);
        EXPECT_EQ(popData(owners_queue), 0);
    }

    EXPECT_EQ(read_data, data_to_write);
    for (uint i = 0; i < read_data.size(); i++) {
        EXPECT_EQ(receiveData(users_queue, &read_bytes, &read_buff), 0);
        EXPECT_EQ(string(read_buff, read_bytes), read_data[i]);
        EXPECT_EQ(popData(users_queue), 0);
    }
}

TEST_F(SharedIPCTest, reset_shmem)
{
    string data_to_write = "my basic_write_read_pop_transaction test data";

    int count = 0;
    while (sendData(users_queue, data_to_write.size(), data_to_write.c_str()) == 0) {
        count++;
        ASSERT_NE(count, num_of_shmem_elem);
    }

    EXPECT_NE(sendData(users_queue, data_to_write.size(), data_to_write.c_str()), 0);
    EXPECT_TRUE(isDataAvailable(owners_queue));
    resetIpc(owners_queue, num_of_shmem_elem);
    EXPECT_FALSE(isDataAvailable(owners_queue));
    EXPECT_EQ(sendData(users_queue, data_to_write.size(), data_to_write.c_str()), 0);
}

TEST_F(SharedIPCTest, write_read_pop_mulltiple_elements_transaction)
{
    int my_first_int = 1;
    int my_second_int = 20;
    int my_third_int = 300;
    int my_fourth_int = 4000;
    int my_fifth_int = 50000;

    char my_first_char = '1';
    char my_second_char = '2';
    char my_third_char = '3';
    char my_fourth_char = '4';
    char my_fifth_char = '5';

    vector<const char *> data1 = {
        reinterpret_cast<const char *>(&my_first_int),
        reinterpret_cast<const char *>(&my_second_int),
        reinterpret_cast<const char *>(&my_third_int),
        reinterpret_cast<const char *>(&my_fourth_int),
        reinterpret_cast<const char *>(&my_fifth_int)
    };
    vector<uint16_t> sizes1 = { sizeof(int), sizeof(int), sizeof(int), sizeof(int), sizeof(int) };

    vector<const char *> data2 = {
        const_cast<const char *>(&my_first_char),
        const_cast<const char *>(&my_second_char),
        const_cast<const char *>(&my_third_char),
        const_cast<const char *>(&my_fourth_char),
        const_cast<const char *>(&my_fifth_char)
    };
    vector<uint16_t> sizes2 = { sizeof(char), sizeof(char), sizeof(char), sizeof(char), sizeof(char) };

    const char *read_data = nullptr;
    uint16_t read_bytes = 0;

    EXPECT_EQ(sendChunkedData(owners_queue, sizes1.data(), data1.data(), data1.size()), 0);
    EXPECT_TRUE(isDataAvailable(users_queue));
    EXPECT_EQ(receiveData(users_queue, &read_bytes, &read_data), 0);
    vector<int> expected_data = { my_first_int, my_second_int, my_third_int, my_fourth_int, my_fifth_int };
    vector<int> received_data(
        reinterpret_cast<const int *>(read_data),
        reinterpret_cast<const int *>(read_data) + read_bytes/sizeof(int)
    );
    EXPECT_EQ(received_data, expected_data);
    EXPECT_EQ(popData(users_queue), 0);
    EXPECT_FALSE(isDataAvailable(users_queue));

    EXPECT_EQ(sendChunkedData(users_queue, sizes1.data(), data1.data(), data1.size()), 0);
    EXPECT_TRUE(isDataAvailable(owners_queue));
    EXPECT_EQ(receiveData(owners_queue, &read_bytes, &read_data), 0);
    vector<char> expected_char_data = { my_first_char, my_second_char, my_third_char, my_fourth_char, my_fifth_char };
    vector<char> received_char_data(read_data, read_data + read_bytes/sizeof(char));
    EXPECT_EQ(received_data, expected_data);
    EXPECT_EQ(popData(owners_queue), 0);
    EXPECT_FALSE(isDataAvailable(owners_queue));
}

TEST_F(SharedIPCTest, ensure_right_permissions)
{
    char queue_name_tx[max_one_way_queue_name_length];
    char queue_name_rx[max_one_way_queue_name_length];
    snprintf(queue_name_tx, sizeof(queue_name_tx) - 1, "/dev/shm/__cp_nano_tx_shared_memory_%s__", shmem_name.c_str());
    snprintf(queue_name_rx, sizeof(queue_name_rx) - 1, "/dev/shm/__cp_nano_rx_shared_memory_%s__", shmem_name.c_str());
    for (char *queue_name : {queue_name_tx, queue_name_rx}) {
        struct stat info = {};
        ASSERT_EQ(stat(queue_name, &info), 0);
        EXPECT_EQ(info.st_uid, uid);
        EXPECT_EQ(info.st_gid, gid);
        // This fixture passes the owner's IDs: root IDs and unprivileged owners use compatibility mode.
        EXPECT_EQ(info.st_mode & 0777, static_cast<mode_t>(0666));
    }
}

class SharedIPCPermissionsTest : public Test
{
public:
    SharedIPCPermissionsTest()
    {
        const char *value = getenv("CP_NANO_IPC_COMPAT_PERMISSIONS");
        had_compat_env = value != nullptr;
        if (had_compat_env) saved_compat_env = value;
        EXPECT_EQ(unsetenv("CP_NANO_IPC_COMPAT_PERMISSIONS"), 0);
        Debug::setNewDefaultStdout(&capture_debug);
        Debug::setUnitTestFlag(D_SHMEM, Debug::DebugLevel::TRACE);
    }

    ~SharedIPCPermissionsTest()
    {
        if (owner != nullptr) destroyIpc(owner, 1);
        Debug::setNewDefaultStdout(&cout);
        if (had_compat_env) {
            EXPECT_EQ(setenv("CP_NANO_IPC_COMPAT_PERMISSIONS", saved_compat_env.c_str(), 1), 0);
        } else {
            EXPECT_EQ(unsetenv("CP_NANO_IPC_COMPAT_PERMISSIONS"), 0);
        }
    }

    void expectPermissions(uid_t expected_uid, gid_t expected_gid, mode_t expected_mode)
    {
        for (const char *direction : {"rx", "tx"}) {
            const string path = "/dev/shm/__cp_nano_" + string(direction) + "_shared_memory_" + name + "__";
            struct stat info = {};
            ASSERT_EQ(stat(path.c_str(), &info), 0);
            EXPECT_EQ(info.st_uid, expected_uid);
            EXPECT_EQ(info.st_gid, expected_gid);
            EXPECT_EQ(info.st_mode & 0777, expected_mode);
            int fd = open(path.c_str(), O_RDWR);
            ASSERT_NE(fd, -1);
            EXPECT_EQ(close(fd), 0);
        }
    }

    const string name = "d13_ut_" + to_string(getpid());
    SharedMemoryIPC *owner = nullptr;
    stringstream capture_debug;
    bool had_compat_env = false;
    string saved_compat_env;
};

TEST_F(SharedIPCPermissionsTest, attachment_ownership_and_mode)
{
    // Exercise the deployment's root -> kong ownership change; adapt for non-root test runners.
    bool can_restrict = geteuid() == 0;
    for (const char *path : {"/proc/self/uid_map", "/proc/self/gid_map"}) {
        ifstream file(path);
        const string mapping((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        can_restrict = can_restrict && shmemIpcIsIdentityMap(mapping.c_str());
    }
    const uid_t attachment_uid = geteuid() == 0 ? 1001 : geteuid();
    const gid_t attachment_gid = geteuid() == 0 ? 1001 : getegid();
    owner = initIpc(name.c_str(), attachment_uid, attachment_gid, 1, num_of_shmem_elem, debugFunc);
    ASSERT_NE(owner, nullptr);
    expectPermissions(
        can_restrict ? attachment_uid : geteuid(),
        can_restrict ? attachment_gid : getegid(),
        can_restrict ? 0660 : 0666
    );
    if (!can_restrict) EXPECT_THAT(capture_debug.str(), HasSubstr("keeping mode 0666"));
}

TEST(SharedIPCIdentityMap, accepts_full_identity_maps)
{
    const char *maps[] = {
        "0 0 4294967295\n",
        "         0          0 4294967295\n",
        "\t0\t0\t4294967296 \n",
        "0 0 65536\n65536 65536 4294901759\n",
        "0 0 4294967295"
    };
    for (const char *mapping : maps) EXPECT_TRUE(shmemIpcIsIdentityMap(mapping)) << mapping;
}

TEST(SharedIPCIdentityMap, rejects_shifted_partial_and_malformed_maps)
{
    const char *maps[] = {
        "", " \n", "0 100000 65536\n", "1001 101001 1\n", "0 0 1\n", "1 1 4294967295\n",
        "0 0 0\n", "0 0 4294967297\n", "0 0 184467440737095516160\n", "0 0 -1\n",
        "0 0\n4294967295\n", "0 0 4294967295 extra\n", "0 0 4294967295\ninvalid\n",
        "0 0 100\n101 101 4294967194\n", "0 0 100\n99 99 4294967196\n",
        "0 0 100\n100 101 4294967195\n", "0 0 4294967295\n4294967296 4294967296 1\n"
    };
    EXPECT_FALSE(shmemIpcIsIdentityMap(nullptr));
    for (const char *mapping : maps) EXPECT_FALSE(shmemIpcIsIdentityMap(mapping)) << mapping;
}

TEST_F(SharedIPCPermissionsTest, compat_override_requires_exactly_one)
{
    EXPECT_FALSE(shmemIpcCompatPermissionsEnabled());
    for (const char *value : {"", "0", "true", "01", "1 ", " 1", "2"}) {
        ASSERT_EQ(setenv("CP_NANO_IPC_COMPAT_PERMISSIONS", value, 1), 0);
        EXPECT_FALSE(shmemIpcCompatPermissionsEnabled()) << value;
    }
    ASSERT_EQ(setenv("CP_NANO_IPC_COMPAT_PERMISSIONS", "1", 1), 0);
    EXPECT_TRUE(shmemIpcCompatPermissionsEnabled());
}

TEST_F(SharedIPCPermissionsTest, compat_override_keeps_legacy_ownership_and_mode)
{
    ASSERT_EQ(setenv("CP_NANO_IPC_COMPAT_PERMISSIONS", "1", 1), 0);
    owner = initIpc(name.c_str(), 1001, 1001, 1, num_of_shmem_elem, debugFunc);
    ASSERT_NE(owner, nullptr);
    expectPermissions(geteuid(), getegid(), 0666);
    EXPECT_THAT(capture_debug.str(), HasSubstr("CP_NANO_IPC_COMPAT_PERMISSIONS=1"));
    EXPECT_THAT(capture_debug.str(), HasSubstr("keeping mode 0666"));
}

TEST_F(SharedIPCPermissionsTest, unusable_attachment_ids_keep_legacy_access)
{
    const uint32_t invalid_ids[][2] = {{0, 1001}, {1001, 0}, {UINT32_MAX, 1001}, {1001, UINT32_MAX}};
    for (const auto &ids : invalid_ids) {
        capture_debug.str("");
        owner = initIpc(name.c_str(), ids[0], ids[1], 1, num_of_shmem_elem, debugFunc);
        ASSERT_NE(owner, nullptr);
        expectPermissions(geteuid(), getegid(), 0666);
        EXPECT_THAT(capture_debug.str(), HasSubstr("keeping mode 0666"));
        destroyIpc(owner, 1);
        owner = nullptr;
    }
}

TEST(SharedIPCPeerCredentials, reads_socketpair_credentials_without_privileges)
{
    int sockets[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    const bool usable_ids = getuid() != 65534 && getgid() != 65534;
    for (int fd : sockets) {
        ShmemIpcPeerCredentials peer = {UINT32_MAX, UINT32_MAX};
        EXPECT_EQ(shmemIpcGetPeerCredentials(fd, &peer), usable_ids ? 1 : 0);
        EXPECT_EQ(peer.user_id, usable_ids ? static_cast<uint32_t>(getuid()) : UINT32_MAX);
        EXPECT_EQ(peer.group_id, usable_ids ? static_cast<uint32_t>(getgid()) : UINT32_MAX);
    }
    EXPECT_EQ(close(sockets[0]), 0);
    EXPECT_EQ(close(sockets[1]), 0);
}

TEST(SharedIPCPeerCredentials, failure_clears_stale_credentials)
{
    ShmemIpcPeerCredentials peer = {1001, 1001};
    EXPECT_FALSE(shmemIpcGetPeerCredentials(-1, &peer));
    EXPECT_EQ(peer.user_id, UINT32_MAX);
    EXPECT_EQ(peer.group_id, UINT32_MAX);
    int fd = open("/dev/null", O_RDONLY);
    ASSERT_NE(fd, -1);
    peer = {1001, 1001};
    EXPECT_FALSE(shmemIpcGetPeerCredentials(fd, &peer));
    EXPECT_EQ(peer.user_id, UINT32_MAX);
    EXPECT_EQ(peer.group_id, UINT32_MAX);
    EXPECT_EQ(close(fd), 0);
    EXPECT_FALSE(shmemIpcGetPeerCredentials(-1, nullptr));
}

TEST_F(SharedIPCPermissionsTest, failed_peer_lookup_never_uses_message_ids)
{
    ShmemIpcPeerCredentials peer;
    ASSERT_FALSE(shmemIpcGetPeerCredentials(-1, &peer));
    owner = initIpcWithPeerCredentials(name.c_str(), 1001, 1001, 1, num_of_shmem_elem, debugFunc, &peer);
    ASSERT_NE(owner, nullptr);
    expectPermissions(geteuid(), getegid(), 0666);
    EXPECT_THAT(capture_debug.str(), HasSubstr("SO_PEERCRED unavailable or peer UID/GID unmapped/invalid"));
    EXPECT_THAT(capture_debug.str(), HasSubstr("keeping mode 0666"));
}

TEST_F(SharedIPCPermissionsTest, overflow_or_invalid_peer_ids_keep_legacy_access)
{
    const ShmemIpcPeerCredentials invalid_peers[] = {
        {65534, 1001}, {1001, 65534}, {UINT32_MAX, 1001}, {1001, UINT32_MAX}
    };
    for (const auto &peer : invalid_peers) {
        capture_debug.str("");
        owner = initIpcWithPeerCredentials(name.c_str(), 1001, 1001, 1, num_of_shmem_elem, debugFunc, &peer);
        ASSERT_NE(owner, nullptr);
        expectPermissions(geteuid(), getegid(), 0666);
        EXPECT_THAT(capture_debug.str(), HasSubstr("SO_PEERCRED unavailable or peer UID/GID unmapped/invalid"));
        EXPECT_THAT(capture_debug.str(), HasSubstr("keeping mode 0666"));
        destroyIpc(owner, 1);
        owner = nullptr;
    }
}

TEST_F(SharedIPCPermissionsTest, trusted_peer_ids_override_invalid_message_ids)
{
    int sockets[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    ShmemIpcPeerCredentials peer;
    int have_peer = shmemIpcGetPeerCredentials(sockets[0], &peer);
    EXPECT_EQ(close(sockets[0]), 0);
    EXPECT_EQ(close(sockets[1]), 0);
    const bool usable_ids = getuid() != 65534 && getgid() != 65534;
    ASSERT_EQ(have_peer, usable_ids ? 1 : 0);
    owner = initIpcWithPeerCredentials(
        name.c_str(), UINT32_MAX, UINT32_MAX, 1, num_of_shmem_elem, debugFunc, &peer
    );
    ASSERT_NE(owner, nullptr);
    // The existing conservative policy keeps root IDs and non-root owners in compatibility mode.
    expectPermissions(geteuid(), getegid(), 0666);
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Queue name: " + name + ", user id: " + to_string(peer.user_id) +
            ", group id: " + to_string(peer.group_id))
    );
    if (usable_ids) {
        EXPECT_THAT(capture_debug.str(), Not(HasSubstr("SO_PEERCRED unavailable")));
    } else {
        EXPECT_THAT(capture_debug.str(), HasSubstr("SO_PEERCRED unavailable"));
    }
}

TEST_F(SharedIPCPermissionsTest, trusted_root_peer_ids_override_nonroot_message_ids)
{
    // Deterministic even without root: retaining the message IDs would select the wrong owner.
    const ShmemIpcPeerCredentials peer = {0, 0};
    owner = initIpcWithPeerCredentials(name.c_str(), 1001, 1001, 1, num_of_shmem_elem, debugFunc, &peer);
    ASSERT_NE(owner, nullptr);
    expectPermissions(geteuid(), getegid(), 0666);
    EXPECT_THAT(capture_debug.str(), HasSubstr("attachment uid=0 gid=0"));
    EXPECT_THAT(capture_debug.str(), Not(HasSubstr("IPC owner UID/GID maps")));
}

TEST_F(SharedIPCPermissionsTest, trusted_nonroot_peer_ids_set_queue_ownership)
{
    // Ownership transfer needs root and mapped destination IDs; rootless tests above still run.
    if (geteuid() != 0) return;
    for (const char *path : {"/proc/self/uid_map", "/proc/self/gid_map"}) {
        ifstream file(path);
        const string mapping((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        if (!shmemIpcIsIdentityMap(mapping.c_str())) return;
    }
    const ShmemIpcPeerCredentials peer = {1001, 1002};
    owner = initIpcWithPeerCredentials(name.c_str(), 2001, 2002, 1, num_of_shmem_elem, debugFunc, &peer);
    ASSERT_NE(owner, nullptr);
    expectPermissions(1001, 1002, 0660);
}

TEST_F(SharedIPCPermissionsTest, compat_override_applies_to_trusted_peer_ids)
{
    ASSERT_EQ(setenv("CP_NANO_IPC_COMPAT_PERMISSIONS", "1", 1), 0);
    const ShmemIpcPeerCredentials peer = {1001, 1001};
    owner = initIpcWithPeerCredentials(
        name.c_str(), UINT32_MAX, UINT32_MAX, 1, num_of_shmem_elem, debugFunc, &peer
    );
    ASSERT_NE(owner, nullptr);
    expectPermissions(geteuid(), getegid(), 0666);
    EXPECT_THAT(capture_debug.str(), HasSubstr("CP_NANO_IPC_COMPAT_PERMISSIONS=1"));
}

TEST_F(SharedIPCTest, get_main_segment_size)
{
    uint16_t segment_size = getSegmentEntrySize();
    EXPECT_EQ(segment_size, SHARED_MEMORY_SEGMENT_ENTRY_SIZE);
}
