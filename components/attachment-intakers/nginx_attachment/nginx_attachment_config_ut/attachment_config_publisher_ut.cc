#include "gtest/gtest.h"
#include "../attachment_config_publisher.h"

#include <cstdlib>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;
using namespace testing;

namespace
{

// No attachment services are needed to exercise the production publication gate.
struct TestConfig
{
    bool operator==(const TestConfig &other) const { return content == other.content && elements == other.elements; }
    unsigned int getNumOfNginxElements() const { return elements; }

    string content;
    unsigned int elements;
};

class AttachmentConfigPublisherTest : public Test
{
protected:
    void
    SetUp() override
    {
        char directory_template[] = "/tmp/attachment_config_ut_XXXXXX";
        char *created = mkdtemp(directory_template);
        ASSERT_NE(nullptr, created);
        directory = created;
        parent = directory + "/settings";
        path = parent + "/attachment.json";
    }

    void
    TearDown() override
    {
        if (directory.empty()) return;
        unlink(path.c_str());
        rmdir(parent.c_str());
        EXPECT_EQ(0, rmdir(directory.c_str()));
    }

    string
    readSettings()
    {
        ifstream input(path);
        EXPECT_TRUE(input.is_open());
        return string(istreambuf_iterator<char>(input), istreambuf_iterator<char>());
    }

    bool
    publish(const TestConfig &candidate)
    {
        const TestConfig previous = committed;
        const unsigned int previous_elements = ipc_elements;
        const int previous_reconfs = reconfs;
        return publisher.publish(
            candidate,
            committed,
            ipc_elements,
            [&]()
            {
                ++writes;
                // The old state must remain visible throughout the real file write.
                EXPECT_TRUE(committed == previous);
                EXPECT_EQ(previous_elements, ipc_elements);
                EXPECT_EQ(previous_reconfs, reconfs);
                bool result = writeAttachmentSettings(path, candidate.content);
                EXPECT_TRUE(committed == previous);
                EXPECT_EQ(previous_elements, ipc_elements);
                EXPECT_EQ(previous_reconfs, reconfs);
                return result;
            },
            [&]()
            {
                ++reconfs;
                EXPECT_TRUE(committed == candidate);
                EXPECT_EQ(candidate.elements, ipc_elements);
                EXPECT_EQ(candidate.content, readSettings());
            }
        );
    }

    AttachmentConfigPublisher publisher;
    TestConfig committed = {"old settings", 8};
    unsigned int ipc_elements = 8;
    int writes = 0;
    int reconfs = 0;
    string directory;
    string parent;
    string path;
};

TEST_F(AttachmentConfigPublisherTest, IdenticalConfigRetriesAfterOpenFailure)
{
    const TestConfig candidate = {"{\"elements\":16}\n", 16};
    // A missing parent makes open fail even when the tests run as root.
    EXPECT_FALSE(publish(candidate));
    EXPECT_EQ(1, writes);
    EXPECT_EQ("old settings", committed.content);
    EXPECT_EQ(8u, committed.elements);
    EXPECT_EQ(8u, ipc_elements);
    EXPECT_EQ(0, reconfs);
    EXPECT_NE(0, access(path.c_str(), F_OK));

    ASSERT_EQ(0, mkdir(parent.c_str(), 0700));
    ASSERT_TRUE(publish(candidate));
    EXPECT_EQ(2, writes);
    EXPECT_EQ(1, reconfs);
    EXPECT_EQ(candidate.content, readSettings());
    EXPECT_TRUE(committed == candidate);
    EXPECT_EQ(16u, ipc_elements);

    // An unchanged, published config still sends RECONF without writing again.
    EXPECT_TRUE(publish(candidate));
    EXPECT_EQ(2, writes);
    EXPECT_EQ(2, reconfs);
}

TEST_F(AttachmentConfigPublisherTest, EqualConfigMustBePublishedBeforeNotification)
{
    const TestConfig candidate = committed;
    EXPECT_FALSE(publish(candidate));
    EXPECT_EQ(1, writes);
    EXPECT_EQ(0, reconfs);
    ASSERT_EQ(0, mkdir(parent.c_str(), 0700));
    EXPECT_TRUE(publish(candidate));
    EXPECT_EQ(2, writes);
    EXPECT_EQ(1, reconfs);
}

TEST_F(AttachmentConfigPublisherTest, FailedReplacementKeepsPreviousCommitAndRetries)
{
    ASSERT_EQ(0, mkdir(parent.c_str(), 0700));
    const TestConfig previous = committed;
    ASSERT_TRUE(publish(previous));
    ASSERT_EQ(0, unlink(path.c_str()));
    ASSERT_EQ(0, rmdir(parent.c_str()));

    const TestConfig candidate = {"replacement settings", 32};
    EXPECT_FALSE(publish(candidate));
    EXPECT_TRUE(committed == previous);
    EXPECT_EQ(8u, ipc_elements);
    EXPECT_EQ(1, reconfs);
    ASSERT_EQ(0, mkdir(parent.c_str(), 0700));
    EXPECT_TRUE(publish(candidate));
    EXPECT_EQ(3, writes);
    EXPECT_EQ(2, reconfs);
    EXPECT_TRUE(committed == candidate);
    EXPECT_EQ(32u, ipc_elements);
}

TEST_F(AttachmentConfigPublisherTest, RevertingAfterFailedReplacementRewritesMissingFile)
{
    ASSERT_EQ(0, mkdir(parent.c_str(), 0700));
    const TestConfig previous = committed;
    ASSERT_TRUE(publish(previous));
    ASSERT_EQ(0, unlink(path.c_str()));
    ASSERT_EQ(0, rmdir(parent.c_str()));
    EXPECT_FALSE(publish(TestConfig{"replacement settings", 32}));
    EXPECT_EQ(1, reconfs);

    ASSERT_EQ(0, mkdir(parent.c_str(), 0700));
    EXPECT_TRUE(publish(previous));
    EXPECT_EQ(3, writes);
    EXPECT_EQ(2, reconfs);
    EXPECT_EQ(previous.content, readSettings());
}

TEST_F(AttachmentConfigPublisherTest, BufferedWriteFailureDoesNotCommitOrNotify)
{
    // /dev/full opens successfully but rejects writes, including a buffered flush at close.
    ofstream full_device("/dev/full");
    ASSERT_TRUE(full_device.is_open());
    full_device.close();
    ASSERT_FALSE(full_device.fail());
    const TestConfig previous = committed;
    const TestConfig candidate = {"small settings", 16};
    EXPECT_FALSE(publisher.publish(candidate, committed, ipc_elements,
        [&]() { return writeAttachmentSettings("/dev/full", candidate.content); },
        [&]() { ++reconfs; }
    ));
    EXPECT_TRUE(committed == previous);
    EXPECT_EQ(8u, ipc_elements);
    EXPECT_EQ(0, reconfs);
    ASSERT_EQ(0, mkdir(parent.c_str(), 0700));
    EXPECT_TRUE(publish(candidate));
    EXPECT_EQ(1, writes);
    EXPECT_EQ(1, reconfs);
}

TEST_F(AttachmentConfigPublisherTest, LargeWriteFailureDoesNotCommitOrNotify)
{
    ofstream full_device("/dev/full");
    ASSERT_TRUE(full_device.is_open());
    full_device.close();
    ASSERT_FALSE(full_device.fail());
    const TestConfig previous = committed;
    const TestConfig candidate = {string(1024 * 1024, 'x'), 64};
    EXPECT_FALSE(publisher.publish(candidate, committed, ipc_elements,
        [&]() { return writeAttachmentSettings("/dev/full", candidate.content); },
        [&]() { ++reconfs; }
    ));
    EXPECT_TRUE(committed == previous);
    EXPECT_EQ(8u, ipc_elements);
    EXPECT_EQ(0, reconfs);
}

} // namespace
