#include "cptest.h"
#include "policy_maker_utils.h"
#include "scope_exit.h"

#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <iterator>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace std;
using namespace testing;

namespace
{

class PolicyFileTest : public Test
{
protected:
    void
    SetUp() override
    {
        char directory_template[] = "/tmp/policy_file_ut_XXXXXX";
        char *created = mkdtemp(directory_template);
        ASSERT_NE(nullptr, created);
        directory = created;
        target = directory + "/policy.json";
    }

    void
    TearDown() override
    {
        if (directory.empty()) return;
        unlink(target.c_str());
        // A failed commit must also remove its temporary file.
        expectNoTemporaryFiles();
        EXPECT_EQ(0, rmdir(directory.c_str()));
    }

    void
    expectNoTemporaryFiles()
    {
        DIR *dir = opendir(directory.c_str());
        ASSERT_NE(nullptr, dir);
        auto cleanup = make_scope_exit([&]() { closedir(dir); });
        while (auto entry = readdir(dir)) {
            string name = entry->d_name;
            EXPECT_TRUE(name == "." || name == ".." || name == "policy.json") << name;
        }
    }

    string
    readPolicy()
    {
        ifstream input(target);
        EXPECT_TRUE(input.is_open());
        return string(istreambuf_iterator<char>(input), istreambuf_iterator<char>());
    }

    string
    generate(const string &path, const string &version = "test-version")
    {
        // Empty policy maps reach the real serializer/writer without shell commands or mocks.
        return generator.proccesMultipleAppsecPolicies<V1beta2AppsecLinuxPolicy, NewParsedRule>(
            {}, version, path
        );
    }

    void
    checkFailedWritePreservesOldPolicy(const string &version)
    {
        {
            ofstream old_policy(target);
            old_policy << "previous policy\n";
            old_policy.close();
            ASSERT_TRUE(old_policy.good());
        }
        const string previous = readPolicy();
        string result;
        {
            struct rlimit previous_limit;
            ASSERT_EQ(0, getrlimit(RLIMIT_FSIZE, &previous_limit));
            struct sigaction previous_action;
            struct sigaction ignore_action = {};
            ignore_action.sa_handler = SIG_IGN;
            sigemptyset(&ignore_action.sa_mask);
            ASSERT_EQ(0, sigaction(SIGXFSZ, &ignore_action, &previous_action));
            auto restore_signal = make_scope_exit([&]() {
                EXPECT_EQ(0, sigaction(SIGXFSZ, &previous_action, nullptr));
            });
            struct rlimit limited = previous_limit;
            limited.rlim_cur = 0;
            ASSERT_EQ(0, setrlimit(RLIMIT_FSIZE, &limited));
            auto restore_limit = make_scope_exit([&]() { EXPECT_EQ(0, setrlimit(RLIMIT_FSIZE, &previous_limit)); });
            // Deterministically fail actual file I/O, including when tests run as root.
            result = generate(target, version);
        }
        EXPECT_TRUE(result.empty());
        EXPECT_EQ(previous, readPolicy());
        expectNoTemporaryFiles();
        // Failure must not poison subsequent use of the same generator.
        string retried = generate(target);
        ASSERT_FALSE(retried.empty());
        EXPECT_EQ(retried, readPolicy());
    }

    PolicyMakerUtils generator;
    string directory;
    string target;
};

TEST_F(PolicyFileTest, RejectsDirectoryTarget)
{
    ASSERT_EQ(0, mkdir(target.c_str(), 0700));
    EXPECT_TRUE(generate(target).empty());
    struct stat info;
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_TRUE(S_ISDIR(info.st_mode));
    expectNoTemporaryFiles();
    EXPECT_EQ(0, rmdir(target.c_str()));
}

TEST_F(PolicyFileTest, RejectsMissingParentDirectory)
{
    EXPECT_TRUE(generate(directory + "/missing/policy.json").empty());
    EXPECT_NE(0, access((directory + "/missing").c_str(), F_OK));
    expectNoTemporaryFiles();
}

TEST_F(PolicyFileTest, WritesCompletePolicyAndReplacesPreviousFile)
{
    string first = generate(target, "first-version");
    ASSERT_FALSE(first.empty());
    EXPECT_EQ(first, readPolicy());
    ASSERT_EQ(0, chmod(target.c_str(), 0640));
    string second = generate(target, "second-version");
    ASSERT_FALSE(second.empty());
    EXPECT_NE(first, second);
    EXPECT_EQ(second, readPolicy());
    struct stat info;
    ASSERT_EQ(0, stat(target.c_str(), &info));
    EXPECT_EQ(0640, info.st_mode & 0777);
    expectNoTemporaryFiles();
}

TEST_F(PolicyFileTest, PreservesOldFileWhenBufferedCloseFails)
{
    // The small policy fits in stdio's buffer; fclose must detect the failed flush.
    checkFailedWritePreservesOldPolicy("small-policy");
}

TEST_F(PolicyFileTest, PreservesOldFileWhenWriteFails)
{
    // Exceed stdio's buffer so fwrite itself encounters the file size limit.
    checkFailedWritePreservesOldPolicy(string(1024 * 1024, 'x'));
}

} // namespace
