#include <unistd.h>

#include "config_component.h"
#include "cptest.h"
#include "environment.h"
#include "mock/mock_mainloop.h"
#include "shell_cmd.h"
#include "time_proxy.h"

using namespace std;
using namespace testing;

class ShellCmdTest : public Test
{
public:
    ShellCmdTest()
    {
        env.preload();
        ON_CALL(mainloop, yield(A<bool>())).WillByDefault(Invoke([](bool idle) {
            if (idle) usleep(1000);
        }));
        shell_cmd.init();
    }

    ~ShellCmdTest()
    {
        shell_cmd.fini();
    }

    NiceMock<MockMainLoop> mainloop;
    ::Environment env;
    ConfigComponent config;
    TimeProxyComponent time_get;
    ShellCmd shell_cmd;
    I_ShellCmd *shell = Singleton::Consume<I_ShellCmd>::from(shell_cmd);
};

TEST_F(ShellCmdTest, preservesPartialLineAcrossWouldBlock)
{
    // On musl, fgets can consume part1 and return NULL on EAGAIN, losing those bytes.
    for (bool do_yield : {false, true}) {
        SCOPED_TRACE(do_yield);
        auto output = shell->getExecOutput("printf part1; sleep 0.3; printf part2", 5000, do_yield);
        ASSERT_TRUE(output.ok());
        EXPECT_EQ(*output, "part1part2");
    }
}

TEST_F(ShellCmdTest, preservesOutputLargerThanPipeBuffer)
{
    // Two MiB exceeds the usual Linux pipe capacity. There are no line boundaries.
    auto output = shell->getExecOutput(
        "printf start; head -c 2097152 /dev/zero | tr '\\000' x; sleep 0.3; printf end",
        10000,
        true
    );
    ASSERT_TRUE(output.ok());
    EXPECT_EQ(*output, "start" + string(2097152, 'x') + "end");
}

TEST_F(ShellCmdTest, preservesEmbeddedNullBytes)
{
    // This also fails with the old result += buffer on libc implementations that keep partial lines.
    auto output = shell->getExecOutput("printf 'part1\\000part2\\n'", 5000);
    ASSERT_TRUE(output.ok());
    EXPECT_EQ(*output, string("part1\0part2\n", 12));
}

TEST_F(ShellCmdTest, preservesOutputAndNonzeroExitCode)
{
    auto output = shell->getExecOutputAndCode("printf output; exit 7", 5000);
    ASSERT_TRUE(output.ok());
    EXPECT_EQ(output->first, "output");
    EXPECT_EQ(output->second, 7);
    auto code = shell->getExecReturnCode("exit 9", 5000);
    ASSERT_TRUE(code.ok());
    EXPECT_EQ(*code, 9);
}

TEST_F(ShellCmdTest, acceptsEmptyOutputAtEof)
{
    auto output = shell->getExecOutputAndCode("exit 0", 5000);
    ASSERT_TRUE(output.ok());
    EXPECT_TRUE(output->first.empty());
    EXPECT_EQ(output->second, 0);
}

TEST_F(ShellCmdTest, returnsTimeoutErrorWhileWaitingForMoreOutput)
{
    const string command = "printf part1; sleep 0.3; printf part2";
    auto output = shell->getExecOutput(command, 50, true);
    ASSERT_FALSE(output.ok());
    EXPECT_EQ(output.getErr(), "Reached timeout while executing shell command: " + command);
}
