#include "../rate_limit_redis.h"

#include <vector>

#include "gtest/gtest.h"

namespace
{

class RateLimitTimeoutTest : public testing::Test
{
protected:
    void SetUp() override { active = this; }
    void TearDown() override { active = nullptr; }

    static int
    setTimeout(redisContext *context, const timeval timeout)
    {
        active->configured.push_back(context);
        EXPECT_TRUE(active->freed.empty());
        EXPECT_EQ(active->timeout.tv_sec, timeout.tv_sec);
        EXPECT_EQ(active->timeout.tv_usec, timeout.tv_usec);
        return active->result;
    }

    static void
    freeContext(redisContext *context)
    {
        ASSERT_FALSE(active->configured.empty());
        EXPECT_EQ(active->configured.back(), context);
        active->freed.push_back(context);
    }

    static void *
    command(redisContext *, const char *, ...)
    {
        ADD_FAILURE() << "No command may run on a dropped connection";
        return nullptr;
    }

    static void freeReply(void *) { ADD_FAILURE() << "No reply should have been allocated"; }

    redisContext *
    configure(redisContext *context)
    {
        return setRateLimitRedisTimeout(context, timeout, setTimeout, freeContext);
    }

    static RateLimitTimeoutTest *active;
    const timeval timeout{0, 30000};
    int result = REDIS_OK;
    std::vector<redisContext *> configured;
    std::vector<redisContext *> freed;
};

RateLimitTimeoutTest *RateLimitTimeoutTest::active = nullptr;

TEST_F(RateLimitTimeoutTest, SetsTimeoutOnEveryNewConnection)
{
    redisContext first{};
    redisContext second{};
    EXPECT_EQ(&first, configure(&first));
    EXPECT_EQ(&second, configure(&second));
    ASSERT_EQ(2u, configured.size());
    EXPECT_EQ(&first, configured[0]);
    EXPECT_EQ(&second, configured[1]);
    EXPECT_TRUE(freed.empty());
}

TEST_F(RateLimitTimeoutTest, TimeoutSetupFailureDropsConnectionAndKeepsFailOpen)
{
    result = REDIS_ERR;
    redisContext context{};
    auto connection = configure(&context);
    EXPECT_EQ(nullptr, connection);
    ASSERT_EQ(1u, configured.size());
    ASSERT_EQ(1u, freed.size());
    EXPECT_EQ(&context, freed[0]);

    RateLimitRedis client(command, freeReply);
    EXPECT_FALSE(client.loadScript(connection, "return false"));
    EXPECT_EQ(RateLimitVerdict::ACCEPT, client.decide(connection, "key", 1, 1, []() {
        ADD_FAILURE() << "Must not reload a script on a dropped connection";
        return false;
    }));
    EXPECT_FALSE(client.isReady());
}

TEST_F(RateLimitTimeoutTest, MissingConnectionDoesNotSetTimeoutOrFree)
{
    EXPECT_EQ(nullptr, configure(nullptr));
    EXPECT_TRUE(configured.empty());
    EXPECT_TRUE(freed.empty());
}

} // namespace
