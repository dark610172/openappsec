#include "../rate_limit_redis.h"

#include <cstdarg>
#include <cstring>
#include <deque>
#include <set>
#include <vector>

#include "gtest/gtest.h"

namespace
{

class RateLimitRedisTest : public testing::Test
{
protected:
    struct Response
    {
        int type;
        std::string text;
        bool missing;
        int context_error;
    };

    struct Call
    {
        std::string format;
        std::string script;
        std::string sha;
        std::string key;
        double limit = 0;
        int burst = 0;
    };

    void SetUp() override { active = this; }

    void
    TearDown() override
    {
        EXPECT_TRUE(responses.empty()) << "Expected Redis commands were not issued";
        EXPECT_EQ(allocated, freed);
        EXPECT_TRUE(live.empty()) << "Redis replies leaked";
        for (auto reply : live) {
            delete[] reply->str;
            delete reply;
        }
        active = nullptr;
    }

    static void *
    command(redisContext *context, const char *format, ...)
    {
        auto &fake = *active;
        EXPECT_EQ(&fake.context, context);
        // Every earlier command reply must be released before issuing another command.
        EXPECT_TRUE(fake.live.empty());
        Call call;
        call.format = format;
        va_list args;
        va_start(args, format);
        if (call.format == "SCRIPT LOAD %s") {
            call.script = va_arg(args, const char *);
        } else if (call.format == "EVALSHA %s 1 %s %f %d") {
            call.sha = va_arg(args, const char *);
            call.key = va_arg(args, const char *);
            call.limit = va_arg(args, double);
            call.burst = va_arg(args, int);
        } else {
            ADD_FAILURE() << "Unexpected Redis command: " << format;
        }
        va_end(args);
        fake.calls.push_back(call);
        if (fake.responses.empty()) {
            ADD_FAILURE() << "Redis command exceeded the expected retry budget";
            return nullptr;
        }
        const auto response = fake.responses.front();
        fake.responses.pop_front();
        context->err = response.context_error;
        if (response.missing) return nullptr;

        auto reply = new redisReply{};
        reply->type = response.type;
        reply->len = response.text.size();
        reply->str = new char[reply->len + 1];
        std::memcpy(reply->str, response.text.c_str(), reply->len + 1);
        fake.live.insert(reply);
        ++fake.allocated;
        return reply;
    }

    static void
    freeReply(void *object)
    {
        auto reply = static_cast<redisReply *>(object);
        if (active->live.erase(reply) != 1) {
            ADD_FAILURE() << "Reply freed twice or not owned by fake Redis";
            return;
        }
        ++active->freed;
        delete[] reply->str;
        delete reply;
    }

    void enqueue(int type, const std::string &text = "", int context_error = 0)
    {
        responses.push_back({type, text, false, context_error});
    }

    void
    initialize()
    {
        enqueue(REDIS_REPLY_STRING, "old-sha");
        ASSERT_TRUE(client.loadScript(&context, script));
        ASSERT_EQ(1u, calls.size());
        EXPECT_EQ(script, calls[0].script);
        EXPECT_EQ(1u, freed);
        calls.clear();
    }

    RateLimitVerdict
    decide()
    {
        return client.decide(&context, "asset:source:/path", 1.5f, 7, [this]() {
            return client.loadScript(&context, script);
        });
    }

    void
    expectEvaluation(size_t index, const std::string &sha)
    {
        ASSERT_LT(index, calls.size());
        EXPECT_EQ("EVALSHA %s 1 %s %f %d", calls[index].format);
        EXPECT_EQ(sha, calls[index].sha);
        EXPECT_EQ("asset:source:/path", calls[index].key);
        EXPECT_DOUBLE_EQ(1.5, calls[index].limit);
        EXPECT_EQ(7, calls[index].burst);
    }

    void
    expectLoad(size_t index)
    {
        ASSERT_LT(index, calls.size());
        EXPECT_EQ("SCRIPT LOAD %s", calls[index].format);
        EXPECT_EQ(script, calls[index].script);
    }

    static RateLimitRedisTest *active;
    redisContext context{};
    RateLimitRedis client{command, freeReply};
    const std::string script = "return false";
    std::deque<Response> responses;
    std::vector<Call> calls;
    std::set<redisReply *> live;
    size_t allocated = 0;
    size_t freed = 0;
};

RateLimitRedisTest *RateLimitRedisTest::active = nullptr;

class RedisVerdictTest : public RateLimitRedisTest, public testing::WithParamInterface<int> {};

TEST_P(RedisVerdictTest, NoScriptReloadsAndRetriesSameRequestOnce)
{
    initialize();
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT No matching script. Please use EVAL.");
    enqueue(REDIS_REPLY_STRING, "new-sha");
    enqueue(GetParam(), "BLOCK AND LOG");
    const auto expected = GetParam() == REDIS_REPLY_INTEGER ? RateLimitVerdict::ACCEPT
        : GetParam() == REDIS_REPLY_NIL ? RateLimitVerdict::DROP : RateLimitVerdict::DROP_AND_LOG;

    EXPECT_EQ(expected, decide());
    ASSERT_EQ(3u, calls.size());
    expectEvaluation(0, "old-sha");
    expectLoad(1);
    expectEvaluation(2, "new-sha");
    EXPECT_EQ(4u, freed); // Initial load plus all three recovery commands.
    EXPECT_TRUE(client.isReady());

    enqueue(REDIS_REPLY_NIL);
    EXPECT_EQ(RateLimitVerdict::DROP, decide());
    ASSERT_EQ(4u, calls.size());
    expectEvaluation(3, "new-sha");
}

TEST_P(RedisVerdictTest, NormalPathUsesOneCommandAndPreservesVerdict)
{
    initialize();
    enqueue(GetParam(), "BLOCK AND LOG");
    const auto expected = GetParam() == REDIS_REPLY_INTEGER ? RateLimitVerdict::ACCEPT
        : GetParam() == REDIS_REPLY_NIL ? RateLimitVerdict::DROP : RateLimitVerdict::DROP_AND_LOG;
    EXPECT_EQ(expected, decide());
    ASSERT_EQ(1u, calls.size());
    expectEvaluation(0, "old-sha");
    EXPECT_EQ(2u, freed);
    EXPECT_TRUE(client.isReady());
}

INSTANTIATE_TEST_CASE_P(
    Verdicts,
    RedisVerdictTest,
    testing::Values(REDIS_REPLY_INTEGER, REDIS_REPLY_NIL, REDIS_REPLY_STRING)
);

class RedisLoadFailureTest : public RateLimitRedisTest, public testing::WithParamInterface<int> {};

TEST_P(RedisLoadFailureTest, FailedReloadAcceptsAndCanRecoverNextRequest)
{
    initialize();
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT missing");
    enqueue(GetParam(), "ERR load failed");
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    ASSERT_EQ(2u, calls.size());
    expectEvaluation(0, "old-sha");
    expectLoad(1);
    EXPECT_EQ(3u, freed);
    EXPECT_FALSE(client.isReady());

    enqueue(REDIS_REPLY_STRING, "recovered-sha");
    enqueue(REDIS_REPLY_NIL);
    EXPECT_EQ(RateLimitVerdict::DROP, decide());
    ASSERT_EQ(4u, calls.size());
    expectLoad(2);
    expectEvaluation(3, "recovered-sha");
}

TEST_P(RedisLoadFailureTest, FailedInitializationReturnsFalseAndFreesReply)
{
    enqueue(GetParam(), "ERR load failed");
    EXPECT_FALSE(client.loadScript(&context, script));
    EXPECT_FALSE(client.isReady());
    EXPECT_EQ(1u, calls.size());
    EXPECT_EQ(1u, freed);
}

INSTANTIATE_TEST_CASE_P(
    NonStringReplies,
    RedisLoadFailureTest,
    testing::Values(REDIS_REPLY_ERROR, REDIS_REPLY_INTEGER, REDIS_REPLY_NIL, REDIS_REPLY_STATUS)
);

TEST_F(RateLimitRedisTest, OtherErrorAcceptsWithoutReplayAndRecoversNextRequest)
{
    initialize();
    enqueue(REDIS_REPLY_ERROR, "ERR script execution failed");
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    EXPECT_EQ(1u, calls.size());
    EXPECT_EQ(2u, freed);
    EXPECT_FALSE(client.isReady());

    enqueue(REDIS_REPLY_STRING, "recovered-sha");
    enqueue(REDIS_REPLY_NIL);
    EXPECT_EQ(RateLimitVerdict::DROP, decide());
    ASSERT_EQ(3u, calls.size());
    expectLoad(1);
    expectEvaluation(2, "recovered-sha");
}

TEST_F(RateLimitRedisTest, RepeatedNoScriptStopsAfterOneReloadAndOneRetry)
{
    initialize();
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT");
    enqueue(REDIS_REPLY_STRING, "new-sha");
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT missing again");
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    ASSERT_EQ(3u, calls.size());
    expectEvaluation(0, "old-sha");
    expectLoad(1);
    expectEvaluation(2, "new-sha");
    EXPECT_EQ(4u, freed);
    EXPECT_FALSE(client.isReady());
}

TEST_F(RateLimitRedisTest, NoScriptAfterRecoveryLoadStillHasOnlyOneEvalRetry)
{
    enqueue(REDIS_REPLY_STRING, "recovered-sha");
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT missing");
    enqueue(REDIS_REPLY_STRING, "new-sha");
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT missing again");
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    ASSERT_EQ(4u, calls.size());
    expectLoad(0);
    expectEvaluation(1, "recovered-sha");
    expectLoad(2);
    expectEvaluation(3, "new-sha");
    EXPECT_EQ(4u, freed);
    EXPECT_FALSE(client.isReady());
}

TEST_F(RateLimitRedisTest, MissingReloadReplyAcceptsWithoutRetry)
{
    initialize();
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT missing");
    responses.push_back({0, "", true, 0});
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    EXPECT_EQ(2u, calls.size());
    EXPECT_EQ(2u, freed);
    EXPECT_FALSE(client.isReady());
}

TEST_F(RateLimitRedisTest, MissingEvalReplyAcceptsWithoutReplay)
{
    initialize();
    responses.push_back({0, "", true, 0});
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    EXPECT_EQ(1u, calls.size());
    EXPECT_EQ(1u, freed);
    EXPECT_FALSE(client.isReady());
}

TEST_F(RateLimitRedisTest, ContextErrorWithReplyFreesItWithoutReplay)
{
    initialize();
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPT missing", 1);
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    EXPECT_EQ(1u, calls.size());
    EXPECT_EQ(2u, freed);
    EXPECT_FALSE(client.isReady());
}

TEST_F(RateLimitRedisTest, LoadContextErrorWithStringReplyFailsAndFreesIt)
{
    enqueue(REDIS_REPLY_STRING, "sha", 1);
    EXPECT_FALSE(client.loadScript(&context, script));
    EXPECT_FALSE(client.isReady());
    EXPECT_EQ(1u, calls.size());
    EXPECT_EQ(1u, freed);
}

TEST_F(RateLimitRedisTest, EmptyShaIsFailedInitialization)
{
    enqueue(REDIS_REPLY_STRING);
    EXPECT_FALSE(client.loadScript(&context, script));
    EXPECT_FALSE(client.isReady());
    EXPECT_EQ(1u, freed);
}

TEST_F(RateLimitRedisTest, NoConnectionAcceptsWithoutCommands)
{
    EXPECT_EQ(RateLimitVerdict::ACCEPT, client.decide(nullptr, "key", 1, 1, []() {
        ADD_FAILURE() << "Must not reload without a connection";
        return false;
    }));
    EXPECT_FALSE(client.loadScript(nullptr, script));
    context.err = 1;
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    EXPECT_FALSE(client.loadScript(&context, script));
    EXPECT_TRUE(calls.empty());
}

TEST_F(RateLimitRedisTest, SimilarErrorCodeDoesNotTriggerSameRequestReplay)
{
    initialize();
    enqueue(REDIS_REPLY_ERROR, "NOSCRIPTING unrelated error");
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    EXPECT_EQ(1u, calls.size());
    EXPECT_FALSE(client.isReady());
}

TEST_F(RateLimitRedisTest, UnexpectedReplyAcceptsAndInvalidatesScript)
{
    initialize();
    enqueue(REDIS_REPLY_ARRAY);
    EXPECT_EQ(RateLimitVerdict::ACCEPT, decide());
    EXPECT_EQ(1u, calls.size());
    EXPECT_EQ(2u, freed);
    EXPECT_FALSE(client.isReady());
}

} // namespace

TEST(ReconnectGateTest, AllowsOneAttemptPerInterval)
{
    ReconnectGate gate(std::chrono::seconds(5));
    auto start = ReconnectGate::Clock::now();
    EXPECT_TRUE(gate.allow(start));
    EXPECT_FALSE(gate.allow(start + std::chrono::seconds(1)));
    EXPECT_FALSE(gate.allow(start + std::chrono::milliseconds(4999)));
    EXPECT_TRUE(gate.allow(start + std::chrono::seconds(5)));
    EXPECT_FALSE(gate.allow(start + std::chrono::seconds(6)));
}
