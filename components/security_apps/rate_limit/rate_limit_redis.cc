#include "rate_limit_redis.h"

#include <cstring>

redisContext *
setRateLimitRedisTimeout(
    redisContext *context,
    const timeval &timeout,
    int (*set_timeout)(redisContext *, const timeval),
    void (*free_context)(redisContext *)
)
{
    if (context == nullptr) return nullptr;
    if (set_timeout(context, timeout) != REDIS_OK) {
        free_context(context);
        return nullptr;
    }
    return context;
}

namespace
{

bool
isNoScript(const redisReply &reply)
{
    const char *code = "NOSCRIPT";
    const size_t length = std::strlen(code);
    return reply.type == REDIS_REPLY_ERROR && reply.str != nullptr && reply.len >= length
        && std::strncmp(reply.str, code, length) == 0
        && (reply.len == length || reply.str[length] == ' ');
}

} // namespace

bool
RateLimitRedis::loadScript(redisContext *context, const std::string &script)
{
    reset();
    if (context == nullptr || context->err) return false;

    Reply reply(static_cast<redisReply *>(command(context, "SCRIPT LOAD %s", script.c_str())), free_reply);
    if (!reply || context->err || reply->type != REDIS_REPLY_STRING || reply->str == nullptr || reply->len == 0) {
        return false;
    }

    sha.assign(reply->str, reply->len);
    return true;
}

RateLimitVerdict
RateLimitRedis::decide(
    redisContext *context,
    const std::string &key,
    float limit,
    int burst,
    const std::function<bool()> &reload_script
)
{
    if (context == nullptr || context->err) {
        reset();
        return RateLimitVerdict::ACCEPT;
    }

    if (!isReady() && !reload_script()) {
        reset();
        return RateLimitVerdict::ACCEPT;
    }

    auto evaluate = [&]() {
        return Reply(
            static_cast<redisReply *>(command(
                context, "EVALSHA %s 1 %s %f %d", sha.c_str(), key.c_str(), limit, burst
            )),
            free_reply
        );
    };

    Reply reply = evaluate();
    // Only NOSCRIPT guarantees that the script did not execute. Never replay an I/O failure.
    if (reply && !context->err && isNoScript(*reply)) {
        reply.reset();
        reset();
        if (!reload_script()) {
            reset();
            return RateLimitVerdict::ACCEPT;
        }
        reply = evaluate();
    }

    if (reply && !context->err) {
        if (reply->type == REDIS_REPLY_INTEGER) return RateLimitVerdict::ACCEPT;
        if (reply->type == REDIS_REPLY_NIL) return RateLimitVerdict::DROP;
        const char *log_str = "BLOCK AND LOG";
        if (reply->type == REDIS_REPLY_STRING && reply->str != nullptr
            && std::strncmp(reply->str, log_str, std::strlen(log_str)) == 0) {
            return RateLimitVerdict::DROP_AND_LOG;
        }
    }

    reset();
    return RateLimitVerdict::ACCEPT;
}
