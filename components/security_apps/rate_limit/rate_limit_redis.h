#ifndef RATE_LIMIT_REDIS_H
#define RATE_LIMIT_REDIS_H

#include <functional>
#include <memory>
#include <string>

#include "hiredis/hiredis.h"

enum class RateLimitVerdict { ACCEPT, DROP, DROP_AND_LOG };

// Owns the script state and command replies, but not the Redis connection.
class RateLimitRedis
{
public:
    using Command = void *(*)(redisContext *, const char *, ...);
    using FreeReply = void (*)(void *);

    RateLimitRedis(Command command, FreeReply free_reply) : command(command), free_reply(free_reply) {}

    bool loadScript(redisContext *context, const std::string &script);
    RateLimitVerdict decide(
        redisContext *context,
        const std::string &key,
        float limit,
        int burst,
        const std::function<bool()> &reload_script
    );
    bool isReady() const { return !sha.empty(); }
    void reset() { sha.clear(); }

private:
    using Reply = std::unique_ptr<redisReply, FreeReply>;

    Command command;
    FreeReply free_reply;
    std::string sha;
};

#endif // RATE_LIMIT_REDIS_H
