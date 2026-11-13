#include "cptest.h"
#include "policy_maker_utils.h"

#include <map>
#include <string>

#include "cereal/external/rapidjson/document.h"

using namespace std;
using namespace testing;

class MockPolicyEnvDetails : public Singleton::Provide<I_EnvDetails>::From<MockProvider<I_EnvDetails>>
{
public:
    MOCK_METHOD0(getEnvType, EnvType());
    MOCK_METHOD0(getToken, string());
    MOCK_METHOD0(getNameSpace, string());
};

class RateLimitResponseTest : public Test
{
protected:
    void
    SetUp() override
    {
        EXPECT_CALL(env_details, getEnvType()).WillRepeatedly(Return(EnvType::LINUX));
    }

    V1beta2AppsecLinuxPolicy
    loadPolicy(const string &fixture)
    {
        ifstream input(cptestFnameInSrcDir(fixture));
        EXPECT_TRUE(input.is_open());
        cereal::JSONInputArchive archive(input);
        V1beta2AppsecLinuxPolicy policy;
        policy.serialize(archive);
        return policy;
    }

    string
    generate(const map<string, V1beta2AppsecLinuxPolicy> &policies)
    {
        CPTestTempfile output;
        PolicyMakerUtils generator;
        return generator.proccesMultipleAppsecPolicies<V1beta2AppsecLinuxPolicy, NewParsedRule>(
            policies,
            "test-version",
            output.fname
        );
    }

    StrictMock<MockPolicyEnvDetails> env_details;
};

TEST_F(RateLimitResponseTest, MapsEachRuleToItsSelectedResponseInItsOwnPolicy)
{
    auto policy = loadPolicy("rate_limit_responses.json");
    // Identical local response names must resolve within each policy's namespace.
    string generated = generate({{"first", policy}, {"second", policy}});
    rapidjson::Document document;
    document.Parse(generated.c_str());
    ASSERT_FALSE(document.HasParseError());

    const auto &responses = document["triggers"]["rulebase"]["webUserResponse"];
    ASSERT_TRUE(responses.IsArray());
    ASSERT_EQ(4u, responses.Size());
    map<string, string> response_contexts;
    for (const auto &response : responses.GetArray()) {
        string name = response["triggerName"].GetString();
        response_contexts[name] = response["context"].GetString();
        if (name == "first/code" || name == "second/code") {
            EXPECT_STREQ("Response Code", response["details level"].GetString());
            EXPECT_EQ(429, response["response code"].GetInt());
        } else {
            EXPECT_EQ(403, response["response code"].GetInt());
            EXPECT_STREQ("Rate limit exceeded", response["response title"].GetString());
        }
    }

    const auto &limits = document["accessControlV2"]["rulebase"]["rateLimit"];
    ASSERT_TRUE(limits.IsArray());
    ASSERT_EQ(6u, limits.Size());
    map<string, string> expected_responses = {
        {"first/default-limit", "first/code"},
        {"first/page-limit", "first/page"},
        {"first/inherited-limit", "first/code"},
        {"second/default-limit", "second/code"},
        {"second/page-limit", "second/page"},
        {"second/inherited-limit", "second/code"}
    };
    for (const auto &limit : limits.GetArray()) {
        string name = limit["name"].GetString();
        SCOPED_TRACE(name);
        auto expected = expected_responses.find(name);
        ASSERT_NE(expected_responses.end(), expected);
        ASSERT_TRUE(limit.HasMember("webUserResponseId"));
        ASSERT_TRUE(limit["webUserResponseId"].IsString());
        string id = limit["webUserResponseId"].GetString();
        ASSERT_FALSE(id.empty());
        auto response = response_contexts.find(expected->second);
        ASSERT_NE(response_contexts.end(), response);
        EXPECT_EQ("triggerId(" + id + ")", response->second);
        EXPECT_STREQ("Active", limit["mode"].GetString());
        ASSERT_EQ(1u, limit["rules"].Size());
        expected_responses.erase(expected);
    }
    EXPECT_TRUE(expected_responses.empty());
}

TEST_F(RateLimitResponseTest, LeavesResponseIdEmptyWhenNoResponseIsSelected)
{
    // A response defined elsewhere must not become a global default.
    string generated = generate({{"fallback", loadPolicy("rate_limit_fallback.json")}});
    rapidjson::Document document;
    document.Parse(generated.c_str());
    ASSERT_FALSE(document.HasParseError());
    const auto &limits = document["accessControlV2"]["rulebase"]["rateLimit"];
    ASSERT_TRUE(limits.IsArray());
    ASSERT_EQ(1u, limits.Size());
    ASSERT_TRUE(limits[0].HasMember("webUserResponseId"));
    ASSERT_TRUE(limits[0]["webUserResponseId"].IsString());
    EXPECT_STREQ("", limits[0]["webUserResponseId"].GetString());
    EXPECT_TRUE(document["triggers"]["rulebase"]["webUserResponse"].Empty());
}

TEST_F(RateLimitResponseTest, KeepsSharedPracticeForEachHostAndDefaultRule)
{
    string generated = generate({{"shared", loadPolicy("rate_limit_shared_practice.json")}});
    rapidjson::Document document;
    document.Parse(generated.c_str());
    ASSERT_FALSE(document.HasParseError());

    const auto &responses = document["triggers"]["rulebase"]["webUserResponse"];
    ASSERT_TRUE(responses.IsArray());
    ASSERT_EQ(2u, responses.Size());
    map<string, string> response_contexts;
    for (const auto &response : responses.GetArray()) {
        response_contexts[response["triggerName"].GetString()] = response["context"].GetString();
    }

    const auto &limits = document["accessControlV2"]["rulebase"]["rateLimit"];
    ASSERT_TRUE(limits.IsArray());
    ASSERT_EQ(3u, limits.Size());
    map<string, string> expected_responses = {
        {"assetId(first.example)", "shared/page"},
        {"assetId(second.example)", "shared/code"},
        {"All()", "shared/code"}
    };
    map<string, string> limit_contexts;
    for (const auto &limit : limits.GetArray()) {
        string context = limit["context"].GetString();
        SCOPED_TRACE(context);
        auto expected = expected_responses.find(context);
        ASSERT_NE(expected_responses.end(), expected);
        EXPECT_STREQ("shared/limit", limit["name"].GetString());
        EXPECT_STREQ("Active", limit["mode"].GetString());
        ASSERT_EQ(1u, limit["rules"].Size());
        EXPECT_EQ(10, limit["rules"][0]["limit"].GetInt());
        string id = limit["practiceId"].GetString();
        ASSERT_FALSE(id.empty());
        EXPECT_TRUE(limit_contexts.emplace(id, context).second);
        ASSERT_TRUE(limit.HasMember("webUserResponseId"));
        ASSERT_TRUE(limit["webUserResponseId"].IsString());
        string response_id = limit["webUserResponseId"].GetString();
        ASSERT_FALSE(response_id.empty());
        auto response = response_contexts.find(expected->second);
        ASSERT_NE(response_contexts.end(), response);
        EXPECT_EQ("triggerId(" + response_id + ")", response->second);
        expected_responses.erase(expected);
    }
    EXPECT_TRUE(expected_responses.empty());

    const auto &rules = document["rules"]["rulebase"]["rulesConfig"];
    ASSERT_TRUE(rules.IsArray());
    ASSERT_EQ(3u, rules.Size());
    for (const auto &rule : rules.GetArray()) {
        string asset_id = rule["assetId"].GetString();
        SCOPED_TRACE(asset_id);
        unsigned int rate_limit_practices = 0;
        for (const auto &practice : rule["practices"].GetArray()) {
            if (string(practice["practiceType"].GetString()) != "RateLimit") continue;
            ++rate_limit_practices;
            EXPECT_STREQ("shared/limit", practice["practiceName"].GetString());
            auto limit = limit_contexts.find(practice["practiceId"].GetString());
            ASSERT_NE(limit_contexts.end(), limit);
            EXPECT_EQ(asset_id == "Any" ? "All()" : "assetId(" + asset_id + ")", limit->second);
            limit_contexts.erase(limit);
        }
        EXPECT_EQ(1u, rate_limit_practices);
    }
    EXPECT_TRUE(limit_contexts.empty());
}
