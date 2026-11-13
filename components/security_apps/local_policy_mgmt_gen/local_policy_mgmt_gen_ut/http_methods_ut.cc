#include "cptest.h"
#include "config_component.h"
#include "policy_maker_utils.h"

#include <map>
#include <sstream>
#include <string>

#include "cereal/external/rapidjson/document.h"
#include "cereal/external/rapidjson/stringbuffer.h"
#include "cereal/external/rapidjson/writer.h"

using namespace std;
using namespace testing;

namespace
{

class MockHttpMethodsEnvDetails : public Singleton::Provide<I_EnvDetails>::From<MockProvider<I_EnvDetails>>
{
public:
    MOCK_METHOD0(getEnvType, EnvType());
    MOCK_METHOD0(getToken, string());
    MOCK_METHOD0(getNameSpace, string());
};

class HttpMethodsTest : public Test
{
protected:
    void
    SetUp() override
    {
        EXPECT_CALL(env, getEnvType()).WillRepeatedly(Return(EnvType::LINUX));
        environment.preload();
        environment.init();
        config.preload();
    }

    string
    policyJson(bool v1beta2, const string &value)
    {
        const string key = v1beta2 ? "nonValidHttpMethods" : "non-valid-http-methods";
        const string protections = value.empty() ? "{}" : "{\"" + key + "\":" + value + "}";
        if (v1beta2) {
            return R"({
                "apiVersion": "v1beta2",
                "policies": {
                    "default": {"mode": "prevent", "threatPreventionPractices": ["web"],
                        "accessControlPractices": [], "customResponse": ""},
                    "specificRules": []
                },
                "threatPreventionPractices": [{
                    "name": "web",
                    "fileSecurity": {"overrideMode": "inactive"},
                    "intrusionPrevention": {"overrideMode": "inactive"},
                    "snortSignatures": {"overrideMode": "inactive"},
                    "webAttacks": {"overrideMode": "prevent", "protections": )" + protections + R"(},
                    "antiBot": {"overrideMode": "inactive"},
                    "schemaValidation": {"overrideMode": "inactive"}
                }],
                "autoUpgrade": {"mode": "manual"}
            })";
        }
        return R"({
            "apiVersion": "v1beta1",
            "policies": {
                "default": {"mode": "prevent", "practices": ["web"]},
                "specific-rules": []
            },
            "practices": [{
                "name": "web",
                "web-attacks": {"override-mode": "prevent", "protections": )" + protections + R"(},
                "anti-bot": {"override-mode": "inactive"}
            }]
        })";
    }

    template <class Policy, class Rule>
    void
    expectGeneratedValue(const string &json, int expected)
    {
        istringstream input(json);
        cereal::JSONInputArchive archive(input);
        Policy policy;
        policy.serialize(archive);
        CPTestTempfile output;
        PolicyMakerUtils generator;
        const string generated = generator.proccesMultipleAppsecPolicies<Policy, Rule>(
            {{"fixture", policy}}, "test-version", output.fname
        );
        ASSERT_FALSE(generated.empty());
        EXPECT_EQ(generated, output.readFile());
        rapidjson::Document document;
        document.Parse(generated.c_str());
        ASSERT_FALSE(document.HasParseError());
        ASSERT_TRUE(document.IsObject());
        ASSERT_TRUE(document.HasMember("waap"));
        ASSERT_TRUE(document["waap"].HasMember("WAAP"));
        ASSERT_TRUE(document["waap"]["WAAP"].HasMember("WebApplicationSecurity"));
        const auto &apps = document["waap"]["WAAP"]["WebApplicationSecurity"];
        ASSERT_TRUE(apps.IsArray());
        ASSERT_EQ(1u, apps.Size());
        ASSERT_TRUE(apps[0].HasMember("practiceAdvancedConfig"));
        const auto &advanced = apps[0]["practiceAdvancedConfig"];
        ASSERT_TRUE(advanced.IsObject());
        ASSERT_TRUE(advanced.HasMember("httpIllegalMethodsAllowed"));
        ASSERT_TRUE(advanced["httpIllegalMethodsAllowed"].IsInt());
        EXPECT_EQ(expected, advanced["httpIllegalMethodsAllowed"].GetInt());

        // Snapshot all advanced fields and their order, without the surrounding generated UUIDs.
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        advanced.Accept(writer);
        const string expected_config = R"({"httpHeaderMaxSize":102400,"httpIllegalMethodsAllowed":)"
            + to_string(expected)
            + R"(,"httpRequestBodyMaxSize":1000000,"jsonMaxObjectDepth":40,"urlMaxSize":32768})";
        EXPECT_EQ(expected_config, buffer.GetString());
    }

    StrictMock<MockHttpMethodsEnvDetails> env;
    ::Environment environment;
    ConfigComponent config;
};

TEST_F(HttpMethodsTest, V1beta1TrueAllowsNonValidMethods)
{
    expectGeneratedValue<AppsecLinuxPolicy, ParsedRule>(policyJson(false, "true"), 1);
}

TEST_F(HttpMethodsTest, V1beta1FalseKeepsBlockingNonValidMethods)
{
    expectGeneratedValue<AppsecLinuxPolicy, ParsedRule>(policyJson(false, "false"), 0);
}

TEST_F(HttpMethodsTest, V1beta1AbsentKeepsDefaultOutput)
{
    expectGeneratedValue<AppsecLinuxPolicy, ParsedRule>(policyJson(false, ""), 0);
}

TEST_F(HttpMethodsTest, V1beta2TrueAllowsNonValidMethods)
{
    expectGeneratedValue<V1beta2AppsecLinuxPolicy, NewParsedRule>(policyJson(true, "true"), 1);
}

TEST_F(HttpMethodsTest, V1beta2FalseKeepsBlockingNonValidMethods)
{
    expectGeneratedValue<V1beta2AppsecLinuxPolicy, NewParsedRule>(policyJson(true, "false"), 0);
}

TEST_F(HttpMethodsTest, V1beta2AbsentKeepsDefaultOutput)
{
    expectGeneratedValue<V1beta2AppsecLinuxPolicy, NewParsedRule>(policyJson(true, ""), 0);
}

} // namespace
