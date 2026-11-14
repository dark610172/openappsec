#include "cptest.h"
#include "config_component.h"
#include "policy_maker_utils.h"

#include <sstream>
#include <string>

#include "cereal/external/rapidjson/document.h"

using namespace std;
using namespace testing;

namespace
{

class MockV1beta1ProtectionsEnvDetails : public Singleton::Provide<I_EnvDetails>::From<MockProvider<I_EnvDetails>>
{
public:
    MOCK_METHOD0(getEnvType, EnvType());
    MOCK_METHOD0(getToken, string());
    MOCK_METHOD0(getNameSpace, string());
};

class V1beta1ProtectionsTest : public Test
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
    policyYaml(const string &protection, const string &mode, bool omit_protections = false)
    {
        // JSON flow syntax is valid YAML. Use the JSON parser boundary directly,
        // as in the other policy-generator tests; external yq is not under test.
        const string protections = mode.empty() ? "{}" : "{\"" + protection + "\":\"" + mode + "\"}";
        return R"({
            "apiVersion": "v1beta1",
            "policies": {
                "default": {"mode": "prevent", "practices": ["web"]},
                "specific-rules": []
            },
            "practices": [{
                "name": "web",
                "web-attacks": {"override-mode": "as-top-level")"
            + (omit_protections ? "" : ", \"protections\": " + protections) + R"(},
                "anti-bot": {"override-mode": "inactive"}
            }]
        })";
    }

    void
    expectProtection(const string &protection, const string &mode, const string &expected, bool omit_protections = false)
    {
        SCOPED_TRACE(protection + "=" + (mode.empty() ? "<absent>" : mode));
        istringstream input(policyYaml(protection, mode, omit_protections));
        cereal::JSONInputArchive archive(input);
        AppsecLinuxPolicy policy;
        policy.serialize(archive);
        CPTestTempfile output;
        PolicyMakerUtils generator;
        const string generated = generator.proccesMultipleAppsecPolicies<AppsecLinuxPolicy, ParsedRule>(
            {{"fixture", policy}}, "test-version", output.fname
        );
        ASSERT_FALSE(generated.empty());
        EXPECT_EQ(generated, output.readFile());
        rapidjson::Document document;
        document.Parse(generated.c_str());
        ASSERT_FALSE(document.HasParseError());
        ASSERT_TRUE(document.IsObject());
        ASSERT_TRUE(document.HasMember("waap"));
        ASSERT_TRUE(document["waap"].IsObject());
        ASSERT_TRUE(document["waap"].HasMember("WAAP"));
        ASSERT_TRUE(document["waap"]["WAAP"].IsObject());
        ASSERT_TRUE(document["waap"]["WAAP"].HasMember("WebApplicationSecurity"));
        const auto &apps = document["waap"]["WAAP"]["WebApplicationSecurity"];
        ASSERT_TRUE(apps.IsArray());
        ASSERT_EQ(1u, apps.Size());
        ASSERT_TRUE(apps[0].IsObject());
        const char *input_keys[] = {"csrf-enabled", "open-redirect-enabled", "error-disclosure-enabled"};
        const char *output_keys[] = {"csrfProtection", "openRedirect", "errorDisclosure"};
        for (unsigned int i = 0; i < 3; ++i) {
            ASSERT_TRUE(apps[0].HasMember(output_keys[i]));
            ASSERT_TRUE(apps[0][output_keys[i]].IsString());
            // Each policy changes just one protection. Its siblings keep their defaults.
            EXPECT_EQ(protection == input_keys[i] ? expected : "Disabled", apps[0][output_keys[i]].GetString())
                << output_keys[i];
        }
    }

    void
    expectAllProtections(const string &mode, const string &expected)
    {
        for (const char *key : {"csrf-enabled", "open-redirect-enabled", "error-disclosure-enabled"}) {
            expectProtection(key, mode, expected);
        }
    }

    StrictMock<MockV1beta1ProtectionsEnvDetails> env;
    ::Environment environment;
    ConfigComponent config;
};

TEST_F(V1beta1ProtectionsTest, PreventIsEmittedForEachProtection)
{
    expectAllProtections("prevent", "Prevent");
}

TEST_F(V1beta1ProtectionsTest, DetectIsEmittedForEachProtection)
{
    expectAllProtections("detect", "Detect");
}

TEST_F(V1beta1ProtectionsTest, InactiveDisablesEachProtection)
{
    expectAllProtections("inactive", "Disabled");
}

TEST_F(V1beta1ProtectionsTest, AbsentSettingsKeepEachProtectionDisabled)
{
    expectAllProtections("", "Disabled");
}

TEST_F(V1beta1ProtectionsTest, AbsentProtectionsObjectKeepsAllDisabled)
{
    expectProtection("", "", "Disabled", true);
}

TEST_F(V1beta1ProtectionsTest, LearnModesUseTheV1beta2Mapping)
{
    expectAllProtections("prevent-learn", "Prevent");
    expectAllProtections("detect-learn", "Learn");
}

} // namespace
