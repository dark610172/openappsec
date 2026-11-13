#include "cptest.h"
#include "policy_maker_utils.h"

#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "cereal/external/rapidjson/document.h"
#include "cereal/external/rapidjson/stringbuffer.h"
#include "cereal/external/rapidjson/writer.h"

using namespace std;
using namespace testing;

namespace
{

class MockExceptionsEnvDetails : public Singleton::Provide<I_EnvDetails>::From<MockProvider<I_EnvDetails>>
{
public:
    MOCK_METHOD0(getEnvType, EnvType());
    MOCK_METHOD0(getToken, string());
    MOCK_METHOD0(getNameSpace, string());
};

string
jsonBytes(const rapidjson::Value &value)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    value.Accept(writer);
    return buffer.GetString();
}

class MultipleExceptionsTest : public Test
{
protected:
    void
    SetUp() override
    {
        EXPECT_CALL(env, getEnvType()).WillRepeatedly(Return(EnvType::LINUX));
    }

    string
    specificRule(const string &host, const string &exceptions = "")
    {
        return R"({"host": ")" + host + R"(", "mode": "prevent",
            "threatPreventionPractices": ["web"], "accessControlPractices": [], "customResponse": "")"
            + (exceptions.empty() ? "" : ", \"exceptions\": " + exceptions) + "}";
    }

    void
    generatePolicy(rapidjson::Document &document, const string &defaults, const string &specific_rules = "[]")
    {
        string json = R"({
            "apiVersion": "v1beta2",
            "policies": {
                "default": {
                    "mode": "prevent",
                    "threatPreventionPractices": ["web"],
                    "accessControlPractices": [],
                    "customResponse": "",
                    "exceptions": )" + defaults + R"(
                },
                "specificRules": )" + specific_rules + R"(
            },
            "threatPreventionPractices": [{
                "name": "web",
                "fileSecurity": {"overrideMode": "inactive"},
                "intrusionPrevention": {"overrideMode": "inactive"},
                "snortSignatures": {"overrideMode": "inactive"},
                "webAttacks": {"overrideMode": "prevent"},
                "antiBot": {"overrideMode": "inactive"},
                "schemaValidation": {"overrideMode": "inactive"}
            }],
            "exceptions": [
                {"name": "z-accept", "action": "accept", "condition": [{"key": "url", "value": "/allowed"}]},
                {"name": "a-drop", "action": "drop", "condition": [{"key": "sourceIp", "value": "192.0.2.0/24"}]},
                {"name": "default-accept", "action": "accept",
                    "condition": [{"key": "sourceIdentifier", "value": "trusted-client"}]},
                {"name": "default-drop", "action": "drop",
                    "condition": [{"key": "hostName", "value": "blocked.example"}]}
            ],
            "autoUpgrade": {"mode": "manual"}
        })";
        istringstream input(json);
        cereal::JSONInputArchive archive(input);
        V1beta2AppsecLinuxPolicy policy;
        policy.serialize(archive);
        CPTestTempfile output;
        PolicyMakerUtils generator;
        string generated = generator.proccesMultipleAppsecPolicies<V1beta2AppsecLinuxPolicy, NewParsedRule>(
            {{"test", policy}}, "test-version", output.fname
        );
        ASSERT_FALSE(generated.empty());
        EXPECT_EQ(generated, output.readFile());
        document.Parse(generated.c_str());
        ASSERT_FALSE(document.HasParseError());
    }

    void
    checkPolicy(const rapidjson::Document &document, const map<string, vector<string>> &expected_rules)
    {
        struct ExpectedException
        {
            string action;
            string key;
            string value;
        };
        const map<string, ExpectedException> specs = {
            {"z-accept", {"accept", "url", "/allowed"}},
            {"a-drop", {"reject", "sourceIP", "192.0.2.0/24"}},
            {"default-accept", {"accept", "sourceIdentifier", "trusted-client"}},
            {"default-drop", {"reject", "hostName", "blocked.example"}}
        };
        const auto &sections = document["exceptions"]["rulebase"]["exception"];
        ASSERT_EQ(1u, sections.Size());
        const auto &exceptions = sections[0]["exceptions"];
        ASSERT_TRUE(exceptions.IsArray());
        map<string, const rapidjson::Value *> resources;
        string context = "Any(";
        for (const auto &exception : exceptions.GetArray()) {
            string id = exception["behavior"]["id"].GetString();
            ASSERT_FALSE(id.empty());
            ASSERT_TRUE(resources.emplace(id, &exception).second);
            if (context != "Any(") context += ", ";
            context += "parameterId(" + id + ")";
        }
        EXPECT_EQ(context + ")", sections[0]["context"].GetString());

        const auto &apps = document["waap"]["WAAP"]["WebApplicationSecurity"];
        ASSERT_TRUE(apps.IsArray());
        ASSERT_EQ(expected_rules.size(), apps.Size());
        map<string, const rapidjson::Value *> apps_by_asset;
        for (const auto &app : apps.GetArray()) {
            ASSERT_TRUE(apps_by_asset.emplace(app["assetName"].GetString(), &app).second);
        }

        const auto &rules = document["rules"]["rulebase"]["rulesConfig"];
        ASSERT_TRUE(rules.IsArray());
        ASSERT_EQ(expected_rules.size(), rules.Size());
        map<string, string> ids_by_name;
        for (const auto &rule : rules.GetArray()) {
            string asset = rule["assetName"].GetString();
            SCOPED_TRACE(asset);
            auto expected = expected_rules.find(asset);
            ASSERT_NE(expected_rules.end(), expected);
            auto app = apps_by_asset.find(asset);
            ASSERT_NE(apps_by_asset.end(), app);
            const auto &parameters = rule["parameters"];
            const auto &overrides = (*app->second)["overrides"];
            ASSERT_TRUE(parameters.IsArray());
            ASSERT_TRUE(overrides.IsArray());
            ASSERT_EQ(expected->second.size(), parameters.Size());
            ASSERT_EQ(parameters.Size(), overrides.Size());
            for (rapidjson::SizeType i = 0; i < parameters.Size(); ++i) {
                const string &name = expected->second[i];
                SCOPED_TRACE(name);
                const auto &spec = specs.at(name);
                const auto &parameter = parameters[i];
                string id = parameter["parameterId"].GetString();
                ASSERT_FALSE(id.empty());
                auto previous_id = ids_by_name.emplace(name, id);
                EXPECT_EQ(previous_id.first->second, id);
                EXPECT_EQ("test/" + name, parameter["parameterName"].GetString());
                EXPECT_STREQ("Exception", parameter["parameterType"].GetString());
                auto resource = resources.find(id);
                ASSERT_NE(resources.end(), resource);
                // Snapshot the legacy field names, order, conditions and action mapping, using the emitted UUID.
                string behavior = R"({"key":"action","value":")" + spec.action + R"(","id":")" + id + R"("})";
                string match = R"({"key":")" + spec.key
                    + R"(","op":"equals","type":"condition","value":[")" + spec.value + R"("]})";
                EXPECT_EQ("{\"behavior\":" + behavior + ",\"match\":" + match + "}", jsonBytes(*resource->second));
                string parsed_match = R"({"operator":"basic","tag":")" + spec.key
                    + R"(","value":")" + spec.value + R"("})";
                string override_json = R"({"id":")" + id + R"(","parsedBehavior":[{"action":")" + spec.action
                    + R"("}],"parsedMatch":)" + parsed_match + "}";
                EXPECT_EQ(override_json, jsonBytes(overrides[i]));
            }
            apps_by_asset.erase(app);
        }
        EXPECT_TRUE(apps_by_asset.empty());
        // No unreferenced or duplicate global resources, including resources from overridden defaults.
        EXPECT_EQ(ids_by_name.size(), resources.size());
    }

    StrictMock<MockExceptionsEnvDetails> env;
};

TEST_F(MultipleExceptionsTest, LinksBothNamedExceptionsAndWaapOverrides)
{
    rapidjson::Document document;
    ASSERT_NO_FATAL_FAILURE(generatePolicy(document, "[]", "[" + specificRule(
        "multi.example", R"(["z-accept", "a-drop"])"
    ) + "]"));
    ASSERT_NO_FATAL_FAILURE(checkPolicy(document, {{"Any", {}}, {"multi.example", {"z-accept", "a-drop"}}}));
}

TEST_F(MultipleExceptionsTest, PreservesSingleExceptionSerialization)
{
    rapidjson::Document document;
    ASSERT_NO_FATAL_FAILURE(generatePolicy(document, R"(["z-accept"])"));
    ASSERT_NO_FATAL_FAILURE(checkPolicy(document, {{"Any", {"z-accept"}}}));
    const auto &parameters = document["rules"]["rulebase"]["rulesConfig"][0]["parameters"];
    string id = parameters[0]["parameterId"].GetString();
    EXPECT_EQ(R"([{"parameterId":")" + id
        + R"(","parameterName":"test/z-accept","parameterType":"Exception"}])", jsonBytes(parameters));
    const auto &section = document["exceptions"]["rulebase"]["exception"][0];
    EXPECT_EQ("Any(parameterId(" + id + "))", section["context"].GetString());
}

TEST_F(MultipleExceptionsTest, InheritsAllDefaultsUnlessSpecificExceptionsAreSelected)
{
    string rules = "[" + specificRule("inherited.example") + ","
        + specificRule("empty.example", "[]") + ","
        + specificRule("specific.example", R"(["z-accept", "a-drop"])") + "]";
    rapidjson::Document document;
    ASSERT_NO_FATAL_FAILURE(generatePolicy(document, R"(["default-accept", "default-drop"])", rules));
    ASSERT_NO_FATAL_FAILURE(checkPolicy(document, {
        {"Any", {"default-accept", "default-drop"}},
        {"inherited.example", {"default-accept", "default-drop"}},
        {"empty.example", {"default-accept", "default-drop"}},
        {"specific.example", {"z-accept", "a-drop"}}
    }));
}

TEST_F(MultipleExceptionsTest, ReusesNamedResourcesAndIgnoresRepeatedAndEmptyNames)
{
    rapidjson::Document document;
    ASSERT_NO_FATAL_FAILURE(generatePolicy(document, R"(["z-accept"])", "[" + specificRule(
        "reuse.example", R"(["z-accept", "", "a-drop", "z-accept"])"
    ) + "]"));
    ASSERT_NO_FATAL_FAILURE(checkPolicy(document, {
        {"Any", {"z-accept"}}, {"reuse.example", {"z-accept", "a-drop"}}
    }));
}

TEST_F(MultipleExceptionsTest, KeepsFirstEmptySpecificNameAsDefaultFallback)
{
    rapidjson::Document document;
    ASSERT_NO_FATAL_FAILURE(generatePolicy(document, R"(["default-accept", "default-drop"])", "[" + specificRule(
        "fallback.example", R"(["", "a-drop"])"
    ) + "]"));
    ASSERT_NO_FATAL_FAILURE(checkPolicy(document, {
        {"Any", {"default-accept", "default-drop"}},
        {"fallback.example", {"default-accept", "default-drop"}}
    }));
}

TEST_F(MultipleExceptionsTest, EmitsNoParameterLinksWhenNoExceptionsAreSelected)
{
    rapidjson::Document document;
    ASSERT_NO_FATAL_FAILURE(generatePolicy(document, "[]"));
    ASSERT_NO_FATAL_FAILURE(checkPolicy(document, {{"Any", {}}}));
}

TEST_F(MultipleExceptionsTest, KeepsFirstEmptyDefaultNameAsNoDefaultException)
{
    rapidjson::Document document;
    ASSERT_NO_FATAL_FAILURE(generatePolicy(document, R"(["", "default-drop"])", "[" + specificRule(
        "specific.example", R"(["z-accept", "a-drop"])"
    ) + "]"));
    ASSERT_NO_FATAL_FAILURE(checkPolicy(document, {
        {"Any", {}}, {"specific.example", {"z-accept", "a-drop"}}
    }));
}

} // namespace
