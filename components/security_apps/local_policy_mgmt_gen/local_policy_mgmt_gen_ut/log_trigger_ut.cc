#include "cptest.h"
#include "config_component.h"
#include "policy_maker_utils.h"

#include <iterator>
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

class MockLogTriggerEnvDetails : public Singleton::Provide<I_EnvDetails>::From<MockProvider<I_EnvDetails>>
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

class LogTriggerTest : public Test
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
    policyJson(const string &destination = "", const string &response_code = "")
    {
        ifstream input(cptestFnameInSrcDir("log_trigger.json"));
        EXPECT_TRUE(input.is_open());
        string fixture((istreambuf_iterator<char>(input)), istreambuf_iterator<char>());
        rapidjson::Document document;
        document.Parse(fixture.c_str());
        EXPECT_FALSE(document.HasParseError());
        auto &trigger = document["logTriggers"][0];
        if (!destination.empty()) {
            rapidjson::Document value;
            value.Parse(destination.c_str());
            EXPECT_FALSE(value.HasParseError());
            trigger["logDestination"].CopyFrom(value, document.GetAllocator());
            trigger["logDestination"].AddMember("local-tuning", false, document.GetAllocator());
        }
        if (!response_code.empty()) {
            trigger["additionalSuspiciousEventsLogging"].AddMember(
                "responseCode", response_code == "true", document.GetAllocator()
            );
        }
        return jsonBytes(document);
    }

    template <class Policy>
    Policy
    parsePolicy(const string &json)
    {
        istringstream input(json);
        cereal::JSONInputArchive archive(input);
        Policy policy;
        policy.serialize(archive);
        return policy;
    }

    template <class Policy, class Rule>
    void
    generate(rapidjson::Document &document, const string &json)
    {
        auto policy = parsePolicy<Policy>(json);
        CPTestTempfile output;
        PolicyMakerUtils generator;
        string generated = generator.proccesMultipleAppsecPolicies<Policy, Rule>(
            {{"fixture", policy}}, "test-version", output.fname
        );
        document.Parse(generated.c_str());
        ASSERT_FALSE(document.HasParseError());
        ASSERT_TRUE(document.HasMember("triggers"));
        ASSERT_TRUE(document["triggers"]["rulebase"]["log"].IsArray());
        ASSERT_EQ(1u, document["triggers"]["rulebase"]["log"].Size());
    }

    void
    generateV2(rapidjson::Document &document, const string &destination = "", const string &response_code = "")
    {
        generate<V1beta2AppsecLinuxPolicy, NewParsedRule>(document, policyJson(destination, response_code));
    }

    void
    expectTrigger(
        const rapidjson::Document &document,
        const string &service = "",
        bool response_code = false,
        int port = 1514)
    {
        // This snapshot covers every stable serialized field, including legacy/default values.
        // The context contains a newly generated UUID, so validate it separately.
        rapidjson::Document expected;
        expected.Parse(R"({
            "triggerName": "fixture/log", "triggerType": "log", "verbosity": "Standard",
            "acAllow": false, "acDrop": true, "complianceViolations": false, "complianceWarnings": false,
            "extendLoggingMinSeverity": "high", "extendLogging": true,
            "logToAgent": true, "logToCef": false, "logToCloud": false, "logTolocalTuning": false,
            "logToSyslog": false, "responseBody": false, "responseCode": false,
            "tpDetect": false, "tpPrevent": true, "webBody": false, "webHeaders": false,
            "webRequests": false, "webUrlPath": false, "webUrlQuery": false,
            "urlForSyslog": ":514", "urlForCef": ":0", "formatLoggingOutput": false
        })");
        ASSERT_FALSE(expected.HasParseError());
        expected["responseCode"].SetBool(response_code);
        if (!service.empty()) {
            const char *flag = service == "syslogService" ? "logToSyslog" : "logToCef";
            const char *url = service == "syslogService" ? "urlForSyslog" : "urlForCef";
            expected[flag].SetBool(true);
            string address = "192.0.2.10:" + to_string(port);
            expected[url].SetString(address.c_str(), expected.GetAllocator());
        }
        const auto &trigger = document["triggers"]["rulebase"]["log"][0];
        ASSERT_TRUE(trigger.HasMember("context"));
        ASSERT_TRUE(trigger["context"].IsString());
        EXPECT_THAT(string(trigger["context"].GetString()), StartsWith("triggerId("));
        rapidjson::Document actual;
        actual.CopyFrom(trigger, actual.GetAllocator());
        actual.RemoveMember("context");
        EXPECT_TRUE(actual == expected) << "Actual: " << jsonBytes(actual) << "\nExpected: " << jsonBytes(expected);
    }

    void
    expectInvalid(const string &service, const string &value, const string &message)
    {
        string json = policyJson("{\"" + service + "\":" + value + "}");
        try {
            // Test the entire policy parser: optional-field handling must not swallow validation errors.
            parsePolicy<V1beta2AppsecLinuxPolicy>(json);
            FAIL() << "Expected PolicyGenException for " << service << ": " << value;
        } catch (const PolicyGenException &e) {
            EXPECT_THAT(string(e.what()), HasSubstr(service));
            EXPECT_THAT(string(e.what()), HasSubstr(message));
        }
    }

    StrictMock<MockLogTriggerEnvDetails> env;
    ::Environment environment;
    ConfigComponent config;
};

TEST_F(LogTriggerTest, AbsentDestinationsKeepDefaultOutput)
{
    rapidjson::Document document;
    generateV2(document);
    expectTrigger(document);
}

TEST_F(LogTriggerTest, EmptyDestinationArraysKeepDefaultOutput)
{
    for (const string service : {"syslogService", "cefService"}) {
        SCOPED_TRACE(service);
        rapidjson::Document document;
        generateV2(document, "{\"" + service + "\":[]}");
        expectTrigger(document);
    }
}

TEST_F(LogTriggerTest, SingleDestinationArraysEnableLogging)
{
    for (const string service : {"syslogService", "cefService"}) {
        SCOPED_TRACE(service);
        rapidjson::Document document;
        generateV2(document, "{\"" + service + R"(":[{"address":"192.0.2.10","port":1514,"proto":"udp"}]})");
        expectTrigger(document, service);
    }
}

TEST_F(LogTriggerTest, LegacyDestinationObjectsKeepOutput)
{
    for (const string service : {"syslogService", "cefService"}) {
        SCOPED_TRACE(service);
        rapidjson::Document document;
        generateV2(document, "{\"" + service + R"(":{"address":"192.0.2.10","port":1514,"proto":"udp"}})");
        expectTrigger(document, service);
    }
}

TEST_F(LogTriggerTest, EmptyDestinationObjectsKeepDefaultOutput)
{
    rapidjson::Document document;
    generateV2(document, R"({"syslogService":{},"cefService":{}})");
    expectTrigger(document);
}

TEST_F(LogTriggerTest, DefaultDestinationPortsArePreserved)
{
    for (const string service : {"syslogService", "cefService"}) {
        for (bool array : {false, true}) {
            SCOPED_TRACE(service + (array ? " array" : " object"));
            string value = R"({"address":"192.0.2.10"})";
            rapidjson::Document document;
            generateV2(document, "{\"" + service + "\":" + (array ? "[" + value + "]" : value) + "}");
            expectTrigger(document, service, false, 514);
        }
    }
}

TEST_F(LogTriggerTest, RejectsMultipleDestinationsInsteadOfUsingTheFirst)
{
    for (const string service : {"syslogService", "cefService"}) {
        SCOPED_TRACE(service);
        expectInvalid(service, R"([{"address":"192.0.2.10"},{"address":"192.0.2.11"}])",
            "at most one destination; received 2");
    }
}

TEST_F(LogTriggerTest, RejectsWrongDestinationTypes)
{
    for (const string service : {"syslogService", "cefService"}) {
        for (const string value : {"null", "true", "42", "\"server\"", "[null]", "[false]", "[42]",
            "[\"server\"]", "[[]]"}) {
            SCOPED_TRACE(service + ": " + value);
            expectInvalid(service, value, "object");
        }
    }
}

TEST_F(LogTriggerTest, RejectsWrongServiceFieldTypes)
{
    for (const string service : {"syslogService", "cefService"}) {
        for (const string value : {R"({"address":42})", R"({"port":"514"})", R"({"proto":true})"}) {
            for (bool array : {false, true}) {
                SCOPED_TRACE(service + ": " + value);
                expectInvalid(service, array ? "[" + value + "]" : value, "invalid type");
            }
        }
    }
}

TEST_F(LogTriggerTest, BothDestinationsAreParsedWithoutLosingArchivePosition)
{
    rapidjson::Document document;
    generateV2(document, R"({"syslogService":[],"cefService":[{"address":"192.0.2.10","port":1514}]})");
    expectTrigger(document, "cefService");
    generateV2(document, R"({"cefService":[],"syslogService":[{"address":"192.0.2.10","port":1514}]})");
    expectTrigger(document, "syslogService");
}

TEST_F(LogTriggerTest, SerializesAbsentResponseCodeAsFalse)
{
    rapidjson::Document document;
    generateV2(document);
    expectTrigger(document);
}

TEST_F(LogTriggerTest, SerializesExplicitResponseCodeTrue)
{
    rapidjson::Document document;
    generateV2(document, "", "true");
    expectTrigger(document, "", true);
}

TEST_F(LogTriggerTest, SerializesExplicitResponseCodeFalse)
{
    rapidjson::Document document;
    generateV2(document, "", "false");
    expectTrigger(document);
}

TEST_F(LogTriggerTest, V1beta1KeepsResponseCodeFalse)
{
    // v1beta1 never supported this option; even an extra responseCode key must not enable it.
    const string json = R"({
        "policies":{"default":{"mode":"prevent","practices":[],"triggers":["log"]},"specific-rules":[]},
        "log-triggers":[{
            "name":"log","access-control-logging":{},
            "additional-suspicious-events-logging":{"responseCode":true},
            "appsec-logging":{},"extended-logging":{},"log-destination":{}
        }]
    })";
    rapidjson::Document document;
    generate<AppsecLinuxPolicy, ParsedRule>(document, json);
    EXPECT_FALSE(document["triggers"]["rulebase"]["log"][0]["responseCode"].GetBool());
}

} // namespace
