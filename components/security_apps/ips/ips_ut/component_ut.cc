#include "ips_comp.h"

#include <sstream>

#include "cptest.h"
#include "ips_entry.h"
#include "ips_configuration.h"
#include "ips_signatures.h"
#include "ips_metric.h"
#include "new_table_entry.h"
#include "keyword_comp.h"
#include "environment.h"
#include "mock/mock_table.h"
#include "config.h"
#include "http_manager.h"
#include "config_component.h"
#include "agent_details.h"
#include "mock/mock_logging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"
#include "encryptor.h"
#include "generic_rulebase/generic_rulebase.h"
#include "generic_rulebase/triggers_config.h"

using namespace testing;
using namespace std;

class ComponentTest : public Test
{
public:
    ComponentTest()
    {
        comp.preload();
        comp.init();
        auto err = genError("not coroutine");
        EXPECT_CALL(mainloop, getCurrentRoutineId()).WillRepeatedly(Return(Maybe<I_MainLoop::RoutineID>(err)));
    }

    ~ComponentTest()
    {
        comp.fini();
    }

    void
    loadPolicy(const string &config)
    {
        stringstream ss;
        ss << config;
        Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(ss);
    }

    void
    setTrigger()
    {
        string log_trigger(
            "{"
            "    \"context\": \"triggerId(5eaeefde6765c30010bae8b6)\","
            "    \"triggerName\": \"Logging Trigger\","
            "    \"triggerType\": \"log\","
            "    \"urlForSyslog\": \"\","
            "    \"urlForCef\": \"128.1.1.1:333\","
            "    \"acAllow\": false,"
            "    \"acDrop\": true,"
            "    \"complianceViolations\": true,"
            "    \"complianceWarnings\": true,"
            "    \"logToAgent\": true,"
            "    \"logToCloud\": true,"
            "    \"logToSyslog\": false,"
            "    \"logToCef\": true,"
            "    \"tpDetect\": true,"
            "    \"tpPrevent\": true,"
            "    \"verbosity\": \"Standard\","
            "    \"webBody\": true,"
            "    \"webHeaders\": true,"
            "    \"webRequests\": true,"
            "    \"webUrlPath\": true,"
            "    \"webUrlQuery\": true"
            "}"
        );

        stringstream ss(log_trigger);
        cereal::JSONInputArchive ar(ss);
        LogTriggerConf trigger;
        trigger.load(ar);

        setConfiguration(trigger, "rulebase", "log");
    }

    IPSComp comp;
    StrictMock<MockTable> table;
    IPSEntry entry;

    GenericRulebase generic_rulebase;
    ConfigComponent conf;
    Encryptor encryptor;
    KeywordComp keywords;
    ::Environment env;
    AgentDetails details;
    NiceMock<MockLogging> logs;
    NiceMock<MockTimeGet> time;
    NiceMock<MockMainLoop> mainloop;
    static const EventVerdict inspect;
    static const EventVerdict accept;
    static const EventVerdict drop;

    HttpHeader end_headers{Buffer(""), Buffer(""), 0, true};
};

static bool
operator ==(const EventVerdict &first, const EventVerdict &second)
{
    return first.getVerdict() == second.getVerdict();
}

const EventVerdict ComponentTest::inspect(ServiceVerdict::TRAFFIC_VERDICT_INSPECT);

const EventVerdict ComponentTest::accept(ServiceVerdict::TRAFFIC_VERDICT_ACCEPT);

const EventVerdict ComponentTest::drop(ServiceVerdict::TRAFFIC_VERDICT_DROP);

namespace IPSHelper
{
extern bool has_deobfuscation;
}

class RawMatchCapture : public Listener<IPSSignatureSubTypes::MatchEvent>
{
public:
    RawMatchCapture() { registerListener(); }
    ~RawMatchCapture() { unregisterListener(); }

    void
    upon(const IPSSignatureSubTypes::MatchEvent &event) override
    {
        actions.push_back(event.getAction());
    }

    vector<IPSSignatureSubTypes::SignatureAction> actions;
};

// Exercise the same runtime events with each of the two signature sources.
class IPSRuntimeTest : public ComponentTest, public WithParamInterface<bool>
{
public:
    IPSRuntimeTest() : saved_deobfuscation(IPSHelper::has_deobfuscation)
    {
        // Match signatures_ut's plaintext IPS setup without depending on test execution order.
        IPSHelper::has_deobfuscation = true;
    }

    ~IPSRuntimeTest()
    {
        IPSHelper::has_deobfuscation = saved_deobfuscation;
    }

    void
    loadRules(
        const vector<pair<string, string>> &rules,
        const string &action = "Prevent",
        const string &ssm = ""
    )
    {
        string protections;
        for (const auto &rule : rules) {
            stringstream detection;
            {
                cereal::JSONOutputArchive ar(detection);
                const string type = "simple";
                const vector<string> contexts{rule.first};
                ar(
                    cereal::make_nvp("type", type),
                    cereal::make_nvp("SSM", ssm),
                    cereal::make_nvp("keywords", rule.second),
                    cereal::make_nvp("context", contexts)
                );
            }
            if (!protections.empty()) protections += ",";
            protections += R"({
                "protectionMetadata": {
                    "protectionName": "Runtime regression",
                    "maintrainId": "101",
                    "severity": "Low",
                    "confidenceLevel": "Low",
                    "performanceImpact": "Medium High",
                    "lastUpdate": "20210420",
                    "tags": [],
                    "cveList": []
                },
                "detectionRules": )" + detection.str() + "}";
        }

        if (GetParam()) {
            stringstream resource_json(
                R"([{"modificationTime":"22/02/08","name":"runtime.rules","protections":[)" +
                protections + "]}]"
            );
            cereal::JSONInputArchive resource_ar(resource_json);
            SnortSignaturesResource resource;
            resource.load(resource_ar);
            ASSERT_EQ(resource.getSignatures("runtime.rules").size(), rules.size());
            setResource(resource, "IPSSnortSigs", "protections");

            stringstream policy_json(R"({
                "assetName": "asset1", "assetId": "1-1-1",
                "practiceName": "practice1", "practiceId": "2-2-2",
                "files": ["runtime.rules"], "mode": ")" + action + R"("
            })");
            cereal::JSONInputArchive policy_ar(policy_json);
            SnortSignatures signatures;
            signatures.load(policy_ar);
            ASSERT_FALSE(signatures.isEmpty());
            setConfiguration(signatures, "IPSSnortSigs", "SnortProtections");
        } else {
            stringstream resource_json("[" + protections + "]");
            cereal::JSONInputArchive resource_ar(resource_json);
            IPSSignaturesResource resource;
            resource.load(resource_ar);
            ASSERT_EQ(resource.getSignatures().size(), rules.size());
            setResource(resource, "IPS", "protections");

            stringstream policy_json(R"({
                "assetName": "asset1", "assetId": "1-1-1",
                "practiceName": "practice1", "practiceId": "2-2-2",
                "defaultAction": ")" + action + R"(", "rules": []
            })");
            cereal::JSONInputArchive policy_ar(policy_json);
            IPSSignatures signatures;
            signatures.load(policy_ar);
            ASSERT_FALSE(signatures.isEmpty());
            setConfiguration(signatures, "IPS", "IpsProtections");
        }
    }

    void
    startRequest()
    {
        EXPECT_CALL(table, createStateRValueRemoved(_, _));
        EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
        EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

        HttpTransactionData transaction(
            "HTTP/1.1", "POST", "example.test",
            IPAddr::createIPAddr("0.0.0.0").unpack(), 80, "/",
            IPAddr::createIPAddr("1.1.1.1").unpack(), 5428
        );
        EXPECT_THAT(NewHttpTransactionEvent(transaction).query(), ElementsAre(inspect));
    }

    void
    checkRawDefaultWithConfiguration(const string &json)
    {
        loadRules({{"HTTP_RAW", "data: \"D2MARKER\";"}});
        stringstream input(json);
        cereal::JSONInputArchive ar(input);
        IPSConfiguration configuration;
        configuration.load(ar);
        setConfiguration(configuration, "IPS", "IpsConfigurations");
        startRequest();
        EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
        HttpBody first(Buffer(string(1200, 'x') + "D2"), false, 0);
        EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
        EXPECT_FALSE(entry.isDrop());
        EXPECT_EQ(entry.getBuffer("HTTP_RAW"), Buffer(string(998, 'x') + "D2"));
        HttpBody last(Buffer("MARKER"), true, 1);
        EXPECT_THAT(HttpRequestBodyEvent(last, Buffer()).query(), ElementsAre(inspect));
        EXPECT_EQ(entry.getBuffer("HTTP_RAW").size(), 1000u);
        EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
    }

    void
    checkRawDetectHistory(const string &keywords, const string &ssm = "", bool fresh_ssm_prefix = false)
    {
        loadRules({{"HTTP_RAW", keywords}}, "Detect", ssm);
        setTrigger();
        RawMatchCapture capture;
        const uint extra_ssm_match = fresh_ssm_prefix ? 1 : 0;
        EXPECT_CALL(logs, sendLog(_)).Times(3 + extra_ssm_match);
        startRequest();
        EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
        HttpBody first(Buffer("D2"), false, 0);
        EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
        EXPECT_TRUE(capture.actions.empty());
        HttpBody second(Buffer("MARKER"), false, 1);
        EXPECT_THAT(HttpRequestBodyEvent(second, Buffer()).query(), ElementsAre(inspect));
        EXPECT_THAT(capture.actions, ElementsAre(IPSSignatureSubTypes::SignatureAction::DETECT));
        for (uint i = 0; i < 300; ++i) {
            HttpBody clean(Buffer("x"), false, i + 2);
            EXPECT_THAT(HttpRequestBodyEvent(clean, Buffer()).query(), ElementsAre(inspect));
        }
        EXPECT_EQ(capture.actions.size(), 1u);
        // The old occurrence is still retained when a second occurrence crosses a chunk boundary.
        HttpBody next_prefix(Buffer("D2"), false, 302);
        EXPECT_THAT(HttpRequestBodyEvent(next_prefix, Buffer()).query(), ElementsAre(inspect));
        // A fresh SSM can conservatively complete the conjunction with the old keyword chain.
        EXPECT_EQ(capture.actions.size(), 1u + extra_ssm_match);
        HttpBody next_suffix(Buffer("MARKER"), false, 303);
        EXPECT_THAT(HttpRequestBodyEvent(next_suffix, Buffer()).query(), ElementsAre(inspect));
        EXPECT_EQ(capture.actions.size(), 2u + extra_ssm_match);
        HttpBody empty(Buffer(""), false, 304);
        EXPECT_THAT(HttpRequestBodyEvent(empty, Buffer()).query(), ElementsAre(inspect));
        EXPECT_EQ(capture.actions.size(), 2u + extra_ssm_match);
        HttpBody roll_window(Buffer(string(1200, 'x')), false, 305);
        EXPECT_THAT(HttpRequestBodyEvent(roll_window, Buffer()).query(), ElementsAre(inspect));
        EXPECT_EQ(capture.actions.size(), 2u + extra_ssm_match);
        HttpBody fresh(Buffer("D2MARKER"), true, 306);
        EXPECT_THAT(HttpRequestBodyEvent(fresh, Buffer()).query(), ElementsAre(inspect));
        vector<IPSSignatureSubTypes::SignatureAction> expected_actions(
            3u + extra_ssm_match, IPSSignatureSubTypes::SignatureAction::DETECT
        );
        EXPECT_THAT(capture.actions, ElementsAreArray(expected_actions));
        EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
    }

    void
    checkRawSplitPredicate(const string &keywords)
    {
        loadRules({{"HTTP_RAW", keywords}});
        startRequest();
        EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
        EXPECT_FALSE(entry.isDrop());
        HttpBody first(Buffer("D2"), false, 0);
        EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
        EXPECT_FALSE(entry.isDrop());
        HttpBody last(Buffer("MARKER"), true, 1);
        EXPECT_THAT(HttpRequestBodyEvent(last, Buffer()).query(), ElementsAre(inspect));
        EXPECT_TRUE(entry.isDrop());
        EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
    }

    void
    checkRawZeroWidthReplay(const string &keywords)
    {
        loadRules({{"HTTP_RAW", keywords}}, "Detect");
        setTrigger();
        RawMatchCapture capture;
        EXPECT_CALL(logs, sendLog(_)).Times(::testing::AtLeast(4));
        startRequest();
        EXPECT_TRUE(capture.actions.empty());
        EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
        EXPECT_FALSE(capture.actions.empty());
        const size_t baseline = capture.actions.size();
        // Zero-width assertions have untracked input dependencies; allow replay rather than miss detection.
        for (uint i = 0; i < 3; ++i) {
            HttpBody clean(Buffer("x"), i == 2, i);
            EXPECT_THAT(HttpRequestBodyEvent(clean, Buffer()).query(), ElementsAre(inspect));
            EXPECT_EQ(capture.actions.size(), baseline + i + 1u);
        }
        EXPECT_THAT(capture.actions, Each(IPSSignatureSubTypes::SignatureAction::DETECT));
        EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
    }

    void
    checkNamedResponseHeader(const string &context, const string &field)
    {
        // The general rule keeps the old EndRequest path inspecting, isolating D02 from D01.
        loadRules({{context, "data: \"D2MARKER\";"}, {"HTTP_RESPONSE_HEADER", "data: \"NEVER_MATCH\";"}});
        startRequest();
        EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
        EXPECT_THAT(EndRequestEvent().query(), ElementsAre(inspect));
        EXPECT_EQ(entry.respond(ParsedContext(Buffer("D2MARKER"), context, 0)), ParsedContextReply::DROP);

        HttpHeader unrelated(Buffer("X-Other"), Buffer("D2MARKER"), 0, false);
        EXPECT_THAT(HttpResponseHeaderEvent(unrelated).query(), ElementsAre(inspect));
        HttpHeader clean(Buffer(field), Buffer("clean"), 1, false);
        EXPECT_THAT(HttpResponseHeaderEvent(clean).query(), ElementsAre(inspect));
        HttpHeader matching(Buffer(field), Buffer("D2MARKER"), 2, true);
        EXPECT_THAT(HttpResponseHeaderEvent(matching).query(), ElementsAre(drop));
    }

private:
    const bool saved_deobfuscation;
};

INSTANTIATE_TEST_CASE_P(SignatureSources, IPSRuntimeTest, Values(false, true));

TEST_P(IPSRuntimeTest, response_code_only_stays_inspecting_at_end_request)
{
    loadRules({{"HTTP_RESPONSE_CODE", "data: \"403\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(inspect));
}

TEST_P(IPSRuntimeTest, named_response_header_only_stays_inspecting_at_end_request)
{
    loadRules({{"HTTP_RESPONSE_HEADER_SET-COOKIE", "data: \"D2MARKER\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(inspect));
}

TEST_P(IPSRuntimeTest, response_cookie_only_stays_inspecting_at_end_request)
{
    loadRules({{"HTTP_RESPONSE_HEADER_COOKIE", "data: \"D2MARKER\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(inspect));
}

TEST_P(IPSRuntimeTest, request_only_rule_still_accepts_at_end_request)
{
    loadRules({{"HTTP_REQUEST_HEADER_X-AUDIT", "data: \"D2MARKER\";"}});
    startRequest();
    HttpHeader header(Buffer("x-AuDiT"), Buffer("clean"), 0, true);
    EXPECT_THAT(HttpRequestHeaderEvent(header).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_P(IPSRuntimeTest, named_request_header_still_drops)
{
    loadRules({{"HTTP_REQUEST_HEADER_X-AUDIT", "data: \"D2MARKER\";"}});
    startRequest();
    HttpHeader header(Buffer("x-AuDiT"), Buffer("D2MARKER"), 0, true);
    EXPECT_THAT(HttpRequestHeaderEvent(header).query(), ElementsAre(drop));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, named_response_header_receives_value)
{
    checkNamedResponseHeader("HTTP_RESPONSE_HEADER_X-AUDIT", "x-AuDiT");
}

TEST_P(IPSRuntimeTest, named_set_cookie_receives_value)
{
    checkNamedResponseHeader("HTTP_RESPONSE_HEADER_SET-COOKIE", "sEt-CoOkIe");
}

TEST_P(IPSRuntimeTest, snort_response_cookie_receives_set_cookie_value)
{
    checkNamedResponseHeader("HTTP_RESPONSE_HEADER_COOKIE", "sEt-CoOkIe");
}

TEST_P(IPSRuntimeTest, general_response_header_still_drops)
{
    loadRules({{"HTTP_RESPONSE_HEADER", "data: \"D2MARKER\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(inspect));
    HttpHeader header(Buffer("X-Audit"), Buffer("D2MARKER"), 0, true);
    EXPECT_THAT(HttpResponseHeaderEvent(header).query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, raw_content_in_one_body_chunk_drops)
{
    loadRules({{"HTTP_RAW", "data: \"D2MARKER\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    HttpBody body(Buffer("D2MARKER"), true, 0);
    EXPECT_THAT(HttpRequestBodyEvent(body, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, raw_content_across_body_chunks_drops)
{
    loadRules({{"HTTP_RAW", "data: \"D2MARKER\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    HttpBody first(Buffer("D2"), false, 0);
    EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
    EXPECT_FALSE(entry.isDrop());
    HttpBody last(Buffer("MARKER"), true, 1);
    EXPECT_THAT(HttpRequestBodyEvent(last, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, raw_content_across_header_and_body_drops)
{
    loadRules({{"HTTP_RAW", "data: \"D2|0d 0a 0d 0a|MARKER\";"}});
    startRequest();
    HttpHeader header(Buffer("X-Audit"), Buffer("D2"), 0, true);
    EXPECT_THAT(HttpRequestHeaderEvent(header).query(), ElementsAre(inspect));
    EXPECT_FALSE(entry.isDrop());
    HttpBody body(Buffer("MARKER"), true, 0);
    EXPECT_THAT(HttpRequestBodyEvent(body, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, raw_headers_have_exactly_one_terminating_blank_line)
{
    loadRules({{"HTTP_RAW", "data: \"D2|0d 0a|MARKER\";"}});
    startRequest();
    HttpHeader first(Buffer("X-First"), Buffer("clean"), 0, false);
    EXPECT_THAT(HttpRequestHeaderEvent(first).query(), ElementsAre(inspect));
    HttpHeader last(Buffer("X-Audit"), Buffer("D2"), 1, true);
    EXPECT_THAT(HttpRequestHeaderEvent(last).query(), ElementsAre(inspect));
    const string headers = "POST / HTTP/1.1\r\nX-First: clean\r\nX-Audit: D2\r\n\r\n";
    EXPECT_EQ(entry.getBuffer("HTTP_RAW"), Buffer(headers));
    HttpBody body(Buffer("MARKER"), true, 0);
    EXPECT_THAT(HttpRequestBodyEvent(body, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(entry.getBuffer("HTTP_RAW"), Buffer(headers + "MARKER"));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_P(IPSRuntimeTest, raw_empty_headers_have_only_the_terminating_blank_line)
{
    loadRules({{"HTTP_RAW", "data: \"NEVER_MATCH\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_EQ(entry.getBuffer("HTTP_RAW"), Buffer("POST / HTTP/1.1\r\n\r\n"));
}

TEST_P(IPSRuntimeTest, raw_history_is_bounded_and_preserves_tail)
{
    loadRules({{"HTTP_RAW", "data: \"D2MARKER\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    HttpBody first(Buffer(string(1200, 'x') + "D2"), false, 0);
    EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
    EXPECT_FALSE(entry.isDrop());
    EXPECT_EQ(entry.getBuffer("HTTP_RAW"), Buffer(string(998, 'x') + "D2"));
    HttpBody last(Buffer("MARKER"), true, 1);
    EXPECT_THAT(HttpRequestBodyEvent(last, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(entry.getBuffer("HTTP_RAW").size(), 1000u);
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, raw_relative_offsets_share_the_history_window)
{
    loadRules({{"HTTP_RAW", "data: \"D2\"; data: \"MARKER\", relative, depth 6;"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    HttpBody first(Buffer("D2"), false, 0);
    EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
    EXPECT_FALSE(entry.isDrop());
    HttpBody last(Buffer("MARKER"), true, 1);
    EXPECT_THAT(HttpRequestBodyEvent(last, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, omitted_raw_configuration_uses_bounded_default)
{
    checkRawDefaultWithConfiguration(R"({
        "contextsConfiguration": [{"name": "HTTP_RESPONSE_CODE", "type": "keep"}]
    })");
}

TEST_P(IPSRuntimeTest, empty_context_configuration_uses_bounded_raw_default)
{
    checkRawDefaultWithConfiguration(R"({"contextsConfiguration": []})");
}

TEST_P(IPSRuntimeTest, raw_detect_does_not_replay_overlap_matches)
{
    checkRawDetectHistory("data: \"D2MARKER\";");
}

TEST_P(IPSRuntimeTest, raw_relative_detect_finds_new_match_after_old_overlap_match)
{
    checkRawDetectHistory("data: \"D2\"; data: \"MARKER\", relative, depth 6;");
}

TEST_P(IPSRuntimeTest, raw_pcre_detect_finds_new_match_after_old_overlap_match)
{
    checkRawDetectHistory("pcre: \"/D2MARKER/\";");
}

TEST_P(IPSRuntimeTest, raw_ssm_prefilter_preserves_relative_match_into_new_data)
{
    checkRawDetectHistory("data: \"D2\"; data: \"MARKER\", relative, depth 6;", "D2", true);
}

TEST_P(IPSRuntimeTest, raw_relative_length_first_matches_when_new_bytes_arrive)
{
    checkRawSplitPredicate("data: \"D2\"; length: 6, relative, min;");
}

TEST_P(IPSRuntimeTest, raw_relative_length_allows_old_terminal_literal)
{
    checkRawSplitPredicate("data: \"D2\"; length: 6, relative, min; data: \"POST\", caret;");
}

TEST_P(IPSRuntimeTest, raw_pcre_lookahead_first_matches_when_new_bytes_arrive)
{
    checkRawSplitPredicate("pcre: \"/D2(?=MARKER)/\";");
}

TEST_P(IPSRuntimeTest, raw_pcre_lookahead_allows_old_terminal_literal)
{
    checkRawSplitPredicate("pcre: \"/D2(?=MARKER)/\"; data: \"POST\", caret;");
}

TEST_P(IPSRuntimeTest, raw_fresh_ssm_completes_old_caret_keyword)
{
    loadRules({{"HTTP_RAW", "data: \"POST\", caret;"}}, "Prevent", "ATTACK");
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_FALSE(entry.isDrop());
    HttpBody body(Buffer("ATTACK"), true, 0);
    EXPECT_THAT(HttpRequestBodyEvent(body, Buffer()).query(), ElementsAre(inspect));
    EXPECT_TRUE(entry.isDrop());
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_P(IPSRuntimeTest, raw_fresh_split_ssm_completes_old_keyword_without_clean_chunk_replay)
{
    loadRules({{"HTTP_RAW", "data: \"POST\", caret;"}}, "Detect", "ATTACK");
    setTrigger();
    RawMatchCapture capture;
    EXPECT_CALL(logs, sendLog(_)).Times(2);
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_TRUE(capture.actions.empty());
    for (uint i = 0; i < 2; ++i) {
        HttpBody prefix(Buffer("AT"), false, i * 3);
        EXPECT_THAT(HttpRequestBodyEvent(prefix, Buffer()).query(), ElementsAre(inspect));
        EXPECT_EQ(capture.actions.size(), i);
        HttpBody suffix(Buffer("TACK"), false, i * 3 + 1);
        EXPECT_THAT(HttpRequestBodyEvent(suffix, Buffer()).query(), ElementsAre(inspect));
        EXPECT_EQ(capture.actions.size(), i + 1u);
        HttpBody clean(Buffer("x"), i == 1, i * 3 + 2);
        EXPECT_THAT(HttpRequestBodyEvent(clean, Buffer()).query(), ElementsAre(inspect));
        EXPECT_EQ(capture.actions.size(), i + 1u);
    }
    EXPECT_THAT(capture.actions, ElementsAre(
        IPSSignatureSubTypes::SignatureAction::DETECT,
        IPSSignatureSubTypes::SignatureAction::DETECT
    ));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_P(IPSRuntimeTest, raw_zero_width_pcre_conservatively_allows_replay)
{
    checkRawZeroWidthReplay("pcre: \"/(?=POST)/\";");
}

TEST_P(IPSRuntimeTest, raw_zero_width_pcre_disables_suppression_after_old_literal)
{
    checkRawZeroWidthReplay("data: \"POST\", caret; pcre: \"/(?=POST)/\";");
}

TEST_P(IPSRuntimeTest, raw_detect_preserves_new_match_before_later_absolute_old_match)
{
    loadRules({{"HTTP_RAW", "data: \"D2\"; data: \"MARKER\", relative, depth 6; data: \"POST\", caret;"}}, "Detect");
    setTrigger();
    RawMatchCapture capture;
    EXPECT_CALL(logs, sendLog(_)).Times(2);
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    HttpBody first(Buffer("D2"), false, 0);
    EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
    EXPECT_TRUE(capture.actions.empty());
    HttpBody last(Buffer("MARKER"), false, 1);
    EXPECT_THAT(HttpRequestBodyEvent(last, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(capture.actions.size(), 1u);
    HttpBody clean(Buffer("x"), false, 2);
    EXPECT_THAT(HttpRequestBodyEvent(clean, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(capture.actions, ElementsAre(IPSSignatureSubTypes::SignatureAction::DETECT));
    // Backtrack past the old complete chain even though the final absolute literal is old.
    HttpBody next_prefix(Buffer("D2"), false, 3);
    EXPECT_THAT(HttpRequestBodyEvent(next_prefix, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(capture.actions.size(), 1u);
    HttpBody next_suffix(Buffer("MARKER"), true, 4);
    EXPECT_THAT(HttpRequestBodyEvent(next_suffix, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(capture.actions, ElementsAre(
        IPSSignatureSubTypes::SignatureAction::DETECT,
        IPSSignatureSubTypes::SignatureAction::DETECT
    ));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_P(IPSRuntimeTest, raw_detect_finds_self_overlapping_occurrence_into_new_data)
{
    loadRules({{"HTTP_RAW", "data: \"ABAB\"; length: 0, min;"}}, "Detect");
    setTrigger();
    RawMatchCapture capture;
    EXPECT_CALL(logs, sendLog(_)).Times(2);
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    HttpBody first(Buffer("ABAB"), false, 0);
    EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(capture.actions.size(), 1u);
    HttpBody overlapping(Buffer("AB"), false, 1);
    EXPECT_THAT(HttpRequestBodyEvent(overlapping, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(capture.actions.size(), 2u);
    HttpBody clean(Buffer("x"), true, 2);
    EXPECT_THAT(HttpRequestBodyEvent(clean, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(capture.actions, ElementsAre(
        IPSSignatureSubTypes::SignatureAction::DETECT,
        IPSSignatureSubTypes::SignatureAction::DETECT
    ));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_P(IPSRuntimeTest, raw_untracked_length_preserves_self_overlapping_occurrences)
{
    loadRules({{"HTTP_RAW", "data: \"ABAB\"; length: 0, relative, exact;"}}, "Detect");
    setTrigger();
    RawMatchCapture capture;
    EXPECT_CALL(logs, sendLog(_)).Times(2);
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_TRUE(capture.actions.empty());
    HttpBody first(Buffer("ABAB"), false, 0);
    EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(capture.actions.size(), 1u);
    HttpBody overlapping(Buffer("AB"), false, 1);
    EXPECT_THAT(HttpRequestBodyEvent(overlapping, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(capture.actions.size(), 2u);
    HttpBody clean(Buffer("x"), true, 2);
    EXPECT_THAT(HttpRequestBodyEvent(clean, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(capture.actions, ElementsAre(
        IPSSignatureSubTypes::SignatureAction::DETECT,
        IPSSignatureSubTypes::SignatureAction::DETECT
    ));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_P(IPSRuntimeTest, raw_ssm_detect_does_not_replay_overlap_matches)
{
    checkRawDetectHistory("", "D2MARKER");
}

TEST_P(IPSRuntimeTest, explicit_raw_normal_configuration_is_preserved)
{
    loadRules({{"HTTP_RAW", "data: \"D2MARKER\";"}});
    stringstream input(R"({"contextsConfiguration": [{"name": "HTTP_RAW", "type": "normal"}]})");
    cereal::JSONInputArchive ar(input);
    IPSConfiguration configuration;
    configuration.load(ar);
    setConfiguration(configuration, "IPS", "IpsConfigurations");
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    HttpBody first(Buffer("D2"), false, 0);
    EXPECT_THAT(HttpRequestBodyEvent(first, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(entry.getBuffer("HTTP_RAW").size(), 0u);
    HttpBody last(Buffer("MARKER"), true, 1);
    EXPECT_THAT(HttpRequestBodyEvent(last, Buffer()).query(), ElementsAre(inspect));
    EXPECT_EQ(entry.getBuffer("HTTP_RAW").size(), 0u);
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_P(IPSRuntimeTest, response_code_rule_matches_decimal_status)
{
    // Keep the original EndRequest inspecting so this checks D04 independently of D01.
    loadRules({{"HTTP_RESPONSE_CODE", "data: \"403\";"}, {"HTTP_RESPONSE_HEADER", "data: \"NEVER_MATCH\";"}});
    startRequest();
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(inspect));
    EXPECT_THAT(ResponseCodeEvent(200).query(), ElementsAre(inspect));
    EXPECT_THAT(ResponseCodeEvent(403).query(), ElementsAre(drop));
}

class ResponseCodeContextCapture : public Listener<ParsedContext>
{
public:
    ResponseCodeContextCapture() { registerListener(); }
    ~ResponseCodeContextCapture() { unregisterListener(); }

    void upon(const ParsedContext &) override {}
    string getListenerName() const override { return "response code capture"; }

    ParsedContextReply
    respond(const ParsedContext &context) override
    {
        if (context.getName() == "HTTP_RESPONSE_CODE") values.push_back(context.getBuffer());
        return ParsedContextReply::ACCEPT;
    }

    vector<Buffer> values;
};

TEST_F(ComponentTest, response_code_context_contains_only_decimal_text)
{
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    ResponseCodeContextCapture capture;
    EXPECT_THAT(ResponseCodeEvent(403).query(), ElementsAre(inspect));
    EXPECT_THAT(ResponseCodeEvent(200).query(), ElementsAre(inspect));
    EXPECT_THAT(capture.values, ElementsAre(Buffer("403"), Buffer("200")));
}

TEST_F(ComponentTest, check_init_fini_do_not_crush)
{
}

TEST_F(ComponentTest, new_table_entry_with_empty_configuration)
{
    NewTableEntry().notify();
}

TEST_F(ComponentTest, new_table_entry_with_configuration)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"configurations\": ["
                    "{"
                        "\"context\": \"\","
                        "\"contextsConfiguration\": ["
                            "{"
                                "\"type\": \"keep\","
                                "\"name\": \"HTTP_REQUEST_BODY\""
                            "}"
                        "]"
                    "}"
                "],"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"ddd\\\";\","
                            "\"context\": [\"HTTP_REQUEST_BODY\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";

    loadPolicy(config);
    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillOnce(Return(&entry));
    NewTableEntry().notify();
}

TEST_F(ComponentTest, events)
{
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));
    IPSEntry entry;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));

    HttpTransactionData transaction;
    EXPECT_THAT(NewHttpTransactionEvent(transaction).query(), ElementsAre(accept));
    HttpHeader header_req(Buffer("key"), Buffer("val"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req).query(), ElementsAre(inspect));
    HttpBody body_req(Buffer("data"), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));

    EXPECT_THAT(ResponseCodeEvent(200).query(), ElementsAre(inspect));
    HttpHeader header_res(Buffer("key"), Buffer("val"), 2);
    EXPECT_THAT(HttpResponseHeaderEvent(header_res).query(), ElementsAre(inspect));
    HttpBody body_res(Buffer("data"), true, 0);
    EXPECT_THAT(HttpResponseBodyEvent(body_res, Buffer()).query(), ElementsAre(accept));
    EXPECT_THAT(EndTransactionEvent().performNamedQuery(), ElementsAre(Pair("ips application", accept)));
}

TEST_F(ComponentTest, check_url_decoding)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"d d\\\";\","
                            "\"context\": [\"HTTP_COMPLETE_URL_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(drop));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_F(ComponentTest, check_query)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(drop));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));
}

TEST_F(ComponentTest, check_query_detect_mode)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"d d\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Detect\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillOnce(Return(&entry));

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(EndTransactionEvent().query(), ElementsAre(accept));
}

TEST_F(ComponentTest, check_query_inactive_mode)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Prevent\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Inactive\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(accept));
}

TEST_F(ComponentTest, check_query_silent_mode)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"silent\": true,"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Prevent\","
                        "\"rules\": []"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    EXPECT_THAT(HttpRequestHeaderEvent(end_headers).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(accept));
}

TEST_F(ComponentTest, check_filtering_by_year)
{
    string config =
        "{"
            "\"IPS\": {"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [ \"ggg\", \"Threat_Year_2014\", \"hhh\" ],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"g=#\\\";\","
                            "\"context\": [\"HTTP_QUERY_DECODED\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"defaultAction\": \"Prevent\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Inactive\","
                                "\"protectionsFromYear\": 2013"
                            "}"
                        "]"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    HttpTransactionData new_transaction(
        "1.1",
        "GET",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(accept));
}

TEST_F(ComponentTest, log_fields)
{
    generic_rulebase.preload();
    generic_rulebase.init();
    string config =
        "{"
            "\"IPS\": {"
                "\"Max Field Size\": ["
                    "{"
                        "\"value\": 25"
                    "}"
                "],"
                "\"protections\": ["
                    "{"
                        "\"protectionMetadata\": {"
                            "\"protectionName\": \"Test\","
                            "\"maintrainId\": \"101\","
                            "\"severity\": \"Low\","
                            "\"confidenceLevel\": \"Low\","
                            "\"performanceImpact\": \"Medium High\","
                            "\"lastUpdate\": \"20210420\","
                            "\"tags\": [],"
                            "\"cveList\": []"
                        "},"
                        "\"detectionRules\": {"
                            "\"type\": \"simple\","
                            "\"SSM\": \"\","
                            "\"keywords\": \"data: \\\"ddd\\\";\","
                            "\"context\": [\"HTTP_REQUEST_BODY\"]"
                        "}"
                    "}"
                "],"
                "\"IpsProtections\": ["
                    "{"
                        "\"context\": \"\","
                        "\"ruleName\": \"rule1\","
                        "\"assetName\": \"asset1\","
                        "\"assetId\": \"1-1-1\","
                        "\"practiceId\": \"2-2-2\","
                        "\"practiceName\": \"practice1\","
                        "\"triggers\": \"5eaeefde6765c30010bae8b6\","
                        "\"exceptions\": \"\","
                        "\"defaultAction\": \"Detect\","
                        "\"rules\": ["
                            "{"
                                "\"action\": \"Prevent\","
                                "\"severityLevel\": \"Low or above\","
                                "\"performanceImpact\": \"High or lower\","
                                "\"confidenceLevel\": \"Low\""
                            "}"
                        "]"
                    "}"
                "]"
            "},"
            "\"rulebase\": {"
                "\"log\": ["
                    "{"
                        "\"context\": \"triggerId(5eaeefde6765c30010bae8b6)\","
                        "\"triggerName\": \"Logging Trigger\","
                        "\"triggerType\": \"log\","
                        "\"urlForSyslog\": \"\","
                        "\"urlForCef\": \"128.1.1.1:333\","
                        "\"acAllow\": false,"
                        "\"acDrop\": true,"
                        "\"complianceViolations\": true,"
                        "\"complianceWarnings\": true,"
                        "\"logToAgent\": true,"
                        "\"logToCloud\": true,"
                        "\"logToSyslog\": false,"
                        "\"logToCef\": true,"
                        "\"tpDetect\": true,"
                        "\"tpPrevent\": true,"
                        "\"verbosity\": \"Standard\","
                        "\"webBody\": true,"
                        "\"webHeaders\": true,"
                        "\"webRequests\": true,"
                        "\"webUrlPath\": true,"
                        "\"webUrlQuery\": true"
                    "}"
                "]"
            "}"
        "}";
    loadPolicy(config);

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    Report report;
    EXPECT_CALL(logs, sendLog(_)).WillOnce(SaveArg<0>(&report));

    HttpTransactionData new_transaction(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    HttpHeader header_req1(Buffer("key1"), Buffer("val1"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req1).query(), ElementsAre(inspect));
    HttpHeader header_req2(Buffer("key2"), Buffer("val2"), 2);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req2).query(), ElementsAre(inspect));
    HttpHeader header_req3(Buffer("key3"), Buffer("val3"), 3);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req3).query(), ElementsAre(inspect));
    string body_str("data: ddd");
    HttpBody body_req(Buffer(body_str), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));

    EXPECT_THAT(report.getSyslog(), HasSubstr("httpRequestHeaders=\"key1: val1, key2: val2\""));
    EXPECT_THAT(report.getSyslog(), HasSubstr("httpRequestBody=\"" + body_str + "\""));
    EXPECT_THAT(report.getSyslog(), HasSubstr("signatureVersion=\"20210420\""));
}

TEST_F(ComponentTest, log_field_httpRequestHeader)
{
    string config =
        "{"
        "\"IPS\": {"
        "\"Max Field Size\": ["
        "{"
        "\"value\": 25"
        "}"
        "],"
        "\"protections\": ["
        "{"
        "\"protectionMetadata\": {"
        "\"protectionName\": \"Test\","
        "\"maintrainId\": \"101\","
        "\"severity\": \"Low\","
        "\"confidenceLevel\": \"Low\","
        "\"performanceImpact\": \"Medium High\","
        "\"lastUpdate\": \"20210420\","
        "\"tags\": [],"
        "\"cveList\": []"
        "},"
        "\"detectionRules\": {"
        "\"type\": \"simple\","
        "\"SSM\": \"\","
        "\"keywords\": \"data: \\\"ddd\\\";\","
        "\"context\": [\"HTTP_REQUEST_BODY\"]"
        "}"
        "}"
        "],"
        "\"IpsProtections\": ["
        "{"
        "\"context\": \"\","
        "\"ruleName\": \"rule1\","
        "\"assetName\": \"asset1\","
        "\"assetId\": \"1-1-1\","
        "\"practiceId\": \"2-2-2\","
        "\"practiceName\": \"practice1\","
        "\"defaultAction\": \"Detect\","
        "\"rules\": ["
        "{"
        "\"action\": \"Prevent\","
        "\"severityLevel\": \"Low or above\","
        "\"performanceImpact\": \"High or lower\","
        "\"confidenceLevel\": \"Low\""
        "}"
        "]"
        "}"
        "]"
        "}"
        "}";
    loadPolicy(config);
    setTrigger();

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    IPSEntry entry;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    Report report;
    EXPECT_CALL(logs, sendLog(_)).WillOnce(SaveArg<0>(&report));

    HttpTransactionData new_transaction(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    HttpHeader header_req1(Buffer("key1"), Buffer("val1"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req1).query(), ElementsAre(inspect));
    HttpBody body_req(Buffer("data: ddd"), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));

    EXPECT_THAT(report.getSyslog(), HasSubstr("httpRequestHeaders=\"key1: val1\""));

    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    IPSEntry entry1;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry1));
    Report report1;
    EXPECT_CALL(logs, sendLog(_)).WillOnce(SaveArg<0>(&report1));

    HttpTransactionData new_transaction2(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "d%20d?g=%23",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction2).query(), ElementsAre(inspect));
    HttpHeader header_req2(Buffer("key2"), Buffer("val2"), 1);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req2).query(), ElementsAre(inspect));

    HttpBody body_req2(Buffer("data: ddd"), 0, true);
    EXPECT_THAT(HttpRequestBodyEvent(body_req2, Buffer()).query(), ElementsAre(inspect));
    EXPECT_THAT(EndRequestEvent().query(), ElementsAre(drop));

    EXPECT_THAT(report1.getSyslog(), HasSubstr("httpRequestHeaders=\"key2: val2\""));
}

TEST_F(ComponentTest, prxeem_exception_bug)
{
    generic_rulebase.preload();
    generic_rulebase.init();
    string config =
        "{"
        "    \"IPS\": {"
        "        \"protections\": ["
        "            {"
        "                \"protectionMetadata\": {"
        "                    \"protectionName\": \"Null HTTP Encodings\","
        "                    \"maintrainId\": \"101\","
        "                    \"severity\": \"Low\","
        "                    \"confidenceLevel\": \"Low\","
        "                    \"performanceImpact\": \"Medium High\","
        "                    \"lastUpdate\": \"20210420\","
        "                    \"tags\": [],"
        "                    \"cveList\": []"
        "                },"
        "                \"detectionRules\": {"
        "                    \"type\": \"simple\","
        "                    \"SSM\": \"\","
        "                    \"keywords\": \"data: \\\"|25|00\\\"; data: \\\"?\\\";\","
        "                    \"context\": [\"HTTP_COMPLETE_URL_ENCODED\"]"
        "                }"
        "            }"
        "        ],"
        "        \"IpsProtections\": ["
        "            {"
        "                \"context\": \"\","
        "                \"ruleName\": \"rule1\","
        "                \"assetName\": \"asset1\","
        "                \"assetId\": \"1-1-1\","
        "                \"practiceId\": \"2-2-2\","
        "                \"practiceName\": \"practice1\","
        "                \"defaultAction\": \"Prevent\","
        "                \"triggers\": \"\","
        "                \"exceptions\": \"6c3867be-4da5-42c2-93dc-8f509a764004\","
        "                \"rules\": []"
        "            }"
        "        ]"
        "    },"
        "    \"rulebase\": {"
        "        \"rulesConfig\": ["
        "            {"
        "                \"context\": \"All()\","
        "                \"priority\": 1,"
        "                \"ruleId\": \"5eaef0726765c30010bae8bb\","
        "                \"ruleName\": \"Acme web API\","
        "                \"assetId\": \"5e243effd858007660b758ad\","
        "                \"assetName\": \"Acme Power API\","
        "                \"parameters\": ["
        "                    {"
        "                       \"parameterId\": \"6c3867be-4da5-42c2-93dc-8f509a764003\","
        "                       \"parameterType\": \"exceptions\","
        "                       \"parameterName\": \"exception\""
        "                    },"
        "                    {"
        "                       \"parameterId\": \"6c3867be-4da5-42c2-93dc-8f509a764004\","
        "                       \"parameterType\": \"exceptions\","
        "                       \"parameterName\": \"exception\""
        "                    }"
        "                ],"
        "                \"zoneId\": \"\","
        "                \"zoneName\": \"\""
        "            }"
        "        ],"
        "        \"exception\": ["
        "            {"
        "                \"context\": \"parameterId(6c3867be-4da5-42c2-93dc-8f509a764004)\","
        "                \"match\": {"
        "                   \"type\": \"operator\","
        "                   \"op\": \"and\","
        "                   \"items\": [{"
        "                       \"type\": \"condition\","
        "                       \"op\": \"equals\","
        "                       \"key\": \"url\","
        "                       \"value\": [\"(/en|/de)?/admin/helpdesk/dashboard/operator/advanced_search.*\"]"
        "                   }, {"
        "                       \"type\": \"operator\","
        "                       \"op\": \"or\","
        "                       \"items\": [{"
        "                           \"type\": \"condition\","
        "                           \"op\": \"equals\","
        "                           \"key\": \"protectionName\","
        "                           \"value\": [\"Null HTTP Encodings\"]"
        "                       }, {"
        "                           \"type\": \"condition\","
        "                           \"op\": \"equals\","
        "                           \"key\": \"parameterName\","
        "                           \"value\": [\"op\\\\.submit\\\\.reset\"]"
        "                       }]"
        "                    }]"
        "                },"
        "                \"behavior\": {"
        "                    \"key\": \"action\","
        "                    \"value\": \"accept\""
        "                }"
        "            }"
        "        ]"
        "    }"
        "}";
    loadPolicy(config);


    EXPECT_CALL(table, createStateRValueRemoved(_, _));
    IPSEntry entry;
    EXPECT_CALL(table, getState(_)).WillRepeatedly(Return(&entry));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(Return(true));

    HttpTransactionData new_transaction(
        "1.1",
        "POST",
        "ffff",
        IPAddr::createIPAddr("0.0.0.0").unpack(),
        80,
        "/admin/helpdesk/dashboard/operator/advanced_search?order=created&stuff=%00",
        IPAddr::createIPAddr("1.1.1.1").unpack(),
        5428
    );

    EXPECT_THAT(NewHttpTransactionEvent(new_transaction).query(), ElementsAre(inspect));
    HttpHeader header_req1(Buffer("key1"), Buffer("val1"), 0, true);
    EXPECT_THAT(HttpRequestHeaderEvent(header_req1).query(), ElementsAre(inspect));
}
