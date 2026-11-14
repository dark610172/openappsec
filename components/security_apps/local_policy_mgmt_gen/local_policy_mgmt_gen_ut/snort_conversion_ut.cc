#include "cptest.h"
#include "config_component.h"
#include "mock/mock_shell_cmd.h"
#include "policy_maker_utils.h"

#include <regex>
#include <set>
#include <sstream>
#include <cstdio>
#include <fstream>

#include "cereal/external/rapidjson/document.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

namespace
{

class MockSnortEnvDetails : public Singleton::Provide<I_EnvDetails>::From<MockProvider<I_EnvDetails>>
{
public:
    MOCK_METHOD0(getEnvType, EnvType());
    MOCK_METHOD0(getToken, string());
    MOCK_METHOD0(getNameSpace, string());
};

// The shared MockOrchestrationTools predates several methods in the current interface.
class MockSnortTools : public Singleton::Provide<I_OrchestrationTools>::From<MockProvider<I_OrchestrationTools>>
{
public:
    using Packages = map<string, Package>;
    using JsonParts = map<string, string>;
    MOCK_CONST_METHOD2(packagesToJsonFile, bool(const Packages &, const string &));
    Maybe<Packages>
    loadPackagesFromJson(const string &) const override
    {
        ADD_FAILURE() << "Unexpected package loading";
        return genError("Unexpected package loading");
    }

    Maybe<JsonParts>
    jsonObjectSplitter(const string &, const string &, const string &) const override
    {
        ADD_FAILURE() << "Unexpected JSON splitting";
        return genError("Unexpected JSON splitting");
    }

    MOCK_CONST_METHOD1(isNonEmptyFile, bool(const string &));
    MOCK_CONST_METHOD1(fileStreamWrapper, shared_ptr<ifstream>(const string &));
    MOCK_CONST_METHOD1(readFile, Maybe<string>(const string &));
    MOCK_CONST_METHOD3(writeFile, bool(const string &, const string &, bool));
    MOCK_CONST_METHOD1(removeFile, bool(const string &));
    MOCK_CONST_METHOD2(removeDirectory, bool(const string &, bool));
    MOCK_CONST_METHOD3(deleteVirtualTenantProfileFiles, void(const string &, const string &, const string &));
    MOCK_CONST_METHOD2(copyFile, bool(const string &, const string &));
    MOCK_CONST_METHOD1(doesFileExist, bool(const string &));
    MOCK_CONST_METHOD0(setClusterId, void());
    MOCK_CONST_METHOD3(fillKeyInJson, void(const string &, const string &, const string &));
    MOCK_CONST_METHOD1(createDirectory, bool(const string &));
    MOCK_CONST_METHOD1(doesDirectoryExist, bool(const string &));
    MOCK_CONST_METHOD1(executeCmd, bool(const string &));
    MOCK_CONST_METHOD1(loadTenantsFromDir, void(const string &));
    MOCK_CONST_METHOD1(base64Encode, string(const string &));
    MOCK_CONST_METHOD1(base64Decode, string(const string &));
    MOCK_CONST_METHOD2(calculateChecksum, Maybe<string>(Package::ChecksumTypes, const string &));
};

class SnortConversionTest : public Test
{
protected:
    void
    SetUp() override
    {
        EXPECT_CALL(env, getEnvType()).WillRepeatedly(Return(EnvType::LINUX));
        environment.preload();
        environment.init();
        config.preload();
        Debug::setUnitTestFlag(D_LOCAL_POLICY, Debug::DebugLevel::WARNING);
        Debug::setNewDefaultStdout(&debug_output);
    }

    void
    TearDown() override
    {
        Debug::setNewDefaultStdout(&cout);
    }

    string
    policyJson(const string &file_name, bool with_identifiers = false)
    {
        // Test paths contain no JSON escapes; shell quoting is asserted separately.
        return string(R"({
            "apiVersion": "v1beta2",
            "policies": {
                "default": {
                    "mode": "prevent",
                    "threatPreventionPractices": ["snort"],)")
            + (with_identifiers ? R"(
                    "sourceIdentifiers": "rejected-source",
                    "trustedSources": "rejected-trusted",)" : "") + R"(
                    "accessControlPractices": []
                },
                "specificRules": []
            },
            "threatPreventionPractices": [{
                "name": "snort",
                "practiceMode": "prevent",
                "fileSecurity": {"overrideMode": "inactive"},
                "intrusionPrevention": {"overrideMode": "inactive"},
                "snortSignatures": {"overrideMode": "prevent", "files": [")"
            + file_name + R"("]},
                "webAttacks": {"overrideMode": "inactive"},
                "antiBot": {"overrideMode": "inactive"},
                "schemaValidation": {"overrideMode": "inactive"}
            }],
            )" + (with_identifiers ? R"(
            "sourcesIdentifiers": [{
                "name": "rejected-source",
                "sourcesIdentifiers": [{"identifier": "headerkey", "value": ["X-Rejected-Source"]}]
            }],
            "trustedSources": [{
                "name": "rejected-trusted",
                "minNumOfSources": 3,
                "sourcesIdentifiers": ["rejected-client"]
            }],)" : "") + R"(
            "autoUpgrade": {"mode": "manual"}
        })";
    }

    V1beta2AppsecLinuxPolicy
    loadPolicy(const string &file_name, bool with_identifiers = false)
    {
        istringstream input(policyJson(file_name, with_identifiers));
        cereal::JSONInputArchive archive(input);
        V1beta2AppsecLinuxPolicy policy;
        policy.serialize(archive);
        return policy;
    }

    void
    expectConversion(const string &file_name, const string &quoted_input, const string &basename, Maybe<int> result = 0)
    {
        string prefix = "python3 '/etc/cp/scripts/snort_to_ips_local.py' " + quoted_input + " ";
        EXPECT_CALL(shell, getExecReturnCode(StartsWith(prefix), _, _))
            .WillOnce(Invoke([=](const string &cmd, uint, bool) -> Maybe<int> {
                smatch paths;
                string args = cmd.substr(prefix.size());
                if (!regex_match(args, paths, regex("^'(/tmp/[^/]+)\\.out' '(/tmp/[^/]+)\\.err'$"))) {
                    ADD_FAILURE() << "Unexpected converter output paths: " << args;
                    return genError("Unexpected converter output paths");
                }
                EXPECT_EQ(paths[1].str(), paths[2].str());
                string stem = paths[1].str().substr(5);
                if (file_name == basename) {
                    EXPECT_EQ(basename, stem);
                } else {
                    EXPECT_EQ(basename + ".", stem.substr(0, basename.size() + 1));
                    EXPECT_TRUE(regex_match(stem.substr(basename.size() + 1), regex(
                        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                    )));
                }
                tmp_out = paths[1].str() + ".out";
                tmp_err = paths[2].str() + ".err";
                EXPECT_TRUE(output_paths.insert(tmp_out).second);
                if (result.ok() && result.unpack() == 0) {
                    if (write_errors) {
                        ofstream errors(tmp_err);
                        errors << converter_errors;
                        EXPECT_TRUE(errors.good());
                    }
                    if (write_output) {
                        ofstream output(tmp_out);
                        output << converter_output;
                        EXPECT_TRUE(output.good());
                    }
                }
                return result;
            }));
        EXPECT_CALL(tools, removeFile(_)).Times(2)
            .WillRepeatedly(Invoke([this](const string &path) {
                EXPECT_TRUE(path == tmp_out || path == tmp_err);
                removed_paths.push_back(path);
                std::remove(path.c_str());
                return true;
            }));
    }

    void
    expectConvertedOutput(Maybe<string> result)
    {
        EXPECT_CALL(shell, getExecOutput(Truly([this](const string &cmd) {
            return cmd == "'/etc/cp/bin/yq' eval '" + tmp_out + "' -o json";
        }), _, _)).WillOnce(Return(result));
    }

    void
    expectConvertedOutput()
    {
        EXPECT_CALL(shell, getExecOutput(Truly([this](const string &cmd) {
            return cmd == "'/etc/cp/bin/yq' eval '" + tmp_out + "' -o json";
        }), _, _)).WillOnce(Invoke([this](const string &, uint, bool) -> Maybe<string> {
            ifstream output(tmp_out);
            stringstream contents;
            contents << output.rdbuf();
            return contents.str();
        }));
    }

    string
    signaturePackage()
    {
        return R"({"IPSSnortSigs":{"protections":[{
            "protectionMetadata":{
                "silent":false,"protectionName":"test","severity":"High","confidenceLevel":"High",
                "performanceImpact":"Low","lastUpdate":"20261114","maintrainId":"1","tags":[],"cveList":[]
            },
            "detectionRules":{"type":"SSM","SSM":"test","keywords":"","context":["HTTP_RAW"]}
        }]}})";
    }

    string
    generate(const string &file_name, const string &output_path)
    {
        return generator.proccesMultipleAppsecPolicies<V1beta2AppsecLinuxPolicy, NewParsedRule>(
            {{"test", loadPolicy(file_name)}}, "test-version", output_path
        );
    }

    void
    checkSuccessfulConversion(const string &file_name, const string &quoted_input, const string &basename)
    {
        expectConversion(file_name, quoted_input, basename);
        expectConvertedOutput();
        CPTestTempfile output;
        string generated = generate(file_name, output.fname);
        rapidjson::Document document;
        document.Parse(generated.c_str());
        ASSERT_FALSE(document.HasParseError());
        const auto &snort = document["snort"]["IPSSnortSigs"];
        ASSERT_EQ(1u, snort["protections"].Size());
        EXPECT_EQ(file_name, snort["protections"][0]["name"].GetString());
        ASSERT_EQ(1u, snort["SnortProtections"].Size());
        ASSERT_EQ(1u, snort["SnortProtections"][0]["files"].Size());
        EXPECT_EQ(file_name, snort["SnortProtections"][0]["files"][0].GetString());
        EXPECT_EQ(generated, output.readFile());
        EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
    }

    ::Environment environment;
    ConfigComponent config;
    StrictMock<MockSnortEnvDetails> env;
    StrictMock<MockShellCmd> shell;
    StrictMock<MockSnortTools> tools;
    PolicyMakerUtils generator;
    string tmp_out;
    string tmp_err;
    set<string> output_paths;
    vector<string> removed_paths;
    ostringstream debug_output;
    string converter_errors = R"({"Errors":[],"InternalErrors":[],"InputRules":0})";
    string converter_output = R"({"IPSSnortSigs":{"protections":[]}})";
    bool write_errors = true;
    bool write_output = true;
};

TEST_F(SnortConversionTest, PreservesBasenameOutputPath)
{
    checkSuccessfulConversion("custom.rules", "'custom.rules'", "custom.rules");
}

TEST_F(SnortConversionTest, ReportsFailedRulesAndKeepsConvertedSignatures)
{
    CPTestTempfile input({
        "alert http any any -> any any (sid:1;)",
        "alert http any any -> any any (sid:2;)",
        "alert http any any -> any any (sid:3;)",
        "alert http any any -> any any (sid:4;)",
        "alert http any any -> any any (sid:5;)"
    });
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    converter_output = signaturePackage();
    // InternalErrors is optional. Extra fields must be harmless.
    converter_errors = R"({"Errors":[
        {"Error":"unsupported http_encode","Line":2},
        {"Error":"second rejection","Line":3},
        {"Error":"third rejection","Line":4},
        {"Error":"fourth rejection omitted from preview","Line":5}
    ],"InputRules":5,"extra":"ignored"})";
    expectConversion(input.fname, "'" + input.fname + "'", basename);
    expectConvertedOutput();
    CPTestTempfile output;
    string generated = generate(input.fname, output.fname);
    rapidjson::Document document;
    document.Parse(generated.c_str());
    ASSERT_FALSE(document.HasParseError());
    EXPECT_EQ(1u, document["snort"]["IPSSnortSigs"]["protections"][0]["protections"].Size());
    EXPECT_EQ(generated, output.readFile());
    EXPECT_THAT(debug_output.str(), HasSubstr("Snort conversion failed for 4 rules"));
    EXPECT_THAT(debug_output.str(), HasSubstr("Line 2: unsupported http_encode"));
    EXPECT_THAT(debug_output.str(), HasSubstr("third rejection"));
    EXPECT_THAT(debug_output.str(), Not(HasSubstr("fourth rejection")));
    EXPECT_THAT(debug_output.str(), HasSubstr(tmp_err));
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, KeepsConvertedRulesWhenSomeRulesHitInternalErrors)
{
    converter_output = signaturePackage();
    converter_errors = R"({
        "Errors":[],"InternalErrors":[{"Error":"unexpected exception","Line":1}],"InputRules":2
    })";
    expectConversion("custom.rules", "'custom.rules'", "custom.rules");
    CPTestTempfile output({"previous policy"});
    string generated = generate("custom.rules", output.fname);
    rapidjson::Document document;
    document.Parse(generated.c_str());
    ASSERT_FALSE(document.HasParseError());
    EXPECT_EQ(1u, document["snort"]["IPSSnortSigs"]["protections"][0]["protections"].Size());
    EXPECT_THAT(debug_output.str(), HasSubstr("internal errors: 1"));
    EXPECT_THAT(debug_output.str(), HasSubstr("unexpected exception"));
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, RejectsZeroSignaturesWithReportedInputRulesForRelativePath)
{
    CPTestTempfile input;
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    // The converter reports rules from its data directory; there is no input at the caller's relative path.
    ASSERT_FALSE(ifstream(basename).good());
    converter_errors = R"({"Errors":[],"InternalErrors":[],"InputRules":1})";
    expectConversion(basename, "'" + basename + "'", basename);
    expectConvertedOutput();
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE(generate(basename, output.fname).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, RejectsZeroSignaturesWithReportedInputRulesForCrOnlyInput)
{
    CPTestTempfile input;
    {
        ofstream rules(input.fname, ios::binary | ios::trunc);
        rules << "# comment\ralert badproto any any -> any any (sid:1;)\r";
        ASSERT_TRUE(rules.good());
    }
    converter_errors = R"({
        "Errors":[{"Error":"unsupported protocol","Line":2}],"InternalErrors":[],"InputRules":1
    })";
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    expectConversion(input.fname, "'" + input.fname + "'", basename);
    expectConvertedOutput();
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE(generate(input.fname, output.fname).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_THAT(debug_output.str(), HasSubstr("Snort conversion failed for 1 rules"));
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, RejectsMissingPackageWithReportedInputRulesForRelativePath)
{
    CPTestTempfile input;
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    ASSERT_FALSE(ifstream(basename).good());
    converter_errors = R"({"Errors":[],"InternalErrors":[],"InputRules":1})";
    write_output = false;
    expectConversion(basename, "'" + basename + "'", basename);
    // Permit the previous caller to read valid output, so rejection cannot depend on an unexpected mock call.
    EXPECT_CALL(shell, getExecOutput(_, _, _)).Times(AnyNumber()).WillRepeatedly(Return(signaturePackage()));
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE(generate(basename, output.fname).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, CleanRunWithRulesKeepsSignaturesWithoutWarning)
{
    CPTestTempfile input({"alert http any any -> any any (sid:1;)"});
    converter_errors = R"({"Errors":[],"InternalErrors":[],"InputRules":1})";
    converter_output = signaturePackage();
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    checkSuccessfulConversion(input.fname, "'" + input.fname + "'", basename);
    EXPECT_THAT(debug_output.str(), Not(HasSubstr("Snort conversion failed")));
    EXPECT_THAT(debug_output.str(), Not(HasSubstr("Could not read Snort conversion diagnostics")));
    EXPECT_THAT(debug_output.str(), Not(HasSubstr("input rule count is unknown")));
}

TEST_F(SnortConversionTest, AllowsEmptySignaturesForCommentsOnlyInput)
{
    CPTestTempfile input({"  # comment", "  ", ""});
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    checkSuccessfulConversion(input.fname, "'" + input.fname + "'", basename);
}

TEST_F(SnortConversionTest, AllowsEmptySignaturesWithReportedZeroInputRules)
{
    // Only the converter's count is authoritative, even if a different input is readable by the caller.
    CPTestTempfile input({"alert http any any -> any any (sid:1;)"});
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    checkSuccessfulConversion(input.fname, "'" + input.fname + "'", basename);
    EXPECT_THAT(debug_output.str(), Not(HasSubstr("input rule count is unknown")));
}

TEST_F(SnortConversionTest, MissingInputRulesWarnsOnceAndAllowsEmptySignatures)
{
    CPTestTempfile input({"alert http any any -> any any (sid:1;)"});
    converter_errors = R"({"Errors":[],"InternalErrors":[]})";
    string basename = input.fname.substr(input.fname.find_last_of('/') + 1);
    checkSuccessfulConversion(input.fname, "'" + input.fname + "'", basename);
    const string warning = "Snort conversion input rule count is unknown: " + tmp_err;
    string log = debug_output.str();
    auto position = log.find(warning);
    ASSERT_NE(string::npos, position);
    EXPECT_EQ(string::npos, log.find(warning, position + warning.size()));
    EXPECT_THAT(log, HasSubstr("Missing or invalid InputRules; skipping empty signature package check"));
    EXPECT_THAT(log, Not(HasSubstr("Could not read Snort conversion diagnostics")));
}

TEST_F(SnortConversionTest, MissingDiagnosticsWarnsWithoutFailingGeneration)
{
    write_errors = false;
    checkSuccessfulConversion("custom.rules", "'custom.rules'", "custom.rules");
    const string warning = "Could not read Snort conversion diagnostics: " + tmp_err;
    string log = debug_output.str();
    auto position = log.find(warning);
    ASSERT_NE(string::npos, position);
    EXPECT_EQ(string::npos, log.find(warning, position + warning.size()));
}

TEST_F(SnortConversionTest, MalformedDiagnosticsWarnsWithoutFailingGeneration)
{
    converter_errors = "not JSON";
    checkSuccessfulConversion("custom.rules", "'custom.rules'", "custom.rules");
    const string warning = "Could not read Snort conversion diagnostics: " + tmp_err;
    string log = debug_output.str();
    auto position = log.find(warning);
    ASSERT_NE(string::npos, position);
    EXPECT_EQ(string::npos, log.find(warning, position + warning.size()));
}

TEST_F(SnortConversionTest, UsesBasenameForRelativeSubdirectory)
{
    checkSuccessfulConversion("snort/custom.rules", "'snort/custom.rules'", "custom.rules");
}

TEST_F(SnortConversionTest, UsesBasenameForAbsolutePath)
{
    checkSuccessfulConversion("/etc/cp/conf/snort/custom.rules", "'/etc/cp/conf/snort/custom.rules'", "custom.rules");
}

TEST_F(SnortConversionTest, QuotesPathsWithSpaces)
{
    checkSuccessfulConversion("snort rules/custom rules.rules", "'snort rules/custom rules.rules'", "custom rules.rules");
}

TEST_F(SnortConversionTest, QuotesSingleQuotesAndShellMetacharacters)
{
    checkSuccessfulConversion(
        "/snort's;$(id)/custom.rules", "'/snort'\"'\"'s;$(id)/custom.rules'", "custom.rules"
    );
}

TEST_F(SnortConversionTest, SeparatesFilesWithTheSameBasename)
{
    checkSuccessfulConversion("first/custom.rules", "'first/custom.rules'", "custom.rules");
    removed_paths.clear();
    checkSuccessfulConversion("second/custom.rules", "'second/custom.rules'", "custom.rules");
    EXPECT_EQ(2u, output_paths.size());
}

TEST_F(SnortConversionTest, RejectsNonzeroExitAndCanRetryWithTheSameGenerator)
{
    expectConversion("custom.rules", "'custom.rules'", "custom.rules", 1);
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE(generate("custom.rules", output.fname).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);

    // A failed conversion must be attempted again with the same generator.
    removed_paths.clear();
    output_paths.clear();
    checkSuccessfulConversion("custom.rules", "'custom.rules'", "custom.rules");
}

TEST_F(SnortConversionTest, ClearsIdentifiersAfterFailedConversionBeforeRetry)
{
    expectConversion("custom.rules", "'custom.rules'", "custom.rules", 1);
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE((generator.proccesMultipleAppsecPolicies<V1beta2AppsecLinuxPolicy, NewParsedRule>(
        {{"test", loadPolicy("custom.rules", true)}}, "test-version", output.fname
    )).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);

    removed_paths.clear();
    output_paths.clear();
    expectConversion("custom.rules", "'custom.rules'", "custom.rules");
    expectConvertedOutput();
    string generated = generate("custom.rules", output.fname);
    rapidjson::Document document;
    document.Parse(generated.c_str());
    ASSERT_FALSE(document.HasParseError());
    const auto &identifiers = document["rules"]["rulebase"]["usersIdentifiers"];
    ASSERT_TRUE(identifiers.IsArray());
    EXPECT_TRUE(identifiers.Empty());
    EXPECT_EQ(string::npos, generated.find("X-Rejected-Source"));
    EXPECT_EQ(string::npos, generated.find("rejected-client"));
    EXPECT_EQ(generated, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, RejectsShellExecutionFailure)
{
    expectConversion("custom.rules", "'custom.rules'", "custom.rules", genError("converter timed out"));
    EXPECT_CALL(shell, getExecOutput(_, _, _)).Times(0);
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE(generate("custom.rules", output.fname).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, RejectsUnreadableConvertedOutput)
{
    expectConversion("custom.rules", "'custom.rules'", "custom.rules");
    expectConvertedOutput(genError("cannot read converted output"));
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE(generate("custom.rules", output.fname).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

TEST_F(SnortConversionTest, SinglePolicyEntryRejectsFailedConversion)
{
    EXPECT_CALL(shell, getExecOutput("'/etc/cp/bin/yq' eval 'policy.yaml' -o json", _, _))
        .WillOnce(Return(policyJson("custom.rules")));
    expectConversion("custom.rules", "'custom.rules'", "custom.rules", 1);
    CPTestTempfile output({"previous policy"});
    string previous = output.readFile();
    EXPECT_TRUE(generator.proccesSingleAppsecPolicy("policy.yaml", "test-version", output.fname).empty());
    EXPECT_EQ(previous, output.readFile());
    EXPECT_EQ((vector<string>{tmp_out, tmp_err}), removed_paths);
}

} // namespace
