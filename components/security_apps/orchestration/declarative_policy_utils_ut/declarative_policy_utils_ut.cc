#include "cptest.h"
#include "declarative_policy_utils.h"

using namespace std;
using namespace testing;

namespace
{

class MockDeclarativeEnv : public Singleton::Provide<I_EnvDetails>::From<MockProvider<I_EnvDetails>>
{
public:
    MOCK_METHOD0(getEnvType, EnvType());
    MOCK_METHOD0(getToken, string());
    MOCK_METHOD0(getNameSpace, string());
};

class MockPolicyGenerator : public Singleton::Provide<I_LocalPolicyMgmtGen>::From<MockProvider<I_LocalPolicyMgmtGen>>
{
public:
    MOCK_METHOD3(generateAppSecLocalPolicy, string(EnvType, const string &, const string &));
};

// Keep this fixture independent of the disabled orchestration suite and its outdated tools mock.
class MockDeclarativeTools : public Singleton::Provide<I_OrchestrationTools>::From<MockProvider<I_OrchestrationTools>>
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

class DeclarativePolicyRetryTest : public TestWithParam<EnvType>
{
protected:
    void
    SetUp() override
    {
        EXPECT_CALL(env, getEnvType()).WillRepeatedly(Return(GetParam()));
        if (GetParam() == EnvType::K8S) {
            EXPECT_CALL(tools, readFile("/etc/cp/conf/k8s-policy-check.trigger"))
                .WillRepeatedly(Invoke([this](const string &) -> Maybe<string> { return source_checksum; }));
        } else {
            EXPECT_CALL(tools, calculateChecksum(_, "policy.yaml"))
                .WillRepeatedly(Invoke([this](Package::ChecksumTypes, const string &) -> Maybe<string> {
                    return source_checksum;
                }));
        }
        // Exercise the ApplyPolicyEvent handler without registering REST or recurring routines.
        policy.upon(ApplyPolicyEvent("policy.yaml"));
    }

    StrictMock<MockDeclarativeEnv> env;
    StrictMock<MockDeclarativeTools> tools;
    StrictMock<MockPolicyGenerator> generator;
    DeclarativePolicyUtils policy;
    string source_checksum = "source-checksum\n";
};

TEST_P(DeclarativePolicyRetryTest, RetriesSameContentAfterFailureAndCommitsOnlySuccess)
{
    EXPECT_CALL(generator, generateAppSecLocalPolicy(GetParam(), "source-checksum", "policy.yaml"))
        .WillOnce(Return(""))
        .WillOnce(Return("generated-policy"));
    CheckUpdateRequest request("", "old-output-checksum", "", "", "", "");

    // No output checksum may be calculated/published after the failed generation.
    EXPECT_CALL(tools, calculateChecksum(_, "/tmp/local_appsec.policy")).Times(0);
    EXPECT_TRUE(policy.getUpdate(request).empty());
    EXPECT_TRUE(policy.getCurrPolicy().empty());
    EXPECT_TRUE(policy.shouldApplyPolicy());
    Mock::VerifyAndClearExpectations(&tools);

    // Restore the source expectation after clearing the forbidden output-checksum call.
    if (GetParam() == EnvType::K8S) {
        EXPECT_CALL(tools, readFile("/etc/cp/conf/k8s-policy-check.trigger"))
            .WillRepeatedly(Return(source_checksum));
    } else {
        EXPECT_CALL(tools, calculateChecksum(_, "policy.yaml"))
            .WillRepeatedly(Return(source_checksum));
    }
    EXPECT_CALL(tools, calculateChecksum(_, "/tmp/local_appsec.policy"))
        .Times(2).WillRepeatedly(Return(string("new-output-checksum")));

    // The source content/checksum and request are identical to the first call.
    EXPECT_EQ("new-output-checksum", policy.getUpdate(request));
    EXPECT_EQ("generated-policy", policy.getCurrPolicy());
    CheckUpdateRequest applied("", "new-output-checksum", "", "", "", "");
    EXPECT_TRUE(policy.getUpdate(applied).empty());
    EXPECT_EQ("generated-policy", policy.getCurrPolicy());
    if (GetParam() == EnvType::K8S) EXPECT_FALSE(policy.shouldApplyPolicy());
    // Exactly two generator calls above: the third getUpdate must use the committed version.
}

TEST_P(DeclarativePolicyRetryTest, KeepsPreviousPolicyAndRetriesFailedReplacement)
{
    EXPECT_CALL(generator, generateAppSecLocalPolicy(GetParam(), "source-checksum", "policy.yaml"))
        .WillOnce(Return("previous-policy"));
    EXPECT_CALL(tools, calculateChecksum(_, "/tmp/local_appsec.policy"))
        .WillOnce(Return(string("previous-output-checksum")));
    CheckUpdateRequest request("", "", "", "", "", "");
    EXPECT_EQ("previous-output-checksum", policy.getUpdate(request));
    ASSERT_EQ("previous-policy", policy.getCurrPolicy());

    source_checksum = "changed-checksum\n";
    policy.upon(ApplyPolicyEvent("policy.yaml"));
    EXPECT_CALL(generator, generateAppSecLocalPolicy(GetParam(), "changed-checksum", "policy.yaml"))
        .WillOnce(Return(""))
        .WillOnce(Return("replacement-policy"));
    EXPECT_TRUE(policy.getUpdate(request).empty());
    EXPECT_EQ("previous-policy", policy.getCurrPolicy());
    EXPECT_TRUE(policy.shouldApplyPolicy());

    EXPECT_CALL(tools, calculateChecksum(_, "/tmp/local_appsec.policy"))
        .WillOnce(Return(string("replacement-output-checksum")));
    EXPECT_EQ("replacement-output-checksum", policy.getUpdate(request));
    EXPECT_EQ("replacement-policy", policy.getCurrPolicy());
}

INSTANTIATE_TEST_CASE_P(LinuxAndK8s, DeclarativePolicyRetryTest, Values(EnvType::LINUX, EnvType::K8S));

} // namespace
