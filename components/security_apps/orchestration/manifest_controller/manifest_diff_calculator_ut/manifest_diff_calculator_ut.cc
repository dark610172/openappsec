#include "manifest_diff_calculator.h"

#include <sstream>

#include "cptest.h"

using namespace std;
using namespace testing;

namespace
{

Package
makePackage(const string &name, const vector<string> &dependencies = {}, const string &version = "1")
{
    stringstream json;
    {
        cereal::JSONOutputArchive archive(json);
        const string download_path = "unused";
        const string checksum_type = "sha256sum";
        const string checksum = name + "-" + version;
        const string package_type = "service";
        archive(cereal::make_nvp("download-path", download_path));
        archive(cereal::make_nvp("name", name));
        archive(cereal::make_nvp("version", version));
        archive(cereal::make_nvp("checksum-type", checksum_type));
        archive(cereal::make_nvp("checksum", checksum));
        archive(cereal::make_nvp("package-type", package_type));
        archive(cereal::make_nvp("require", dependencies));
    }

    Package package;
    cereal::JSONInputArchive archive(json);
    package.serialize(archive);
    return package;
}

vector<string>
packageNames(const vector<Package> &packages)
{
    vector<string> names;
    for (const auto &package : packages) names.push_back(package.getName());
    return names;
}

} // namespace

TEST(ManifestDiffCalculatorTest, RejectsMissingDependency)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> packages = {{"A", makePackage("A", {"Missing"})}};

    auto result = calculator.buildInstallationQueue({}, packages);

    ASSERT_FALSE(result.ok());
    EXPECT_EQ(
        "One of the requested dependencies is corrupted or doesn't exist. Package: Missing",
        result.getErr()
    );
}

TEST(ManifestDiffCalculatorTest, RejectsSelfCycle)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> packages = {{"A", makePackage("A", {"A"})}};

    auto result = calculator.buildInstallationQueue({}, packages);

    ASSERT_FALSE(result.ok());
    EXPECT_EQ("Dependency cycle detected. Package: A", result.getErr());
}

TEST(ManifestDiffCalculatorTest, RejectsTwoNodeCycle)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> packages = {
        {"A", makePackage("A", {"B"})},
        {"B", makePackage("B", {"A"})}
    };

    auto result = calculator.buildInstallationQueue({}, packages);

    ASSERT_FALSE(result.ok());
    EXPECT_EQ("Dependency cycle detected. Package: A", result.getErr());
}

TEST(ManifestDiffCalculatorTest, PreservesDiamondOrderWithoutDuplicates)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> packages = {
        {"A", makePackage("A", {"B", "C"})},
        {"B", makePackage("B", {"D"})},
        {"C", makePackage("C", {"D"})},
        {"D", makePackage("D")}
    };

    auto result = calculator.buildInstallationQueue({}, packages);

    ASSERT_TRUE(result.ok());
    EXPECT_THAT(packageNames(result.unpack()), ElementsAre("D", "B", "C", "A"));
}

TEST(ManifestDiffCalculatorTest, AcceptsInstalledDependencyAbsentFromNewPackages)
{
    ManifestDiffCalculator calculator;
    // Its own dependency is irrelevant: the installed package does not need installation.
    const map<string, Package> current = {{"B", makePackage("B", {"NotInManifest"})}};
    const map<string, Package> packages = {{"A", makePackage("A", {"B"})}};

    auto result = calculator.buildInstallationQueue(current, packages);

    ASSERT_TRUE(result.ok());
    EXPECT_THAT(packageNames(result.unpack()), ElementsAre("A"));
}

TEST(ManifestDiffCalculatorTest, PreservesOrderForUnchangedDependencyInBothMaps)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> current = {{"B", makePackage("B")}};
    const map<string, Package> packages = {
        {"A", makePackage("A", {"B"})},
        {"B", makePackage("B")}
    };

    auto result = calculator.buildInstallationQueue(current, packages);

    ASSERT_TRUE(result.ok());
    // The public API still visits every root; filtering unchanged packages is a separate step.
    EXPECT_THAT(packageNames(result.unpack()), ElementsAre("A", "B"));
}

TEST(ManifestDiffCalculatorTest, InstallsChangedDependencyBeforeDependent)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> current = {{"B", makePackage("B")}};
    const map<string, Package> packages = {
        {"A", makePackage("A", {"B"})},
        {"B", makePackage("B", {}, "2")}
    };

    auto result = calculator.buildInstallationQueue(current, packages);

    ASSERT_TRUE(result.ok());
    EXPECT_THAT(packageNames(result.unpack()), ElementsAre("B", "A"));
    EXPECT_EQ("2", result.unpack().front().getVersion());
}

TEST(ManifestDiffCalculatorTest, PreservesPriorityPackagesAndStillVisitsTheirDependencies)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> packages = {
        {"A", makePackage("A", {"B"})},
        {"B", makePackage("B")},
        {"orchestration", makePackage("orchestration", {"B"})},
        {"sharedLibs", makePackage("sharedLibs")},
        {"wlpStandalone", makePackage("wlpStandalone")}
    };

    auto result = calculator.buildInstallationQueue({}, packages);

    ASSERT_TRUE(result.ok());
    EXPECT_THAT(
        packageNames(result.unpack()),
        ElementsAre("orchestration", "sharedLibs", "wlpStandalone", "B", "A")
    );
}

TEST(ManifestDiffCalculatorTest, RejectsCycleEvenWhenPackageIsPrequeued)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> packages = {
        {"orchestration", makePackage("orchestration", {"orchestration"})}
    };

    auto result = calculator.buildInstallationQueue({}, packages);

    ASSERT_FALSE(result.ok());
    EXPECT_EQ("Dependency cycle detected. Package: orchestration", result.getErr());
}

TEST(ManifestDiffCalculatorTest, DoesNotRetainVisitStateBetweenCalls)
{
    ManifestDiffCalculator calculator;
    const map<string, Package> invalid = {{"A", makePackage("A", {"Missing"})}};
    ASSERT_FALSE(calculator.buildInstallationQueue({}, invalid).ok());

    const map<string, Package> valid = {{"A", makePackage("A")}};
    auto first = calculator.buildInstallationQueue({}, valid);
    auto second = calculator.buildInstallationQueue({}, valid);

    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    EXPECT_THAT(packageNames(first.unpack()), ElementsAre("A"));
    EXPECT_THAT(packageNames(second.unpack()), ElementsAre("A"));
}
