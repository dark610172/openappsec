#include "AttackTypeTelemetry.h"

#include "gtest/gtest.h"

TEST(AttackTypeTelemetry, emptyInput)
{
    DecisionTelemetryData data;
    Waap::populateAttackTypeTelemetry(data, "");
    EXPECT_TRUE(data.attackTypes.empty());
}

TEST(AttackTypeTelemetry, singleTypeKeepsSpaces)
{
    DecisionTelemetryData data;
    Waap::populateAttackTypeTelemetry(data, "SQL Injection");
    const std::set<std::string> expected = {"SQL Injection"};
    EXPECT_EQ(data.attackTypes, expected);
}

TEST(AttackTypeTelemetry, multipleTypesUseTelemetryNames)
{
    DecisionTelemetryData data;
    Waap::populateAttackTypeTelemetry(data, "Cross Site Scripting, Remote Code Execution, SQL Injection");
    const std::set<std::string> expected = {"Cross Site Scripting", "Remote Code Execution", "SQL Injection"};
    EXPECT_EQ(data.attackTypes, expected);
}

TEST(AttackTypeTelemetry, replacesPreviousTypes)
{
    DecisionTelemetryData data;
    Waap::populateAttackTypeTelemetry(data, "General");
    const std::set<std::string> expected = {"General"};
    EXPECT_EQ(data.attackTypes, expected);
    Waap::populateAttackTypeTelemetry(data, "");
    EXPECT_TRUE(data.attackTypes.empty());
}
