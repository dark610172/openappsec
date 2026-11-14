#include "ip_utilities.h"

#include "cptest.h"

using namespace std;

TEST(IpUtilitiesCidrTest, ZeroMaskCoversWholeIPv4Space)
{
    auto range = IPUtilities::createRangeFromCidr("0.0.0.0/0");
    ASSERT_TRUE(range.ok()) << range.getErr();
    EXPECT_EQ("0.0.0.0", range.unpack().first);
    EXPECT_EQ("255.255.255.255", range.unpack().second);
}

TEST(IpUtilitiesCidrTest, ZeroMaskMatchesDockerGatewayAddress)
{
    auto range = IPUtilities::createRangeFromString<IPRange, IpAddress>("0.0.0.0/0", "IPv4");
    ASSERT_TRUE(range.ok()) << range.getErr();
    EXPECT_TRUE(IPUtilities::isIpAddrInRange(range.unpack(), IPUtilities::createIpFromString("172.18.0.1")));
    EXPECT_TRUE(IPUtilities::isIpAddrInRange(range.unpack(), IPUtilities::createIpFromString("255.255.255.255")));
    EXPECT_TRUE(IPUtilities::isIpAddrInRange(range.unpack(), IPUtilities::createIpFromString("0.0.0.0")));
}

TEST(IpUtilitiesCidrTest, NormalMasksStillWork)
{
    auto r24 = IPUtilities::createRangeFromCidr("192.168.1.77/24");
    ASSERT_TRUE(r24.ok());
    EXPECT_EQ("192.168.1.0", r24.unpack().first);
    EXPECT_EQ("192.168.1.255", r24.unpack().second);

    auto r32 = IPUtilities::createRangeFromCidr("10.1.2.3/32");
    ASSERT_TRUE(r32.ok());
    EXPECT_EQ("10.1.2.3", r32.unpack().first);
    EXPECT_EQ("10.1.2.3", r32.unpack().second);

    auto r8 = IPUtilities::createRangeFromCidr("10.9.9.9/8");
    ASSERT_TRUE(r8.ok());
    EXPECT_EQ("10.0.0.0", r8.unpack().first);
    EXPECT_EQ("10.255.255.255", r8.unpack().second);
}

TEST(IpUtilitiesCidrTest, OutOfRangeIPv4MaskIsRejected)
{
    EXPECT_FALSE(IPUtilities::createRangeFromCidr("10.0.0.0/33").ok());
    EXPECT_FALSE(IPUtilities::createRangeFromCidr("10.0.0.0/-1").ok());
}

TEST(IpUtilitiesCidrTest, ZeroMaskIPv6CoversWholeAddressSpace)
{
    auto range = IPUtilities::createRangeFromString<IPRange, IpAddress>("::/0", "IPv6");
    ASSERT_TRUE(range.ok()) << range.getErr();
    EXPECT_EQ("::", IPUtilities::IpAddrToString(range.unpack().start));
    EXPECT_EQ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", IPUtilities::IpAddrToString(range.unpack().end));
    EXPECT_TRUE(IPUtilities::isIpAddrInRange(range.unpack(), IPUtilities::createIpFromString("2001:db8::1")));
    EXPECT_TRUE(IPUtilities::isIpAddrInRange(range.unpack(), IPUtilities::createIpFromString("fe80::1")));
}

TEST(IpUtilitiesCidrTest, OutOfRangeIPv6MaskIsRejected)
{
    EXPECT_FALSE(IPUtilities::createRangeFromCidr("2001:db8::/129").ok());
    EXPECT_FALSE(IPUtilities::createRangeFromCidr("2001:db8::/-5").ok());
}
