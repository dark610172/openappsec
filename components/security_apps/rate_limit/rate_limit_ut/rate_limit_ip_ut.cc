#include "../rate_limit_ip.h"

#include "gtest/gtest.h"

TEST(RateLimitIpTest, FormatsIPv4)
{
    in_addr address{};
    ASSERT_EQ(1, inet_pton(AF_INET, "192.0.2.123", &address));
    EXPECT_EQ("192.0.2.123", ipAddrToStr(IPAddr(address)));
}

TEST(RateLimitIpTest, FormatsIPv6Loopback)
{
    in6_addr address{};
    ASSERT_EQ(1, inet_pton(AF_INET6, "::1", &address));
    EXPECT_EQ("::1", ipAddrToStr(IPAddr(address)));
}

TEST(RateLimitIpTest, FormatsGlobalIPv6)
{
    in6_addr address{};
    ASSERT_EQ(1, inet_pton(AF_INET6, "2001:4860:4860::8888", &address));
    EXPECT_EQ("2001:4860:4860::8888", ipAddrToStr(IPAddr(address)));
}

TEST(RateLimitIpTest, FormatsIPv4MappedIPv6)
{
    in6_addr address{};
    ASSERT_EQ(1, inet_pton(AF_INET6, "::ffff:192.0.2.123", &address));
    EXPECT_EQ("::ffff:192.0.2.123", ipAddrToStr(IPAddr(address)));
}

TEST(RateLimitIpTest, UninitializedAddressIsEmpty)
{
    EXPECT_TRUE(ipAddrToStr(IPAddr()).empty());
}
