#include <cabral/model/IpAddress.hpp>

#include <gtest/gtest.h>

using cabral::IpAddress;

TEST(IpAddress, ParsesDottedQuad) {
    const auto address = IpAddress::parse("192.168.1.10");
    ASSERT_TRUE(address.has_value());
    EXPECT_EQ(address->value(), 0xC0A8010Au);
}

TEST(IpAddress, ParsesBoundaryAddresses) {
    EXPECT_EQ(IpAddress::parse("0.0.0.0")->value(), 0u);
    EXPECT_EQ(IpAddress::parse("255.255.255.255")->value(), 0xFFFFFFFFu);
}

TEST(IpAddress, RoundTripsThroughString) {
    for (std::string_view text : {"127.0.0.1", "8.8.8.8", "10.0.0.255", "0.0.0.0"}) {
        const auto address = IpAddress::parse(text);
        ASSERT_TRUE(address.has_value()) << text;
        EXPECT_EQ(address->toString(), text);
    }
}

TEST(IpAddress, RejectsOctetAboveRange) {
    EXPECT_FALSE(IpAddress::parse("192.168.1.256").has_value());
    EXPECT_FALSE(IpAddress::parse("300.1.1.1").has_value());
}

TEST(IpAddress, RejectsWrongOctetCount) {
    EXPECT_FALSE(IpAddress::parse("192.168.1").has_value());
    EXPECT_FALSE(IpAddress::parse("192.168.1.1.1").has_value());
}

TEST(IpAddress, RejectsMalformedInput) {
    EXPECT_FALSE(IpAddress::parse("").has_value());
    EXPECT_FALSE(IpAddress::parse("192.168..1").has_value());
    EXPECT_FALSE(IpAddress::parse("192.168.1.").has_value());
    EXPECT_FALSE(IpAddress::parse(".1.2.3").has_value());
    EXPECT_FALSE(IpAddress::parse("192.168.1.a").has_value());
    EXPECT_FALSE(IpAddress::parse("192.168.1.-1").has_value());
    EXPECT_FALSE(IpAddress::parse("scanme.nmap.org").has_value());
}

// Zero à esquerda é octal na notação clássica; aceitá-lo como decimal faria o scanner
// mirar um endereço diferente do digitado.
TEST(IpAddress, RejectsLeadingZeroOctet) {
    EXPECT_FALSE(IpAddress::parse("192.168.01.1").has_value());
    EXPECT_FALSE(IpAddress::parse("010.0.0.1").has_value());
    EXPECT_TRUE(IpAddress::parse("0.0.0.0").has_value());
}

TEST(IpAddress, ExposesOctetsInNetworkOrder) {
    const auto address = IpAddress::parse("1.2.3.4");
    ASSERT_TRUE(address.has_value());
    const auto parts = address->octets();
    EXPECT_EQ(parts[0], 1);
    EXPECT_EQ(parts[1], 2);
    EXPECT_EQ(parts[2], 3);
    EXPECT_EQ(parts[3], 4);
}

TEST(IpAddress, IsOrderedByNumericValue) {
    EXPECT_LT(*IpAddress::parse("10.0.0.1"), *IpAddress::parse("10.0.0.2"));
    EXPECT_EQ(*IpAddress::parse("10.0.0.1"), *IpAddress::parse("10.0.0.1"));
}
