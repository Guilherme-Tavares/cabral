#include <cabral/services/ServiceTable.hpp>

#include <gtest/gtest.h>

using cabral::Protocol;
using cabral::services::ServiceTable;

TEST(ServiceTable, BuiltinsCoverCommonPorts) {
    const auto table = ServiceTable::builtinOnly();
    EXPECT_EQ(table.lookup(22, Protocol::Tcp), "ssh");
    EXPECT_EQ(table.lookup(80, Protocol::Tcp), "http");
    EXPECT_EQ(table.lookup(443, Protocol::Tcp), "https");
    EXPECT_EQ(table.lookup(53, Protocol::Udp), "domain");
}

TEST(ServiceTable, DistinguishesProtocol) {
    const auto table = ServiceTable::builtinOnly();
    EXPECT_EQ(table.lookup(161, Protocol::Udp), "snmp");
    // 161/tcp não está na tabela embutida; o protocolo faz parte da chave.
    EXPECT_TRUE(table.lookup(161, Protocol::Tcp).empty());
}

TEST(ServiceTable, UnknownPortYieldsEmpty) {
    const auto table = ServiceTable::builtinOnly();
    EXPECT_TRUE(table.lookup(64999, Protocol::Tcp).empty());
}

TEST(ServiceTable, ParsesEtcServicesFormat) {
    ServiceTable table;
    ASSERT_TRUE(table.parseFrom("# comment line\n"
                                "ssh             22/tcp\n"
                                "domain          53/udp     nameserver\n"
                                "http            80/tcp     www\n"));

    EXPECT_EQ(table.lookup(22, Protocol::Tcp), "ssh");
    EXPECT_EQ(table.lookup(53, Protocol::Udp), "domain");
    EXPECT_EQ(table.lookup(80, Protocol::Tcp), "http");
}

TEST(ServiceTable, IgnoresCommentsAndBlankLines) {
    ServiceTable table;
    ASSERT_TRUE(table.parseFrom("\n"
                                "# ssh 9999/tcp\n"
                                "\n"
                                "ssh 22/tcp # trailing comment\n"));
    EXPECT_EQ(table.lookup(22, Protocol::Tcp), "ssh");
    EXPECT_TRUE(table.lookup(9999, Protocol::Tcp).empty());
}

TEST(ServiceTable, SkipsMalformedAndUnsupportedEntries) {
    ServiceTable table;
    table.parseFrom("bad-line-without-port\n"
                    "noproto 100/sctp\n"
                    "zeroport 0/tcp\n"
                    "toobig 70000/tcp\n"
                    "good 8080/tcp\n");

    // parseFrom não injeta embutidos: aqui vale o nome do próprio texto.
    EXPECT_EQ(table.lookup(8080, Protocol::Tcp), "good");
    EXPECT_TRUE(table.lookup(100, Protocol::Tcp).empty());
    EXPECT_TRUE(table.lookup(0, Protocol::Tcp).empty());
}

TEST(ServiceTable, ReportsFailureWhenNothingParsed) {
    ServiceTable table;
    EXPECT_FALSE(table.parseFrom("# only comments\n\n"));
}

TEST(ServiceTable, FirstEntryWinsOverLater) {
    ServiceTable table;
    table.parseFrom("first 1234/tcp\nsecond 1234/tcp\n");
    EXPECT_EQ(table.lookup(1234, Protocol::Tcp), "first");
}

TEST(ServiceTable, SystemLoadAlwaysUsable) {
    const auto table = ServiceTable::loadSystemDefault();
    // Com ou sem arquivo do sistema, os embutidos garantem um mínimo utilizável.
    EXPECT_GT(table.size(), 0u);
    EXPECT_EQ(table.lookup(22, Protocol::Tcp), "ssh");
}
