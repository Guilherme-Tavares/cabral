#include <cabral/net/RawSocket.hpp>
#include <cabral/scan/SynScanner.hpp>

#include <algorithm>
#include <stop_token>
#include <vector>

#include <gtest/gtest.h>

using cabral::IpAddress;
using cabral::Port;
using cabral::PortState;
using cabral::ScanConfig;
using cabral::net::RawCapability;
using cabral::scan::SynScanner;

TEST(SynScanner, ReportsMetadata) {
    SynScanner scanner;
    EXPECT_EQ(scanner.protocol(), cabral::Protocol::Tcp);
    EXPECT_TRUE(scanner.requiresRawSocket());
    EXPECT_EQ(scanner.name(), "syn");
}

TEST(SynScanner, EmptyPortListYieldsNoResults) {
    SynScanner scanner;
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), {}, ScanConfig{}, std::stop_token{});
    EXPECT_TRUE(results.empty());
}

/// Sem privilégio (ou no Windows), toda porta fica Unknown: não há evidência para afirmar
/// qualquer outro estado. Reportar Filtered aqui seria inventar resultado.
TEST(SynScanner, WithoutRawCapabilityEveryPortIsUnknown) {
    if (cabral::net::probeRawCapability() == RawCapability::Available) {
        GTEST_SKIP() << "raw sockets available; this test covers the unprivileged path";
    }

    SynScanner scanner;
    const std::vector<Port> ports{22, 80, 443};
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, ScanConfig{}, std::stop_token{});

    ASSERT_EQ(results.size(), ports.size());
    EXPECT_TRUE(std::all_of(results.begin(), results.end(),
                            [](const auto& r) { return r.state == PortState::Unknown; }));
}

TEST(SynScanner, AccountsForEveryRequestedPort) {
    SynScanner scanner;
    const std::vector<Port> ports{22, 80, 443, 8080};
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, ScanConfig{}, std::stop_token{});

    ASSERT_EQ(results.size(), ports.size());
    EXPECT_TRUE(std::is_sorted(results.begin(), results.end(),
                               [](const auto& a, const auto& b) { return a.port < b.port; }));
    for (std::size_t i = 0; i < ports.size(); ++i) {
        EXPECT_EQ(results[i].port, ports[i]);
        EXPECT_EQ(results[i].protocol, cabral::Protocol::Tcp);
    }
}

TEST(SynScanner, StopRequestYieldsUnknown) {
    std::stop_source source;
    source.request_stop();

    SynScanner scanner;
    const std::vector<Port> ports{22, 80, 443};
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, ScanConfig{}, source.get_token());

    ASSERT_EQ(results.size(), ports.size());
    EXPECT_TRUE(std::all_of(results.begin(), results.end(),
                            [](const auto& r) { return r.state == PortState::Unknown; }));
}

TEST(RawCapability, AdviceIsActionableWhenUnavailable) {
    const auto missing = cabral::net::rawCapabilityAdvice(RawCapability::MissingPrivilege);
    EXPECT_FALSE(missing.empty());
    // Orientar setcap, nunca "rode como root".
    EXPECT_NE(missing.find("setcap"), std::string::npos);
    EXPECT_NE(missing.find("-sT"), std::string::npos);

    const auto unsupported = cabral::net::rawCapabilityAdvice(RawCapability::UnsupportedPlatform);
    EXPECT_FALSE(unsupported.empty());
    EXPECT_NE(unsupported.find("-sT"), std::string::npos);

    EXPECT_TRUE(cabral::net::rawCapabilityAdvice(RawCapability::Available).empty());
}

TEST(RawCapability, WindowsNeverReportsRawAsAvailable) {
#ifdef _WIN32
    // A restrição do XP SP2 não é contornável por privilégio.
    EXPECT_EQ(cabral::net::probeRawCapability(), RawCapability::UnsupportedPlatform);
#else
    GTEST_SKIP() << "windows-only expectation";
#endif
}

TEST(LocalAddress, ResolvesRouteForLoopback) {
    const auto local = cabral::net::localAddressFor(*IpAddress::parse("127.0.0.1"));
    ASSERT_TRUE(local.has_value());
    EXPECT_EQ(*local, *IpAddress::parse("127.0.0.1"));
}
