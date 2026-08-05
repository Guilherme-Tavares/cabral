#include <cabral/model/ScanConfig.hpp>
#include <cabral/scan/ConnectScanner.hpp>

#include <algorithm>
#include <chrono>
#include <stop_token>
#include <vector>

#include <gtest/gtest.h>

#include "TestListener.hpp"

using cabral::IpAddress;
using cabral::Port;
using cabral::PortState;
using cabral::ScanConfig;
using cabral::TimingProfile;
using cabral::scan::ConnectScanner;

namespace {

ScanConfig fastConfig() {
    ScanConfig config;
    config.timing = TimingProfile::Aggressive;
    config.timeoutOverride = std::chrono::milliseconds(300);
    return config;
}

PortState stateOf(const std::vector<cabral::PortResult>& results, Port port) {
    const auto it = std::find_if(results.begin(), results.end(),
                                 [port](const auto& r) { return r.port == port; });
    return (it == results.end()) ? PortState::Unknown : it->state;
}

} // namespace

TEST(ConnectScanner, ReportsMetadata) {
    ConnectScanner scanner;
    EXPECT_EQ(scanner.protocol(), cabral::Protocol::Tcp);
    EXPECT_FALSE(scanner.requiresRawSocket());
    EXPECT_EQ(scanner.name(), "connect");
}

TEST(ConnectScanner, EmptyPortListYieldsNoResults) {
    ConnectScanner scanner;
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), {}, fastConfig(), std::stop_token{});
    EXPECT_TRUE(results.empty());
}

// Aceite da Fase 2: uma porta com listener real precisa aparecer como Open.
TEST(ConnectScanner, DetectsOpenPort) {
    cabral::test::TestListener listener;
    ASSERT_TRUE(listener.isValid()) << "could not open a local listening socket";

    ConnectScanner scanner;
    const std::vector<Port> ports{listener.port()};
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, fastConfig(), std::stop_token{});

    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].port, listener.port());
    EXPECT_EQ(results[0].state, PortState::Open);
}

/// Uma porta sem listener não pode ser Open. Se ela vira Closed ou Filtered depende do
/// host: um firewall que descarta o SYN em vez de responder RST produz Filtered, e esse é
/// o resultado correto — não há evidência para afirmar Closed. O Windows Firewall faz
/// exatamente isso, inclusive em loopback, então afirmar Closed aqui tornaria o teste
/// dependente da configuração da máquina.
TEST(ConnectScanner, ClosedPortIsNotReportedOpen) {
    const Port closedPort = cabral::test::reserveAndReleasePort();
    ASSERT_NE(closedPort, 0);

    ConnectScanner scanner;
    const std::vector<Port> ports{closedPort};
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, fastConfig(), std::stop_token{});

    ASSERT_EQ(results.size(), 1u);
    EXPECT_NE(results[0].state, PortState::Open);
    EXPECT_TRUE(results[0].state == PortState::Closed || results[0].state == PortState::Filtered);
}

/// A tradução de desfecho em estado é a semântica de -sT. Verificá-la diretamente não
/// depende de conseguir um RST real, que exige um host que não filtre.
TEST(ConnectScanner, TranslatesConnectResultToPortState) {
    using cabral::net::SocketError;
    using cabral::scan::stateForConnectResult;

    EXPECT_EQ(stateForConnectResult(SocketError::None), PortState::Open);
    EXPECT_EQ(stateForConnectResult(SocketError::Refused), PortState::Closed);
    EXPECT_EQ(stateForConnectResult(SocketError::TimedOut), PortState::Filtered);
    EXPECT_EQ(stateForConnectResult(SocketError::Unreachable), PortState::Filtered);

    // Nunca reportar Open sem evidência de conexão estabelecida.
    for (auto error :
         {SocketError::Refused, SocketError::TimedOut, SocketError::Unreachable,
          SocketError::PermissionDenied, SocketError::ResourceExhausted, SocketError::Other}) {
        EXPECT_NE(stateForConnectResult(error), PortState::Open);
    }
}

TEST(ConnectScanner, SeparatesOpenFromClosedInOneBatch) {
    cabral::test::TestListener listener;
    ASSERT_TRUE(listener.isValid());
    const Port closedPort = cabral::test::reserveAndReleasePort();
    ASSERT_NE(closedPort, 0);
    ASSERT_NE(closedPort, listener.port());

    ConnectScanner scanner;
    std::vector<Port> ports{listener.port(), closedPort};
    std::sort(ports.begin(), ports.end());

    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, fastConfig(), std::stop_token{});

    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(stateOf(results, listener.port()), PortState::Open);
    EXPECT_NE(stateOf(results, closedPort), PortState::Open);
}

TEST(ConnectScanner, ResultsAreSortedByPort) {
    cabral::test::TestListener listener;
    ASSERT_TRUE(listener.isValid());

    std::vector<Port> ports;
    for (Port p = 1; p <= 40; ++p) {
        ports.push_back(p);
    }
    ports.push_back(listener.port());

    ConnectScanner scanner;
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, fastConfig(), std::stop_token{});

    ASSERT_EQ(results.size(), ports.size());
    EXPECT_TRUE(std::is_sorted(results.begin(), results.end(),
                               [](const auto& a, const auto& b) { return a.port < b.port; }));
    EXPECT_EQ(stateOf(results, listener.port()), PortState::Open);
}

// Cancelamento não pode inventar estado: o que não foi sondado fica Unknown.
TEST(ConnectScanner, StopRequestYieldsUnknownNotFiltered) {
    std::stop_source source;
    source.request_stop();

    std::vector<Port> ports;
    for (Port p = 1; p <= 50; ++p) {
        ports.push_back(p);
    }

    ConnectScanner scanner;
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, fastConfig(), source.get_token());

    ASSERT_EQ(results.size(), ports.size());
    EXPECT_TRUE(std::all_of(results.begin(), results.end(),
                            [](const auto& r) { return r.state == PortState::Unknown; }));
}

TEST(ConnectScanner, EveryRequestedPortIsAccountedFor) {
    std::vector<Port> ports;
    for (Port p = 100; p < 140; ++p) {
        ports.push_back(p);
    }

    ConnectScanner scanner;
    auto config = fastConfig();
    config.timeoutOverride = std::chrono::milliseconds(150);

    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, config, std::stop_token{});

    ASSERT_EQ(results.size(), ports.size());
    for (std::size_t i = 0; i < ports.size(); ++i) {
        EXPECT_EQ(results[i].port, ports[i]);
        EXPECT_EQ(results[i].protocol, cabral::Protocol::Tcp);
    }
}
