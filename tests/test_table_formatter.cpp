#include <TableFormatter.hpp>
#include <string>

#include <gtest/gtest.h>

using cabral::HostResult;
using cabral::IpAddress;
using cabral::PortResult;
using cabral::PortState;
using cabral::Protocol;
using cabral::cli::formatHost;
using cabral::cli::formatSummary;
using cabral::cli::ScanSummary;

namespace {

PortResult makePort(cabral::Port port, PortState state, std::string service = "") {
    PortResult result;
    result.port = port;
    result.protocol = Protocol::Tcp;
    result.state = state;
    result.service = std::move(service);
    return result;
}

HostResult hostWith(std::vector<PortResult> ports) {
    HostResult host;
    host.address = *IpAddress::parse("127.0.0.1");
    host.isUp = true;
    host.ports = std::move(ports);
    return host;
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

} // namespace

TEST(TableFormatter, ShowsOpenPortWithService) {
    const auto text = formatHost(hostWith({makePort(22, PortState::Open, "ssh")}), 0);
    EXPECT_TRUE(contains(text, "22/tcp"));
    EXPECT_TRUE(contains(text, "open"));
    EXPECT_TRUE(contains(text, "ssh"));
    EXPECT_TRUE(contains(text, "127.0.0.1"));
}

TEST(TableFormatter, UnknownServiceIsLabelled) {
    const auto text = formatHost(hostWith({makePort(9999, PortState::Open)}), 0);
    EXPECT_TRUE(contains(text, "unknown"));
}

// Listar centenas de linhas "closed" afogaria as poucas que interessam.
TEST(TableFormatter, ClosedPortsAreSummarisedNotListed) {
    std::vector<PortResult> ports{makePort(22, PortState::Open, "ssh")};
    for (cabral::Port p = 100; p < 200; ++p) {
        ports.push_back(makePort(p, PortState::Closed));
    }

    const auto text = formatHost(hostWith(std::move(ports)), 0);
    EXPECT_TRUE(contains(text, "Not shown: 100 closed ports"));
    EXPECT_TRUE(contains(text, "22/tcp"));
    EXPECT_FALSE(contains(text, "150/tcp"));
}

/// Fechadas e filtradas somam numa linha só: duas linhas "Not shown" separadas sugeririam
/// contagens de coisas distintas.
TEST(TableFormatter, CombinesClosedAndFilteredInOneLine) {
    std::vector<PortResult> ports{makePort(80, PortState::Open, "http")};
    ports.push_back(makePort(21, PortState::Closed));
    for (cabral::Port p = 100; p < 105; ++p) {
        ports.push_back(makePort(p, PortState::Filtered));
    }

    const auto text = formatHost(hostWith(std::move(ports)), 0);
    EXPECT_TRUE(contains(text, "Not shown: 1 closed, 5 filtered ports"));
    // Uma linha, não duas.
    EXPECT_EQ(text.find("Not shown"), text.rfind("Not shown"));
}

TEST(TableFormatter, FilteredPortsHiddenWithoutVerbose) {
    const auto host = hostWith({makePort(80, PortState::Filtered)});
    EXPECT_FALSE(contains(formatHost(host, 0), "80/tcp"));
    EXPECT_TRUE(contains(formatHost(host, 1), "80/tcp"));
}

TEST(TableFormatter, OpenFilteredIsAlwaysShown) {
    const auto text = formatHost(hostWith({makePort(53, PortState::OpenFiltered)}), 0);
    EXPECT_TRUE(contains(text, "open|filtered"));
}

TEST(TableFormatter, DownHostIsReported) {
    HostResult host;
    host.address = *IpAddress::parse("10.0.0.1");
    host.isUp = false;

    const auto text = formatHost(host, 0);
    EXPECT_TRUE(contains(text, "down"));
}

TEST(TableFormatter, HostWithoutOpenPortsSaysSo) {
    const auto text = formatHost(hostWith({makePort(22, PortState::Closed)}), 0);
    EXPECT_TRUE(contains(text, "No open ports"));
}

TEST(TableFormatter, HostnameAppearsWhenPresent) {
    auto host = hostWith({makePort(80, PortState::Open, "http")});
    host.hostname = "localhost";
    EXPECT_TRUE(contains(formatHost(host, 0), "localhost"));
}

TEST(TableFormatter, SummaryReportsCounts) {
    ScanSummary summary;
    summary.hostsScanned = 4;
    summary.hostsUp = 2;
    summary.openPorts = 7;
    summary.elapsed = std::chrono::milliseconds(1500);

    const auto text = formatSummary(summary);
    EXPECT_TRUE(contains(text, "4 hosts"));
    EXPECT_TRUE(contains(text, "2 up"));
    EXPECT_TRUE(contains(text, "7 open ports"));
    EXPECT_TRUE(contains(text, "1.50 seconds"));
}

TEST(TableFormatter, SummaryUsesSingularForOne) {
    ScanSummary summary;
    summary.hostsScanned = 1;
    summary.hostsUp = 1;
    summary.openPorts = 1;

    const auto text = formatSummary(summary);
    EXPECT_TRUE(contains(text, "1 host,"));
    EXPECT_TRUE(contains(text, "1 open port\n"));
}
