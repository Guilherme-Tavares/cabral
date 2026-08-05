#include <ArgParser.hpp>
#include <initializer_list>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

using cabral::OutputFormat;
using cabral::ScanType;
using cabral::TimingProfile;
using cabral::cli::Action;
using cabral::cli::parseArguments;
using cabral::cli::ParsedArguments;

namespace {

auto parse(std::initializer_list<std::string_view> args) {
    std::vector<std::string_view> storage(args);
    return parseArguments(storage);
}

ParsedArguments parseOk(std::initializer_list<std::string_view> args) {
    auto result = parse(args);
    EXPECT_TRUE(result.hasValue());
    return result.hasValue() ? std::move(result).value() : ParsedArguments{};
}

} // namespace

TEST(ArgParser, DefaultsToConnectScan) {
    const auto parsed = parseOk({"127.0.0.1"});
    EXPECT_EQ(parsed.action, Action::Scan);
    EXPECT_EQ(parsed.config.scanType, ScanType::Connect);
    EXPECT_EQ(parsed.config.timing, TimingProfile::Normal);
    ASSERT_EQ(parsed.targets.size(), 1u);
    EXPECT_EQ(parsed.targets[0], "127.0.0.1");
}

TEST(ArgParser, RecognizesEveryScanType) {
    EXPECT_EQ(parseOk({"-sT", "h"}).config.scanType, ScanType::Connect);
    EXPECT_EQ(parseOk({"-sS", "h"}).config.scanType, ScanType::Syn);
    EXPECT_EQ(parseOk({"-sU", "h"}).config.scanType, ScanType::Udp);
    EXPECT_EQ(parseOk({"-sn", "h"}).config.scanType, ScanType::PingSweep);
}

TEST(ArgParser, ParsesPortSpecification) {
    const auto parsed = parseOk({"-p", "22,80,443", "h"});
    EXPECT_EQ(parsed.config.ports, (std::vector<cabral::Port>{22, 80, 443}));
}

TEST(ArgParser, AppliesDefaultPortsWhenUnspecified) {
    EXPECT_EQ(parseOk({"h"}).config.ports.size(), 1024u);
}

TEST(ArgParser, PingSweepDoesNotGetDefaultPorts) {
    EXPECT_TRUE(parseOk({"-sn", "h"}).config.ports.empty());
}

TEST(ArgParser, ParsesTimingProfiles) {
    EXPECT_EQ(parseOk({"-T0", "h"}).config.timing, TimingProfile::Paranoid);
    EXPECT_EQ(parseOk({"-T5", "h"}).config.timing, TimingProfile::Insane);
}

TEST(ArgParser, TimeoutOverridesProfile) {
    const auto parsed = parseOk({"-T0", "--timeout", "250", "h"});
    EXPECT_EQ(parsed.config.effectiveTimeout(), std::chrono::milliseconds(250));
}

TEST(ArgParser, ProfileDrivesTimeoutWithoutOverride) {
    EXPECT_EQ(parseOk({"-T3", "h"}).config.effectiveTimeout(), std::chrono::milliseconds(1000));
}

TEST(ArgParser, ParsesFlagsAndOutputs) {
    const auto parsed = parseOk({"-Pn", "-vv", "--allow-large-range", "-oJ", "out.json", "h"});
    EXPECT_TRUE(parsed.config.skipHostDiscovery);
    EXPECT_TRUE(parsed.config.allowLargeRange);
    EXPECT_EQ(parsed.config.verbosity, 2);
    EXPECT_EQ(parsed.config.outputFormat, OutputFormat::Json);
    EXPECT_EQ(parsed.config.outputPath, "out.json");
}

TEST(ArgParser, ParsesTargetListAndTopPorts) {
    const auto parsed = parseOk({"-iL", "targets.txt", "--top-ports", "100"});
    EXPECT_EQ(parsed.targetListFile, "targets.txt");
    EXPECT_EQ(parsed.topPorts, 100);
}

TEST(ArgParser, AcceptsMultipleTargets) {
    const auto parsed = parseOk({"10.0.0.1", "10.0.0.2", "scanme.nmap.org"});
    EXPECT_EQ(parsed.targets.size(), 3u);
}

TEST(ArgParser, HelpAndVersionShortCircuit) {
    EXPECT_EQ(parseOk({"-h"}).action, Action::ShowHelp);
    EXPECT_EQ(parseOk({"--help"}).action, Action::ShowHelp);
    EXPECT_EQ(parseOk({"--version"}).action, Action::ShowVersion);
}

// Aceite da Fase 1: 'cabral -p 1-100 --help' imprime uso, sem exigir alvo.
TEST(ArgParser, HelpWinsOverMissingTarget) {
    const auto parsed = parseOk({"-p", "1-100", "--help"});
    EXPECT_EQ(parsed.action, Action::ShowHelp);
}

TEST(ArgParser, RejectsMissingTarget) {
    EXPECT_FALSE(parse({"-sT"}).hasValue());
}

TEST(ArgParser, RejectsUnknownOption) {
    EXPECT_FALSE(parse({"--nope", "h"}).hasValue());
    EXPECT_FALSE(parse({"-sX", "h"}).hasValue());
}

TEST(ArgParser, RejectsOptionMissingItsValue) {
    EXPECT_FALSE(parse({"-p"}).hasValue());
    EXPECT_FALSE(parse({"--timeout"}).hasValue());
    EXPECT_FALSE(parse({"-iL"}).hasValue());
}

TEST(ArgParser, RejectsInvalidValues) {
    EXPECT_FALSE(parse({"-p", "0", "h"}).hasValue());
    EXPECT_FALSE(parse({"-p", "http", "h"}).hasValue());
    EXPECT_FALSE(parse({"--timeout", "0", "h"}).hasValue());
    EXPECT_FALSE(parse({"--timeout", "abc", "h"}).hasValue());
    EXPECT_FALSE(parse({"--top-ports", "0", "h"}).hasValue());
    EXPECT_FALSE(parse({"-T6", "h"}).hasValue());
}

TEST(ArgParser, RejectsPortsCombinedWithTopPorts) {
    EXPECT_FALSE(parse({"-p", "80", "--top-ports", "10", "h"}).hasValue());
}

TEST(ArgParser, ErrorMessageIsNotEmpty) {
    auto result = parse({"--nope", "h"});
    ASSERT_FALSE(result.hasValue());
    EXPECT_FALSE(result.error().message.empty());
}
