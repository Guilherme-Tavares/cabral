#include <cabral/discovery/TargetExpander.hpp>

#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using cabral::IpAddress;
using cabral::discovery::expandTarget;
using cabral::discovery::expandTargetFile;
using cabral::discovery::expandTargets;
using cabral::discovery::ExpansionOptions;
using cabral::discovery::TargetError;

namespace {

/// Sem resolução de nome: mantém os testes determinísticos e independentes de DNS.
ExpansionOptions offline(bool allowLarge = false) {
    ExpansionOptions options;
    options.resolveHostnames = false;
    options.allowLargeRange = allowLarge;
    return options;
}

std::vector<std::string> toStrings(const std::vector<IpAddress>& addresses) {
    std::vector<std::string> out;
    out.reserve(addresses.size());
    for (const auto& address : addresses) {
        out.push_back(address.toString());
    }
    return out;
}

} // namespace

TEST(TargetExpander, ExpandsSingleAddress) {
    auto result = expandTarget("192.168.1.10", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(toStrings(result.value()), (std::vector<std::string>{"192.168.1.10"}));
}

TEST(TargetExpander, ExpandsSlash24) {
    auto result = expandTarget("192.168.1.0/24", offline());
    ASSERT_TRUE(result.hasValue());
    const auto& addresses = result.value();
    ASSERT_EQ(addresses.size(), 256u);
    EXPECT_EQ(addresses.front().toString(), "192.168.1.0");
    EXPECT_EQ(addresses.back().toString(), "192.168.1.255");
}

// 192.168.1.37/24 é a rede 192.168.1.0/24: os bits de host são zerados.
TEST(TargetExpander, CidrMasksHostBits) {
    auto result = expandTarget("192.168.1.37/24", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().front().toString(), "192.168.1.0");
}

TEST(TargetExpander, ExpandsSlash32AsSingleHost) {
    auto result = expandTarget("10.0.0.5/32", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(toStrings(result.value()), (std::vector<std::string>{"10.0.0.5"}));
}

TEST(TargetExpander, ExpandsSlash31WithBothHosts) {
    auto result = expandTarget("10.0.0.4/31", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(toStrings(result.value()), (std::vector<std::string>{"10.0.0.4", "10.0.0.5"}));
}

TEST(TargetExpander, ExpandsHyphenRange) {
    auto result = expandTarget("192.168.1.10-13", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(
        toStrings(result.value()),
        (std::vector<std::string>{"192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"}));
}

TEST(TargetExpander, ExpandsCommaSeparatedList) {
    auto result = expandTarget("10.0.0.1,10.0.0.3,10.0.0.2", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(toStrings(result.value()),
              (std::vector<std::string>{"10.0.0.1", "10.0.0.2", "10.0.0.3"}));
}

TEST(TargetExpander, ResultIsSortedAndDeduplicated) {
    auto result = expandTarget("10.0.0.2,10.0.0.1,10.0.0.1", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(toStrings(result.value()), (std::vector<std::string>{"10.0.0.1", "10.0.0.2"}));
}

TEST(TargetExpander, MixesFormsInOneSpec) {
    auto result = expandTarget("10.0.0.1,10.0.1.0/30,10.0.2.5-6", offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().size(), 7u);
}

// Guarda de faixa: /16 são 65 mil hosts, quase sempre digitação errada.
TEST(TargetExpander, RejectsRangeWiderThanSlash24ByDefault) {
    auto result = expandTarget("10.0.0.0/16", offline());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), TargetError::RangeTooLarge);
}

TEST(TargetExpander, AllowsLargeRangeWhenRequested) {
    auto result = expandTarget("10.0.0.0/23", offline(true));
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().size(), 512u);
}

TEST(TargetExpander, RejectsMalformedInput) {
    EXPECT_FALSE(expandTarget("", offline()).hasValue());
    EXPECT_FALSE(expandTarget("192.168.1", offline()).hasValue());
    EXPECT_FALSE(expandTarget("192.168.1.256", offline()).hasValue());
    EXPECT_FALSE(expandTarget("10.0.0.1/33", offline()).hasValue());
    EXPECT_FALSE(expandTarget("10.0.0.1/abc", offline()).hasValue());
}

TEST(TargetExpander, RejectsInvertedHyphenRange) {
    auto result = expandTarget("192.168.1.50-10", offline());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), TargetError::InvertedRange);
}

TEST(TargetExpander, RejectsHostnameWhenResolutionDisabled) {
    auto result = expandTarget("scanme.nmap.org", offline());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), TargetError::UnresolvedHostname);
}

TEST(TargetExpander, ExpandsMultipleSpecs) {
    const std::vector<std::string> specs{"10.0.0.1", "10.0.0.2-3"};
    auto result = expandTargets(specs, offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().size(), 3u);
}

TEST(TargetExpander, EveryErrorHasDescription) {
    for (auto error :
         {TargetError::Empty, TargetError::MalformedAddress, TargetError::MalformedCidr,
          TargetError::PrefixOutOfRange, TargetError::MalformedRange, TargetError::InvertedRange,
          TargetError::RangeTooLarge, TargetError::UnresolvedHostname}) {
        EXPECT_FALSE(cabral::discovery::describe(error).empty());
    }
}

TEST(TargetExpander, ReadsTargetsFromFile) {
    const std::string path = "cabral_targets_test.txt";
    {
        std::ofstream file(path);
        file << "# comentario\n"
             << "10.0.0.1\n"
             << "\n"
             << "10.0.0.5-6   # com comentario ao lado\n";
    }

    auto result = expandTargetFile(path, offline());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(toStrings(result.value()),
              (std::vector<std::string>{"10.0.0.1", "10.0.0.5", "10.0.0.6"}));

    std::remove(path.c_str());
}

TEST(TargetExpander, MissingFileIsAnError) {
    EXPECT_FALSE(expandTargetFile("no_such_file_here.txt", offline()).hasValue());
}
