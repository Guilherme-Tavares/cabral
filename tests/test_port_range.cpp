#include <cabral/model/PortRange.hpp>

#include <vector>

#include <gtest/gtest.h>

using cabral::parsePortSpec;
using cabral::Port;
using cabral::PortSpecError;

namespace {

std::vector<Port> portsOf(std::string_view spec) {
    auto result = parsePortSpec(spec);
    EXPECT_TRUE(result.hasValue()) << spec;
    return result.hasValue() ? std::move(result).value() : std::vector<Port>{};
}

} // namespace

TEST(PortSpec, ParsesSinglePort) {
    EXPECT_EQ(portsOf("22"), (std::vector<Port>{22}));
}

TEST(PortSpec, ParsesRange) {
    EXPECT_EQ(portsOf("20-25"), (std::vector<Port>{20, 21, 22, 23, 24, 25}));
}

TEST(PortSpec, ParsesCommaSeparatedList) {
    EXPECT_EQ(portsOf("22,80,443"), (std::vector<Port>{22, 80, 443}));
}

TEST(PortSpec, ParsesMixedListAndRange) {
    EXPECT_EQ(portsOf("22,100-102,443"), (std::vector<Port>{22, 100, 101, 102, 443}));
}

TEST(PortSpec, DashMeansEveryPort) {
    const auto ports = portsOf("-");
    ASSERT_EQ(ports.size(), 65535u);
    EXPECT_EQ(ports.front(), 1);
    EXPECT_EQ(ports.back(), 65535);
}

TEST(PortSpec, OmittedBoundsFallBackToLimits) {
    const auto low = portsOf("-100");
    EXPECT_EQ(low.front(), 1);
    EXPECT_EQ(low.back(), 100);

    const auto high = portsOf("65530-");
    EXPECT_EQ(high.front(), 65530);
    EXPECT_EQ(high.back(), 65535);
}

TEST(PortSpec, ResultIsSortedAndDeduplicated) {
    EXPECT_EQ(portsOf("443,22,80,22"), (std::vector<Port>{22, 80, 443}));
    EXPECT_EQ(portsOf("20-22,21-23"), (std::vector<Port>{20, 21, 22, 23}));
}

TEST(PortSpec, IgnoresSurroundingWhitespace) {
    EXPECT_EQ(portsOf(" 22 , 80 "), (std::vector<Port>{22, 80}));
}

TEST(PortSpec, AcceptsSinglePortRange) {
    EXPECT_EQ(portsOf("80-80"), (std::vector<Port>{80}));
}

TEST(PortSpec, RejectsEmptySpec) {
    auto result = parsePortSpec("");
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), PortSpecError::Empty);
}

TEST(PortSpec, RejectsEmptyToken) {
    EXPECT_FALSE(parsePortSpec("22,,80").hasValue());
    EXPECT_FALSE(parsePortSpec("22,").hasValue());
}

// Porta 0 é sintaticamente válida no protocolo, mas não é alvo de varredura.
TEST(PortSpec, RejectsPortZero) {
    auto result = parsePortSpec("0");
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), PortSpecError::PortOutOfRange);
}

TEST(PortSpec, RejectsPortAboveMaximum) {
    auto result = parsePortSpec("65536");
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), PortSpecError::PortOutOfRange);
    EXPECT_FALSE(parsePortSpec("99999999999").hasValue());
}

TEST(PortSpec, RejectsInvertedRange) {
    auto result = parsePortSpec("100-20");
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), PortSpecError::InvertedRange);
}

TEST(PortSpec, RejectsMalformedRange) {
    auto result = parsePortSpec("1-2-3");
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), PortSpecError::MalformedRange);
}

TEST(PortSpec, RejectsNonNumericInput) {
    auto result = parsePortSpec("http");
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error(), PortSpecError::InvalidCharacter);
    EXPECT_FALSE(parsePortSpec("8o").hasValue());
}

TEST(PortSpec, EveryErrorHasDescription) {
    for (auto error :
         {PortSpecError::Empty, PortSpecError::InvalidCharacter, PortSpecError::PortOutOfRange,
          PortSpecError::InvertedRange, PortSpecError::MalformedRange}) {
        EXPECT_FALSE(cabral::describe(error).empty());
    }
}
