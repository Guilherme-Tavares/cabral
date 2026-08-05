#include <ResultWriter.hpp>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using cabral::HostResult;
using cabral::IpAddress;
using cabral::OutputFormat;
using cabral::PortResult;
using cabral::PortState;
using cabral::Protocol;
using cabral::ScanConfig;
using cabral::ScanType;
using cabral::cli::escapeJson;
using cabral::cli::ScanSummary;
using cabral::cli::toJson;
using cabral::cli::toText;
using cabral::cli::writeToFile;

namespace {

HostResult sampleHost() {
    HostResult host;
    host.address = *IpAddress::parse("192.168.1.10");
    host.hostname = "target.local";
    host.isUp = true;

    PortResult open;
    open.port = 80;
    open.protocol = Protocol::Tcp;
    open.state = PortState::Open;
    open.service = "http";
    open.rtt = std::chrono::milliseconds(12);
    host.ports.push_back(open);

    PortResult filtered;
    filtered.port = 22;
    filtered.protocol = Protocol::Tcp;
    filtered.state = PortState::Filtered;
    filtered.service = "ssh";
    host.ports.push_back(filtered);

    return host;
}

ScanSummary sampleSummary() {
    ScanSummary summary;
    summary.hostsScanned = 1;
    summary.hostsUp = 1;
    summary.openPorts = 1;
    summary.elapsed = std::chrono::milliseconds(1500);
    return summary;
}

bool contains(const std::string& haystack, std::string_view needle) {
    return haystack.find(needle) != std::string::npos;
}

/// Verificação de balanceamento: um JSON malformado costuma quebrar aqui antes de qualquer
/// outra coisa, e o projeto não tem parser para conferir de verdade.
bool bracesBalanced(const std::string& text) {
    int braces = 0;
    int brackets = 0;
    bool inString = false;
    bool escaped = false;

    for (const char c : text) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (inString) {
            if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                inString = false;
            }
            continue;
        }
        switch (c) {
        case '"':
            inString = true;
            break;
        case '{':
            ++braces;
            break;
        case '}':
            --braces;
            break;
        case '[':
            ++brackets;
            break;
        case ']':
            --brackets;
            break;
        default:
            break;
        }
        if (braces < 0 || brackets < 0) {
            return false;
        }
    }
    return braces == 0 && brackets == 0 && !inString;
}

} // namespace

TEST(EscapeJson, LeavesPlainTextAlone) {
    EXPECT_EQ(escapeJson("http"), "http");
    EXPECT_EQ(escapeJson(""), "");
}

TEST(EscapeJson, EscapesQuotesAndBackslashes) {
    EXPECT_EQ(escapeJson("say \"hi\""), "say \\\"hi\\\"");
    EXPECT_EQ(escapeJson("C:\\path"), "C:\\\\path");
}

TEST(EscapeJson, EscapesNamedControls) {
    EXPECT_EQ(escapeJson("a\nb"), "a\\nb");
    EXPECT_EQ(escapeJson("a\tb"), "a\\tb");
    EXPECT_EQ(escapeJson("a\rb"), "a\\rb");
}

/// Nomes de serviço vêm de /etc/services, que é editável pelo administrador: conteúdo
/// inesperado não pode quebrar o JSON.
TEST(EscapeJson, EscapesOtherControlCharacters) {
    EXPECT_EQ(escapeJson(std::string(1, '\x01')), "\\u0001");
    EXPECT_EQ(escapeJson(std::string(1, '\x1f')), "\\u001f");
}

TEST(EscapeJson, PassesUtf8Through) {
    // Sequências multibyte são válidas em JSON e não precisam de escape.
    EXPECT_EQ(escapeJson("serviço"), "serviço");
}

TEST(ToJson, ProducesBalancedDocument) {
    const std::vector<HostResult> hosts{sampleHost()};
    const auto json = toJson(hosts, sampleSummary(), ScanConfig{});
    EXPECT_TRUE(bracesBalanced(json)) << json;
}

TEST(ToJson, IncludesScanMetadata) {
    ScanConfig config;
    config.scanType = ScanType::Syn;
    config.timing = cabral::TimingProfile::Aggressive;

    const std::vector<HostResult> hosts{sampleHost()};
    const auto json = toJson(hosts, sampleSummary(), config);

    EXPECT_TRUE(contains(json, "\"tool\": \"cabral\""));
    EXPECT_TRUE(contains(json, "\"type\": \"syn\""));
    EXPECT_TRUE(contains(json, "\"timing\": \"T4\""));
}

TEST(ToJson, IncludesHostsAndPorts) {
    const std::vector<HostResult> hosts{sampleHost()};
    const auto json = toJson(hosts, sampleSummary(), ScanConfig{});

    EXPECT_TRUE(contains(json, "\"address\": \"192.168.1.10\""));
    EXPECT_TRUE(contains(json, "\"hostname\": \"target.local\""));
    EXPECT_TRUE(contains(json, "\"up\": true"));
    EXPECT_TRUE(contains(json, "\"port\": 80"));
    EXPECT_TRUE(contains(json, "\"state\": \"open\""));
    EXPECT_TRUE(contains(json, "\"service\": \"http\""));
    EXPECT_TRUE(contains(json, "\"rtt_ms\": 12"));
}

/// Portas filtradas entram no arquivo mesmo sem -v: o arquivo é para ser lido depois, e
/// descartar o que já foi observado perderia informação.
TEST(ToJson, IncludesNonOpenPorts) {
    const std::vector<HostResult> hosts{sampleHost()};
    const auto json = toJson(hosts, sampleSummary(), ScanConfig{});

    EXPECT_TRUE(contains(json, "\"port\": 22"));
    EXPECT_TRUE(contains(json, "\"state\": \"filtered\""));
}

TEST(ToJson, HandlesEmptyResults) {
    const auto json = toJson({}, ScanSummary{}, ScanConfig{});
    EXPECT_TRUE(bracesBalanced(json)) << json;
    EXPECT_TRUE(contains(json, "\"hosts\": []"));
}

TEST(ToJson, HandlesHostWithoutPorts) {
    HostResult host;
    host.address = *IpAddress::parse("10.0.0.1");
    host.isUp = true;

    const std::vector<HostResult> hosts{host};
    const auto json = toJson(hosts, sampleSummary(), ScanConfig{});

    EXPECT_TRUE(bracesBalanced(json)) << json;
    EXPECT_TRUE(contains(json, "\"ports\": []"));
}

TEST(ToJson, OpenFilteredKeepsItsName) {
    HostResult host;
    host.address = *IpAddress::parse("10.0.0.1");
    host.isUp = true;

    PortResult port;
    port.port = 53;
    port.protocol = Protocol::Udp;
    port.state = PortState::OpenFiltered;
    host.ports.push_back(port);

    const std::vector<HostResult> hosts{host};
    const auto json = toJson(hosts, sampleSummary(), ScanConfig{});

    EXPECT_TRUE(contains(json, "open|filtered"));
    EXPECT_TRUE(contains(json, "\"protocol\": \"udp\""));
}

TEST(ToText, IncludesHostsAndSummary) {
    const std::vector<HostResult> hosts{sampleHost()};
    const auto text = toText(hosts, sampleSummary());

    EXPECT_TRUE(contains(text, "192.168.1.10"));
    EXPECT_TRUE(contains(text, "80/tcp"));
    EXPECT_TRUE(contains(text, "http"));
    // Verbosidade forçada: o arquivo guarda o que foi observado, não só o que interessa.
    EXPECT_TRUE(contains(text, "22/tcp"));
    EXPECT_TRUE(contains(text, "1 open port"));
}

TEST(WriteToFile, WritesAndReadsBack) {
    const std::string path = "cabral_writer_test.json";
    const std::string contents = "{\"ok\": true}\n";

    std::string error;
    ASSERT_TRUE(writeToFile(path, contents, error)) << error;

    std::ifstream file(path, std::ios::binary);
    ASSERT_TRUE(file);
    std::ostringstream buffer;
    buffer << file.rdbuf();
    file.close();

    EXPECT_EQ(buffer.str(), contents);
    std::remove(path.c_str());
}

TEST(WriteToFile, ReportsFailureOnBadPath) {
    std::string error;
    EXPECT_FALSE(writeToFile("no_such_dir_here/out.json", "x", error));
    EXPECT_FALSE(error.empty());
}

TEST(WriteToFile, TruncatesExistingFile) {
    const std::string path = "cabral_writer_truncate.txt";

    std::string error;
    ASSERT_TRUE(writeToFile(path, "long previous contents", error));
    ASSERT_TRUE(writeToFile(path, "short", error));

    std::ifstream file(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << file.rdbuf();
    file.close();

    EXPECT_EQ(buffer.str(), "short");
    std::remove(path.c_str());
}
