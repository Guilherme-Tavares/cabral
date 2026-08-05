#include <cabral/net/PacketBuilder.hpp>
#include <cabral/scan/UdpPayloads.hpp>
#include <cabral/scan/UdpScanner.hpp>

#include <algorithm>
#include <cstdint>
#include <stop_token>
#include <vector>

#include <gtest/gtest.h>

using cabral::IpAddress;
using cabral::Port;
using cabral::PortState;
using cabral::ScanConfig;
using cabral::net::buildEchoRequest;
using cabral::net::EchoParams;
using cabral::net::internetChecksum;
using cabral::net::kIcmpDestinationUnreachable;
using cabral::net::kIcmpEchoReply;
using cabral::net::kIcmpEchoRequest;
using cabral::net::parseIcmpMessage;
using cabral::scan::payloadFor;
using cabral::scan::UdpScanner;
namespace icmp_code = cabral::net::icmp_code;

namespace {

/// Monta um datagrama IPv4 contendo uma mensagem ICMP, como o raw socket entregaria.
///
/// `rest` ocupa os octetos 4-7 do cabeçalho ICMP: identificador e sequência no echo, campo
/// não usado nas mensagens de erro. `body` vem depois, a partir do octeto 8.
std::vector<std::uint8_t> wrapIcmp(std::string_view sourceIp, std::uint8_t type, std::uint8_t code,
                                   const std::vector<std::uint8_t>& body, std::uint32_t rest = 0) {
    std::vector<std::uint8_t> datagram(20 + 8 + body.size(), 0);

    datagram[0] = 0x45;
    datagram[9] = 1; // IPPROTO_ICMP
    const auto source = *IpAddress::parse(sourceIp);
    for (int i = 0; i < 4; ++i) {
        datagram[12 + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((source.value() >> (24 - 8 * i)) & 0xFF);
    }

    datagram[20] = type;
    datagram[21] = code;
    for (int i = 0; i < 4; ++i) {
        datagram[24 + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((rest >> (24 - 8 * i)) & 0xFF);
    }
    std::copy(body.begin(), body.end(), datagram.begin() + 28);
    return datagram;
}

/// Corpo de um tipo 3: o datagrama UDP original citado pela mensagem de erro.
std::vector<std::uint8_t> quotedUdpDatagram(std::string_view destinationIp, Port sourcePort,
                                            Port destinationPort) {
    std::vector<std::uint8_t> quoted(20 + 8, 0);
    quoted[0] = 0x45;
    quoted[9] = 17; // IPPROTO_UDP

    const auto destination = *IpAddress::parse(destinationIp);
    for (int i = 0; i < 4; ++i) {
        quoted[16 + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((destination.value() >> (24 - 8 * i)) & 0xFF);
    }

    quoted[20] = static_cast<std::uint8_t>((sourcePort >> 8) & 0xFF);
    quoted[21] = static_cast<std::uint8_t>(sourcePort & 0xFF);
    quoted[22] = static_cast<std::uint8_t>((destinationPort >> 8) & 0xFF);
    quoted[23] = static_cast<std::uint8_t>(destinationPort & 0xFF);
    return quoted;
}

std::uint16_t readUint16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
}

} // namespace

TEST(EchoRequest, HasValidTypeAndChecksum) {
    EchoParams params;
    params.identifier = 0xABCD;
    params.sequence = 7;

    const auto packet = buildEchoRequest(params);
    EXPECT_EQ(packet[0], kIcmpEchoRequest);
    EXPECT_EQ(packet[1], 0);
    EXPECT_EQ(readUint16(packet.data() + 4), 0xABCD);
    EXPECT_EQ(readUint16(packet.data() + 6), 7);

    // Mensagem válida soma zero quando o próprio checksum é incluído.
    EXPECT_EQ(internetChecksum(packet), 0);
}

TEST(ParseIcmp, ReadsEchoReply) {
    // Identificador 0x1234 e sequência 5 ocupam os octetos 4-7 do cabeçalho ICMP.
    const auto datagram = wrapIcmp("10.0.0.7", kIcmpEchoReply, 0, {}, 0x12340005u);
    const auto message = parseIcmpMessage(datagram);

    ASSERT_TRUE(message.has_value());
    EXPECT_EQ(message->type, kIcmpEchoReply);
    EXPECT_EQ(message->source, *IpAddress::parse("10.0.0.7"));
    EXPECT_EQ(message->identifier, 0x1234);
    EXPECT_EQ(message->sequence, 5);
}

// Port unreachable é a única evidência de porta UDP fechada.
TEST(ParseIcmp, PortUnreachableCarriesOriginalPorts) {
    const auto body = quotedUdpDatagram("192.168.1.50", 45000, 161);
    const auto datagram =
        wrapIcmp("192.168.1.50", kIcmpDestinationUnreachable, icmp_code::PortUnreachable, body);

    const auto message = parseIcmpMessage(datagram);
    ASSERT_TRUE(message.has_value());
    EXPECT_TRUE(message->isPortUnreachable());
    EXPECT_FALSE(message->isFilteredIndication());
    ASSERT_TRUE(message->hasOriginalDatagram);
    EXPECT_EQ(message->originalDestination, *IpAddress::parse("192.168.1.50"));
    EXPECT_EQ(message->originalProtocol, 17);
    EXPECT_EQ(message->originalSourcePort, 45000);
    EXPECT_EQ(message->originalDestinationPort, 161);
}

TEST(ParseIcmp, ProhibitedCodesMeanFiltered) {
    for (std::uint8_t code :
         {icmp_code::NetUnreachable, icmp_code::HostUnreachable, icmp_code::NetProhibited,
          icmp_code::HostProhibited, icmp_code::CommunicationProhibited}) {
        const auto body = quotedUdpDatagram("10.0.0.1", 40000, 53);
        const auto datagram = wrapIcmp("10.0.0.1", kIcmpDestinationUnreachable, code, body);

        const auto message = parseIcmpMessage(datagram);
        ASSERT_TRUE(message.has_value()) << "code " << static_cast<int>(code);
        EXPECT_TRUE(message->isFilteredIndication()) << "code " << static_cast<int>(code);
        EXPECT_FALSE(message->isPortUnreachable()) << "code " << static_cast<int>(code);
    }
}

TEST(ParseIcmp, RejectsMalformedDatagrams) {
    EXPECT_FALSE(parseIcmpMessage({}).has_value());

    std::vector<std::uint8_t> tooShort(10, 0);
    tooShort[0] = 0x45;
    EXPECT_FALSE(parseIcmpMessage(tooShort).has_value());

    auto wrongProtocol = wrapIcmp("10.0.0.1", kIcmpEchoReply, 0, {});
    wrongProtocol[9] = 6; // TCP
    EXPECT_FALSE(parseIcmpMessage(wrongProtocol).has_value());
}

TEST(ParseIcmp, TruncatedQuotedDatagramIsTolerated) {
    // Alguns dispositivos citam menos do que o exigido; a mensagem ainda é legível, apenas
    // sem correlação possível.
    auto datagram = wrapIcmp("10.0.0.1", kIcmpDestinationUnreachable, icmp_code::PortUnreachable,
                             std::vector<std::uint8_t>(8, 0));
    const auto message = parseIcmpMessage(datagram);
    ASSERT_TRUE(message.has_value());
    EXPECT_FALSE(message->hasOriginalDatagram);
}

// Datagrama vazio quase nunca provoca resposta; a sonda específica é o que revela Open.
TEST(UdpPayloads, WellKnownPortsGetProtocolSpecificProbes) {
    EXPECT_FALSE(payloadFor(53).empty());
    EXPECT_FALSE(payloadFor(123).empty());
    EXPECT_FALSE(payloadFor(161).empty());
    EXPECT_TRUE(payloadFor(9999).empty());
}

TEST(UdpPayloads, DnsQueryIsWellFormed) {
    const auto payload = payloadFor(53);
    ASSERT_GE(payload.size(), 12u);
    // Um bit de resposta ligado indicaria que a sonda é uma resposta, não uma consulta.
    EXPECT_EQ(payload[2] & 0x80, 0);
    EXPECT_EQ(readUint16(payload.data() + 4), 1); // exatamente uma pergunta
}

TEST(UdpPayloads, NtpRequestIsClientMode) {
    const auto payload = payloadFor(123);
    ASSERT_EQ(payload.size(), 48u);
    EXPECT_EQ(payload[0] & 0x07, 3);        // modo 3 = client
    EXPECT_EQ((payload[0] >> 3) & 0x07, 4); // versão 4
}

/// A aritmética BER precisa fechar: comprimentos declarados que não batem com o corpo
/// fazem o agente descartar o pacote em silêncio.
TEST(UdpPayloads, SnmpGetHasConsistentBerLengths) {
    const auto payload = payloadFor(161);
    ASSERT_GE(payload.size(), 2u);

    EXPECT_EQ(payload[0], 0x30); // SEQUENCE
    // Comprimento declarado deve cobrir exatamente o que vem depois dos dois primeiros
    // octetos.
    EXPECT_EQ(payload[1] + 2u, payload.size());

    // A PDU GetRequest também precisa declarar o próprio tamanho corretamente.
    const auto pduIt = std::find(payload.begin(), payload.end(), 0xA0);
    ASSERT_NE(pduIt, payload.end());
    const std::size_t pduIndex = static_cast<std::size_t>(pduIt - payload.begin());
    ASSERT_LT(pduIndex + 1, payload.size());
    EXPECT_EQ(payload[pduIndex + 1] + pduIndex + 2u, payload.size());
}

TEST(UdpScanner, ReportsMetadata) {
    UdpScanner scanner;
    EXPECT_EQ(scanner.protocol(), cabral::Protocol::Udp);
    EXPECT_EQ(scanner.name(), "udp");

    // O envio usa socket UDP comum: exigir raw socket eliminaria -sU do Windows, onde a
    // arquitetura prevê suporte com resultado degradado.
    EXPECT_FALSE(scanner.requiresRawSocket());
}

TEST(UdpScanner, EmptyPortListYieldsNoResults) {
    UdpScanner scanner;
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), {}, ScanConfig{}, std::stop_token{});
    EXPECT_TRUE(results.empty());
}

TEST(UdpScanner, StopRequestYieldsUnknown) {
    std::stop_source source;
    source.request_stop();

    UdpScanner scanner;
    const std::vector<Port> ports{53, 123, 161};
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, ScanConfig{}, source.get_token());

    ASSERT_EQ(results.size(), ports.size());
    EXPECT_TRUE(std::all_of(results.begin(), results.end(),
                            [](const auto& r) { return r.state == PortState::Unknown; }));
}

TEST(UdpScanner, ResultsAreUdpProtocolAndSorted) {
    UdpScanner scanner;
    auto config = ScanConfig{};
    config.timeoutOverride = std::chrono::milliseconds(100);
    config.timing = cabral::TimingProfile::Insane;

    const std::vector<Port> ports{161, 53, 123};
    const auto results =
        scanner.scan(*IpAddress::parse("127.0.0.1"), ports, config, std::stop_token{});

    ASSERT_EQ(results.size(), ports.size());
    EXPECT_TRUE(std::is_sorted(results.begin(), results.end(),
                               [](const auto& a, const auto& b) { return a.port < b.port; }));
    for (const auto& result : results) {
        EXPECT_EQ(result.protocol, cabral::Protocol::Udp);
    }
}
