#include <cabral/net/PacketBuilder.hpp>

#include <array>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

using cabral::IpAddress;
using cabral::net::buildSynPacket;
using cabral::net::internetChecksum;
using cabral::net::kIpv4HeaderSize;
using cabral::net::kSynPacketSize;
using cabral::net::kTcpHeaderSize;
using cabral::net::parseTcpResponse;
using cabral::net::SynPacketParams;
namespace tcp_flag = cabral::net::tcp_flag;

namespace {

std::uint16_t readUint16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) | data[1]);
}

SynPacketParams defaultParams() {
    SynPacketParams params;
    params.source = *IpAddress::parse("192.168.1.10");
    params.destination = *IpAddress::parse("192.168.1.20");
    params.sourcePort = 45000;
    params.destinationPort = 80;
    params.sequence = 0x12345678;
    params.ipId = 0xABCD;
    return params;
}

/// Recalcula o checksum TCP sobre o pacote montado. Um segmento válido soma zero quando o
/// próprio campo de checksum é incluído — propriedade do complemento de um.
std::uint16_t verifyTcpChecksum(const std::array<std::uint8_t, kSynPacketSize>& packet,
                                const SynPacketParams& params) {
    std::vector<std::uint8_t> block;
    block.reserve(12 + kTcpHeaderSize);

    const std::uint32_t source = params.source.value();
    const std::uint32_t destination = params.destination.value();
    for (int shift : {24, 16, 8, 0}) {
        block.push_back(static_cast<std::uint8_t>((source >> shift) & 0xFF));
    }
    for (int shift : {24, 16, 8, 0}) {
        block.push_back(static_cast<std::uint8_t>((destination >> shift) & 0xFF));
    }
    block.push_back(0);
    block.push_back(6);
    block.push_back(0);
    block.push_back(static_cast<std::uint8_t>(kTcpHeaderSize));

    block.insert(block.end(), packet.begin() + kIpv4HeaderSize, packet.end());
    return internetChecksum(block);
}

} // namespace

// RFC 1071: soma em complemento de um sobre palavras de 16 bits, resultado complementado.
TEST(InternetChecksum, MatchesRfc1071Example) {
    const std::array<std::uint8_t, 8> data{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
    EXPECT_EQ(internetChecksum(data), 0x220d);
}

TEST(InternetChecksum, EmptyInputYieldsComplementOfZero) {
    EXPECT_EQ(internetChecksum({}), 0xFFFF);
}

TEST(InternetChecksum, HandlesOddLength) {
    const std::array<std::uint8_t, 3> odd{0x12, 0x34, 0x56};
    const std::array<std::uint8_t, 4> padded{0x12, 0x34, 0x56, 0x00};
    // O octeto final entra como metade alta de uma palavra: equivale a completar com zero.
    EXPECT_EQ(internetChecksum(odd), internetChecksum(padded));
}

TEST(InternetChecksum, IncludingChecksumYieldsZero) {
    std::array<std::uint8_t, 6> header{0x45, 0x00, 0x00, 0x28, 0x00, 0x00};
    const std::uint16_t sum = internetChecksum(header);

    std::array<std::uint8_t, 8> withSum{};
    std::copy(header.begin(), header.end(), withSum.begin());
    withSum[6] = static_cast<std::uint8_t>((sum >> 8) & 0xFF);
    withSum[7] = static_cast<std::uint8_t>(sum & 0xFF);

    EXPECT_EQ(internetChecksum(withSum), 0);
}

TEST(SynPacket, HasExpectedSize) {
    const auto packet = buildSynPacket(defaultParams());
    EXPECT_EQ(packet.size(), 40u);
    EXPECT_EQ(kIpv4HeaderSize + kTcpHeaderSize, kSynPacketSize);
}

TEST(SynPacket, WritesIpv4Header) {
    const auto params = defaultParams();
    const auto packet = buildSynPacket(params);

    EXPECT_EQ(packet[0], 0x45); // versão 4, IHL 5
    EXPECT_EQ(readUint16(packet.data() + 2), kSynPacketSize);
    EXPECT_EQ(readUint16(packet.data() + 4), params.ipId);
    EXPECT_EQ(packet[9], 6); // IPPROTO_TCP
    EXPECT_EQ(packet[8], 64);
}

TEST(SynPacket, WritesAddressesInNetworkOrder) {
    const auto params = defaultParams();
    const auto packet = buildSynPacket(params);

    EXPECT_EQ(packet[12], 192);
    EXPECT_EQ(packet[13], 168);
    EXPECT_EQ(packet[14], 1);
    EXPECT_EQ(packet[15], 10);

    EXPECT_EQ(packet[16], 192);
    EXPECT_EQ(packet[19], 20);
}

TEST(SynPacket, WritesTcpHeaderWithSynFlagOnly) {
    const auto params = defaultParams();
    const auto packet = buildSynPacket(params);
    const std::uint8_t* tcp = packet.data() + kIpv4HeaderSize;

    EXPECT_EQ(readUint16(tcp + 0), params.sourcePort);
    EXPECT_EQ(readUint16(tcp + 2), params.destinationPort);
    EXPECT_EQ(tcp[12], 0x50); // data offset 5 palavras
    EXPECT_EQ(tcp[13], tcp_flag::Syn);
    EXPECT_EQ(tcp[13] & tcp_flag::Ack, 0);
    EXPECT_EQ(tcp[13] & tcp_flag::Rst, 0);
}

TEST(SynPacket, IpChecksumIsValid) {
    const auto packet = buildSynPacket(defaultParams());
    // Cabeçalho válido soma zero quando o próprio checksum é incluído.
    EXPECT_EQ(internetChecksum({packet.data(), kIpv4HeaderSize}), 0);
}

// Sem o pseudo-header o alvo descarta o segmento em silêncio, sem erro no emissor.
TEST(SynPacket, TcpChecksumCoversPseudoHeader) {
    const auto params = defaultParams();
    const auto packet = buildSynPacket(params);

    EXPECT_NE(readUint16(packet.data() + kIpv4HeaderSize + 16), 0);
    EXPECT_EQ(verifyTcpChecksum(packet, params), 0);
}

TEST(SynPacket, ChecksumChangesWithDestination) {
    auto first = defaultParams();
    auto second = defaultParams();
    second.destination = *IpAddress::parse("10.0.0.1");

    const auto packetA = buildSynPacket(first);
    const auto packetB = buildSynPacket(second);

    EXPECT_NE(readUint16(packetA.data() + kIpv4HeaderSize + 16),
              readUint16(packetB.data() + kIpv4HeaderSize + 16));
}

TEST(ParseTcpResponse, ReadsSynAck) {
    auto params = defaultParams();
    auto packet = buildSynPacket(params);
    packet[kIpv4HeaderSize + 13] = tcp_flag::Syn | tcp_flag::Ack;

    const auto response = parseTcpResponse(packet);
    ASSERT_TRUE(response.has_value());
    EXPECT_TRUE(response->isSynAck());
    EXPECT_FALSE(response->isRst());
    EXPECT_EQ(response->sourcePort, params.sourcePort);
    EXPECT_EQ(response->source, params.source);
}

TEST(ParseTcpResponse, ReadsRst) {
    auto packet = buildSynPacket(defaultParams());
    packet[kIpv4HeaderSize + 13] = tcp_flag::Rst | tcp_flag::Ack;

    const auto response = parseTcpResponse(packet);
    ASSERT_TRUE(response.has_value());
    EXPECT_TRUE(response->isRst());
    EXPECT_FALSE(response->isSynAck());
}

TEST(ParseTcpResponse, RejectsTruncatedDatagram) {
    const auto packet = buildSynPacket(defaultParams());
    EXPECT_FALSE(parseTcpResponse({packet.data(), 10}).has_value());
    EXPECT_FALSE(parseTcpResponse({packet.data(), kIpv4HeaderSize}).has_value());
    EXPECT_FALSE(parseTcpResponse({}).has_value());
}

TEST(ParseTcpResponse, RejectsNonIpv4) {
    auto packet = buildSynPacket(defaultParams());
    packet[0] = 0x65; // versão 6
    EXPECT_FALSE(parseTcpResponse(packet).has_value());
}

TEST(ParseTcpResponse, RejectsNonTcpProtocol) {
    auto packet = buildSynPacket(defaultParams());
    packet[9] = 17; // UDP
    EXPECT_FALSE(parseTcpResponse(packet).has_value());
}

// Cabeçalho com opções é maior que 20 octetos; assumir tamanho fixo leria o lugar errado.
TEST(ParseTcpResponse, RespectsIhlWithOptions) {
    std::vector<std::uint8_t> datagram(24 + kTcpHeaderSize, 0);
    datagram[0] = 0x46; // IHL 6 palavras = 24 octetos
    datagram[9] = 6;
    datagram[12] = 10;
    datagram[13] = 0;
    datagram[14] = 0;
    datagram[15] = 5;

    std::uint8_t* tcp = datagram.data() + 24;
    tcp[0] = 0x01;
    tcp[1] = 0xBB; // porta de origem 443
    tcp[13] = tcp_flag::Syn | tcp_flag::Ack;

    const auto response = parseTcpResponse(datagram);
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->sourcePort, 443);
    EXPECT_TRUE(response->isSynAck());
    EXPECT_EQ(response->source, *IpAddress::parse("10.0.0.5"));
}
