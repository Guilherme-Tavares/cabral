#include <cabral/net/PacketBuilder.hpp>

#include <cstring>

namespace cabral::net {
namespace {

constexpr std::uint8_t kProtocolIcmp = 1;
constexpr std::uint8_t kProtocolTcp = 6;

void writeUint16(std::uint8_t* out, std::uint16_t value) noexcept {
    out[0] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[1] = static_cast<std::uint8_t>(value & 0xFF);
}

void writeUint32(std::uint8_t* out, std::uint32_t value) noexcept {
    out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[3] = static_cast<std::uint8_t>(value & 0xFF);
}

std::uint16_t readUint16(const std::uint8_t* in) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[0]) << 8) | in[1]);
}

std::uint32_t readUint32(const std::uint8_t* in) noexcept {
    return (static_cast<std::uint32_t>(in[0]) << 24) | (static_cast<std::uint32_t>(in[1]) << 16) |
           (static_cast<std::uint32_t>(in[2]) << 8) | static_cast<std::uint32_t>(in[3]);
}

/// Acumula em 32 bits e dobra o excesso no fim: evita perder o vai-um das somas parciais.
std::uint32_t sumWords(std::span<const std::uint8_t> data, std::uint32_t seed) noexcept {
    std::uint32_t sum = seed;
    std::size_t i = 0;

    for (; i + 1 < data.size(); i += 2) {
        sum += readUint16(data.data() + i);
    }
    // Octeto final ímpar entra como metade alta de uma palavra.
    if (i < data.size()) {
        sum += static_cast<std::uint32_t>(data[i]) << 8;
    }
    return sum;
}

std::uint16_t foldChecksum(std::uint32_t sum) noexcept {
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFF);
}

} // namespace

std::uint16_t internetChecksum(std::span<const std::uint8_t> data) noexcept {
    return foldChecksum(sumWords(data, 0));
}

std::array<std::uint8_t, kSynPacketSize> buildSynPacket(const SynPacketParams& params) noexcept {
    std::array<std::uint8_t, kSynPacketSize> packet{};
    std::uint8_t* const ip = packet.data();
    std::uint8_t* const tcp = packet.data() + kIpv4HeaderSize;

    // --- IPv4 (RFC 791) ---
    ip[0] = 0x45; // versão 4, IHL 5 palavras (sem opções)
    ip[1] = 0;    // DSCP/ECN
    writeUint16(ip + 2, static_cast<std::uint16_t>(kSynPacketSize));
    writeUint16(ip + 4, params.ipId);
    writeUint16(ip + 6, 0x4000); // don't fragment
    ip[8] = 64;                  // TTL
    ip[9] = kProtocolTcp;
    writeUint16(ip + 10, 0); // checksum preenchido abaixo
    writeUint32(ip + 12, params.source.value());
    writeUint32(ip + 16, params.destination.value());

    // O checksum IP cobre apenas o próprio cabeçalho. Vários kernels o recalculam para
    // raw sockets, mas preenchê-lo mantém o pacote correto onde isso não acontece.
    writeUint16(ip + 10, internetChecksum({ip, kIpv4HeaderSize}));

    // --- TCP (RFC 793) ---
    writeUint16(tcp + 0, params.sourcePort);
    writeUint16(tcp + 2, params.destinationPort);
    writeUint32(tcp + 4, params.sequence);
    writeUint32(tcp + 8, 0); // ACK não usado em um SYN puro
    tcp[12] = 0x50;          // data offset 5 palavras, sem opções
    tcp[13] = tcp_flag::Syn;
    writeUint16(tcp + 14, 1024); // janela
    writeUint16(tcp + 16, 0);    // checksum preenchido abaixo
    writeUint16(tcp + 18, 0);    // urgent pointer

    // Pseudo-header: origem, destino, zero, protocolo, comprimento TCP. Não viaja no
    // pacote, mas entra no checksum — sem ele o alvo descarta o segmento em silêncio.
    std::array<std::uint8_t, 12> pseudo{};
    writeUint32(pseudo.data() + 0, params.source.value());
    writeUint32(pseudo.data() + 4, params.destination.value());
    pseudo[8] = 0;
    pseudo[9] = kProtocolTcp;
    writeUint16(pseudo.data() + 10, static_cast<std::uint16_t>(kTcpHeaderSize));

    const std::uint32_t seed = sumWords({pseudo.data(), pseudo.size()}, 0);
    writeUint16(tcp + 16, foldChecksum(sumWords({tcp, kTcpHeaderSize}, seed)));

    return packet;
}

std::optional<TcpResponse> parseTcpResponse(std::span<const std::uint8_t> datagram) noexcept {
    if (datagram.size() < kIpv4HeaderSize) {
        return std::nullopt;
    }

    const std::uint8_t version = static_cast<std::uint8_t>((datagram[0] >> 4) & 0x0F);
    if (version != 4) {
        return std::nullopt;
    }

    // IHL vem em palavras de 32 bits; com opções o cabeçalho passa de 20 octetos.
    const std::size_t headerLength = static_cast<std::size_t>(datagram[0] & 0x0F) * 4;
    if (headerLength < kIpv4HeaderSize || datagram.size() < headerLength + kTcpHeaderSize) {
        return std::nullopt;
    }
    if (datagram[9] != kProtocolTcp) {
        return std::nullopt;
    }

    const std::uint8_t* const tcp = datagram.data() + headerLength;

    TcpResponse response;
    response.source = IpAddress(readUint32(datagram.data() + 12));
    response.sourcePort = readUint16(tcp + 0);
    response.destinationPort = readUint16(tcp + 2);
    response.sequence = readUint32(tcp + 4);
    response.acknowledgement = readUint32(tcp + 8);
    response.flags = tcp[13];
    return response;
}

std::array<std::uint8_t, kEchoPacketSize> buildEchoRequest(const EchoParams& params) noexcept {
    std::array<std::uint8_t, kEchoPacketSize> packet{};

    packet[0] = kIcmpEchoRequest;
    packet[1] = 0;                     // código
    writeUint16(packet.data() + 2, 0); // checksum preenchido abaixo
    writeUint16(packet.data() + 4, params.identifier);
    writeUint16(packet.data() + 6, params.sequence);

    // O checksum ICMP cobre a mensagem inteira, sem pseudo-header.
    writeUint16(packet.data() + 2, internetChecksum({packet.data(), packet.size()}));
    return packet;
}

std::optional<IcmpMessage> parseIcmpMessage(std::span<const std::uint8_t> datagram) noexcept {
    if (datagram.size() < kIpv4HeaderSize) {
        return std::nullopt;
    }
    if (((datagram[0] >> 4) & 0x0F) != 4) {
        return std::nullopt;
    }

    const std::size_t headerLength = static_cast<std::size_t>(datagram[0] & 0x0F) * 4;
    if (headerLength < kIpv4HeaderSize || datagram.size() < headerLength + kIcmpHeaderSize) {
        return std::nullopt;
    }
    if (datagram[9] != kProtocolIcmp) {
        return std::nullopt;
    }

    const std::uint8_t* const icmp = datagram.data() + headerLength;

    IcmpMessage message;
    message.source = IpAddress(readUint32(datagram.data() + 12));
    message.type = icmp[0];
    message.code = icmp[1];

    if (message.type == kIcmpEchoReply || message.type == kIcmpEchoRequest) {
        message.identifier = readUint16(icmp + 4);
        message.sequence = readUint16(icmp + 6);
        return message;
    }

    // Tipo 3 cita o datagrama original: cabeçalho IP completo mais 8 octetos, que para UDP
    // e TCP contêm as portas. É a única forma de saber qual sonda provocou o erro.
    if (message.type == kIcmpDestinationUnreachable) {
        const std::size_t quotedOffset = headerLength + kIcmpHeaderSize;
        if (datagram.size() < quotedOffset + kIpv4HeaderSize) {
            return message;
        }

        const std::uint8_t* const quoted = datagram.data() + quotedOffset;
        const std::size_t quotedHeaderLength = static_cast<std::size_t>(quoted[0] & 0x0F) * 4;
        if (quotedHeaderLength < kIpv4HeaderSize ||
            datagram.size() < quotedOffset + quotedHeaderLength + 4) {
            return message;
        }

        message.hasOriginalDatagram = true;
        message.originalDestination = IpAddress(readUint32(quoted + 16));
        message.originalProtocol = quoted[9];
        message.originalSourcePort = readUint16(quoted + quotedHeaderLength + 0);
        message.originalDestinationPort = readUint16(quoted + quotedHeaderLength + 2);
    }

    return message;
}

} // namespace cabral::net
