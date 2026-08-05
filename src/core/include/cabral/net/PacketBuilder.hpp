#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/PortRange.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace cabral::net {

/// Cabeçalhos em ordem de rede, sem padding. Montados à mão porque raw socket entrega e
/// recebe bytes crus: as structs do sistema variam de nome de campo entre plataformas.
constexpr std::size_t kIpv4HeaderSize = 20;
constexpr std::size_t kTcpHeaderSize = 20;
constexpr std::size_t kSynPacketSize = kIpv4HeaderSize + kTcpHeaderSize;

/// Flags TCP relevantes para -sS. SYN/ACK indica porta aberta, RST indica fechada.
namespace tcp_flag {
constexpr std::uint8_t Fin = 0x01;
constexpr std::uint8_t Syn = 0x02;
constexpr std::uint8_t Rst = 0x04;
constexpr std::uint8_t Psh = 0x08;
constexpr std::uint8_t Ack = 0x10;
constexpr std::uint8_t Urg = 0x20;
} // namespace tcp_flag

/// Soma de verificação da internet (RFC 1071): soma em complemento de um sobre palavras
/// de 16 bits, com o resultado complementado. Um octeto ímpar final é tratado como a
/// metade alta de uma palavra.
std::uint16_t internetChecksum(std::span<const std::uint8_t> data) noexcept;

struct SynPacketParams {
    IpAddress source;
    IpAddress destination;
    Port sourcePort = 0;
    Port destinationPort = 0;
    std::uint32_t sequence = 0;
    std::uint16_t ipId = 0;
};

/// Monta um pacote IPv4+TCP com o bit SYN, pronto para sendto() em raw socket.
///
/// O checksum TCP cobre um pseudo-header com endereços de origem e destino, protocolo e
/// comprimento TCP — campos que não estão no segmento em si. Omiti-lo faz o alvo descartar
/// o pacote em silêncio, sem erro visível no emissor.
std::array<std::uint8_t, kSynPacketSize> buildSynPacket(const SynPacketParams& params) noexcept;

struct TcpResponse {
    IpAddress source;
    Port sourcePort = 0;
    Port destinationPort = 0;
    std::uint32_t sequence = 0;
    std::uint32_t acknowledgement = 0;
    std::uint8_t flags = 0;

    bool isSynAck() const noexcept {
        return (flags & tcp_flag::Syn) != 0 && (flags & tcp_flag::Ack) != 0;
    }
    bool isRst() const noexcept { return (flags & tcp_flag::Rst) != 0; }
};

/// Interpreta um datagrama IPv4 recebido em raw socket como resposta TCP.
///
/// Devolve vazio se o buffer não for IPv4/TCP bem formado. Respeita IHL, pois cabeçalhos
/// com opções são maiores que 20 octetos e assumir tamanho fixo deslocaria a leitura do
/// segmento TCP.
std::optional<TcpResponse> parseTcpResponse(std::span<const std::uint8_t> datagram) noexcept;

} // namespace cabral::net
