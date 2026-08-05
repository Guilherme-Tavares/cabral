#include <cabral/scan/UdpPayloads.hpp>

#include <array>

namespace cabral::scan {
namespace {

/// Consulta DNS padrão por "version.bind" em CHAOS TXT (RFC 1035). Qualquer resolvedor
/// responde algo, nem que seja recusa — e resposta basta para classificar Open.
constexpr std::array<std::uint8_t, 30> kDnsQuery{
    0x13, 0x37, // transaction id
    0x01, 0x00, // flags: consulta padrão, recursão desejada
    0x00, 0x01, // 1 pergunta
    0x00, 0x00, // 0 respostas
    0x00, 0x00, // 0 autoridades
    0x00, 0x00, // 0 adicionais
    0x07, 'v',  'e', 'r', 's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd',
    0x00,       // fim do nome
    0x00, 0x10, // tipo TXT
    0x00, 0x03, // classe CHAOS
};

/// Pacote NTP client mode 3, versão 4 (RFC 5905). Só o primeiro octeto precisa estar
/// correto; o resto do cabeçalho de 48 octetos pode ir zerado.
constexpr std::array<std::uint8_t, 48> kNtpRequest{
    0x23, // LI=0, VN=4, Mode=3 (client)
};

/// SNMPv1 GetRequest de sysDescr.0 (1.3.6.1.2.1.1.1.0) com community "public", em BER.
///
/// O primeiro octeto do OID codifica dois arcos: 1.3 vira 0x2B (1*40 + 3). Os comprimentos
/// externos precisam acompanhar qualquer mudança no corpo, ou o agente descarta o pacote.
constexpr std::array<std::uint8_t, 43> kSnmpGet{
    0x30, 0x29,                                                 // SEQUENCE, 41 octetos
    0x02, 0x01, 0x00,                                           // version: 0 (SNMPv1)
    0x04, 0x06, 'p',  'u',  'b',  'l',  'i',  'c',              // community
    0xA0, 0x1C,                                                 // GetRequest PDU, 28 octetos
    0x02, 0x04, 0x12, 0x34, 0x56, 0x78,                         // request id
    0x02, 0x01, 0x00,                                           // error status
    0x02, 0x01, 0x00,                                           // error index
    0x30, 0x0E,                                                 // varbind list, 14 octetos
    0x30, 0x0C,                                                 // varbind, 12 octetos
    0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID sysDescr.0
    0x05, 0x00,                                                 // NULL
};

} // namespace

std::span<const std::uint8_t> payloadFor(Port port) noexcept {
    switch (port) {
    case 53:
        return kDnsQuery;
    case 123:
        return kNtpRequest;
    case 161:
        return kSnmpGet;
    // Demais portas recebem datagrama vazio: sem conhecer o protocolo, qualquer conteúdo
    // seria adivinhação.
    default:
        return {};
    }
}

} // namespace cabral::scan
