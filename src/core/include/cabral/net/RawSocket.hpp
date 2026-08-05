#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/PortRange.hpp>
#include <cabral/net/Socket.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace cabral::net {

enum class RawCapability : std::uint8_t {
    Available,
    MissingPrivilege,   // sem CAP_NET_RAW nem root
    UnsupportedPlatform // Windows bloqueia envio de TCP raw desde o XP SP2
};

/// Verifica se raw sockets estão utilizáveis, sem lançar. Chamado antes de iniciar a
/// varredura para que a falta de privilégio vire mensagem clara, não EPERM cru no meio.
RawCapability probeRawCapability() noexcept;

/// Orientação acionável para o usuário: sugere setcap, nunca "rode como root".
std::string rawCapabilityAdvice(RawCapability capability);

/// Socket para envio de pacotes TCP montados à mão. Requer CAP_NET_RAW.
class RawTcpSender {
public:
    RawTcpSender();

    bool isValid() const noexcept { return socket_.isValid(); }

    /// Envia um datagrama IPv4 completo ao destino. Devolve falso em erro de envio.
    bool send(std::span<const std::uint8_t> packet, IpAddress destination) noexcept;

private:
    Socket socket_;
};

/// Socket para recepção de respostas TCP. O kernel entrega uma cópia de todo segmento TCP
/// que chega ao host, então o chamador precisa filtrar o que é seu.
class RawTcpReceiver {
public:
    RawTcpReceiver();

    bool isValid() const noexcept { return socket_.isValid(); }

    /// Espera por um datagrama até o timeout. Devolve o número de octetos escritos em
    /// buffer, ou 0 se nada chegou a tempo.
    std::size_t receive(std::span<std::uint8_t> buffer, std::chrono::milliseconds timeout) noexcept;

private:
    Socket socket_;
};

/// Socket ICMP para echo request (ping sweep) e para recepção de mensagens de erro, entre
/// elas o port unreachable que classifica porta UDP fechada. Requer CAP_NET_RAW.
class RawIcmpSocket {
public:
    RawIcmpSocket();

    bool isValid() const noexcept { return socket_.isValid(); }

    /// Envia uma mensagem ICMP já montada. O kernel preenche o cabeçalho IP.
    bool send(std::span<const std::uint8_t> message, IpAddress destination) noexcept;

    std::size_t receive(std::span<std::uint8_t> buffer, std::chrono::milliseconds timeout) noexcept;

private:
    Socket socket_;
};

/// Socket UDP comum para as sondas de -sU. Não exige privilégio: o que exige é a recepção
/// do ICMP de erro, feita por RawIcmpSocket.
class UdpProbeSocket {
public:
    UdpProbeSocket();

    bool isValid() const noexcept { return socket_.isValid(); }

    bool sendTo(std::span<const std::uint8_t> payload, IpAddress destination, Port port) noexcept;

    struct Datagram {
        std::size_t size = 0;
        IpAddress source;
        Port sourcePort = 0;
    };

    /// Resposta UDP direta, que indica porta aberta sem ambiguidade. Devolve também a
    /// origem: sem ela não há como saber qual sonda foi respondida, e atribuir a resposta
    /// à porta errada inventaria um Open.
    Datagram receiveFrom(std::span<std::uint8_t> buffer,
                         std::chrono::milliseconds timeout) noexcept;

private:
    Socket socket_;
};

/// Descobre qual endereço local o sistema usaria para alcançar o destino. Necessário para
/// preencher o campo de origem do cabeçalho IP e para o pseudo-header do checksum.
///
/// Usa um socket UDP não conectado a tráfego: o connect() apenas consulta a tabela de
/// rotas, sem emitir pacote algum.
std::optional<IpAddress> localAddressFor(IpAddress destination) noexcept;

} // namespace cabral::net
