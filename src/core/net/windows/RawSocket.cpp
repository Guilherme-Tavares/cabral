#include <cabral/net/RawSocket.hpp>

#include <winsock2.h>
#include <ws2tcpip.h>
// SIO_UDP_CONNRESET vive aqui, e mswsock.h exige winsock2.h antes.
#include <mswsock.h>

namespace cabral::net {

/// A Microsoft bloqueia envio de TCP sobre raw socket desde o XP SP2. Não é falta de
/// privilégio: nem como administrador funciona. Por isso -sS é recusado de saída, com
/// mensagem explicativa, em vez de falhar no meio da varredura.
RawCapability probeRawCapability() noexcept {
    return RawCapability::UnsupportedPlatform;
}

RawTcpSender::RawTcpSender() = default;

bool RawTcpSender::send(std::span<const std::uint8_t>, IpAddress) noexcept {
    return false;
}

RawTcpReceiver::RawTcpReceiver() = default;

std::size_t RawTcpReceiver::receive(std::span<std::uint8_t>, std::chrono::milliseconds) noexcept {
    return 0;
}

/// Recepção de ICMP por raw socket exige privilégio de administrador no Windows e ainda
/// assim é pouco confiável. Por isso -sU reporta OpenFiltered na ausência de resposta UDP
/// direta, em vez de afirmar Closed sem evidência.
RawIcmpSocket::RawIcmpSocket() = default;

bool RawIcmpSocket::send(std::span<const std::uint8_t>, IpAddress) noexcept {
    return false;
}

std::size_t RawIcmpSocket::receive(std::span<std::uint8_t>, std::chrono::milliseconds) noexcept {
    return 0;
}

UdpProbeSocket::UdpProbeSocket() {
    std::optional<NetworkSubsystem> subsystem;
    try {
        subsystem.emplace();
    } catch (...) {
        return;
    }

    const SOCKET raw = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (raw != INVALID_SOCKET) {
        socket_ = Socket(static_cast<NativeHandle>(raw));
        // Sem isso, um ICMP port unreachable faz o recv() seguinte falhar com
        // WSAECONNRESET, abortando a varredura em vez de apenas não haver resposta.
        BOOL disable = FALSE;
        DWORD returned = 0;
        ::WSAIoctl(raw, SIO_UDP_CONNRESET, &disable, sizeof(disable), nullptr, 0, &returned,
                   nullptr, nullptr);
    }
}

bool UdpProbeSocket::sendTo(std::span<const std::uint8_t> payload, IpAddress destination,
                            Port port) noexcept {
    if (!socket_.isValid()) {
        return false;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = ::htonl(destination.value());
    target.sin_port = ::htons(port);

    const int sent =
        ::sendto(static_cast<SOCKET>(socket_.handle()),
                 reinterpret_cast<const char*>(payload.data()), static_cast<int>(payload.size()), 0,
                 reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    return sent >= 0;
}

UdpProbeSocket::Datagram UdpProbeSocket::receiveFrom(std::span<std::uint8_t> buffer,
                                                     std::chrono::milliseconds timeout) noexcept {
    Datagram result;
    if (!socket_.isValid() || buffer.empty()) {
        return result;
    }

    const SOCKET handle = static_cast<SOCKET>(socket_.handle());

    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(handle, &readSet);

    timeval tv{};
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);

    if (::select(0, &readSet, nullptr, nullptr, &tv) <= 0) {
        return result;
    }

    sockaddr_in from{};
    int length = sizeof(from);
    const int received =
        ::recvfrom(handle, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()),
                   0, reinterpret_cast<sockaddr*>(&from), &length);
    if (received <= 0) {
        return result;
    }

    result.size = static_cast<std::size_t>(received);
    result.source = IpAddress(::ntohl(from.sin_addr.s_addr));
    result.sourcePort = static_cast<Port>(::ntohs(from.sin_port));
    return result;
}

std::optional<IpAddress> localAddressFor(IpAddress destination) noexcept {
    // O Winsock precisa estar inicializado antes de qualquer chamada de socket. Ancorar
    // isso aqui permite consultar a rota sem exigir que o chamador saiba disso; a
    // construção lança se o WSAStartup falhar, e a função é noexcept.
    std::optional<NetworkSubsystem> subsystem;
    try {
        subsystem.emplace();
    } catch (...) {
        return std::nullopt;
    }

    const SOCKET probe = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe == INVALID_SOCKET) {
        return std::nullopt;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = ::htonl(destination.value());
    target.sin_port = ::htons(53);

    if (::connect(probe, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) != 0) {
        ::closesocket(probe);
        return std::nullopt;
    }

    sockaddr_in local{};
    int length = sizeof(local);
    if (::getsockname(probe, reinterpret_cast<sockaddr*>(&local), &length) != 0) {
        ::closesocket(probe);
        return std::nullopt;
    }

    ::closesocket(probe);
    return IpAddress(::ntohl(local.sin_addr.s_addr));
}

} // namespace cabral::net
