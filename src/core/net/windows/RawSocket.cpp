#include <cabral/net/RawSocket.hpp>

#include <winsock2.h>
#include <ws2tcpip.h>

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
