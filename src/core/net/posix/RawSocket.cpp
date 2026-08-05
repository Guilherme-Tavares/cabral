#include <cabral/net/RawSocket.hpp>

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace cabral::net {
namespace {

Socket openRawTcpSocket(bool forSending) {
    const int raw = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw < 0) {
        return Socket{};
    }

    if (forSending) {
        // IP_HDRINCL: o cabeçalho IP vai montado por nós, não pelo kernel.
        const int one = 1;
        if (::setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            ::close(raw);
            return Socket{};
        }
    }

    return Socket(static_cast<NativeHandle>(raw));
}

} // namespace

RawCapability probeRawCapability() noexcept {
    const int raw = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw >= 0) {
        ::close(raw);
        return RawCapability::Available;
    }
    if (errno == EPERM || errno == EACCES) {
        return RawCapability::MissingPrivilege;
    }
    return RawCapability::MissingPrivilege;
}

RawTcpSender::RawTcpSender() : socket_(openRawTcpSocket(true)) {}

bool RawTcpSender::send(std::span<const std::uint8_t> packet, IpAddress destination) noexcept {
    if (!socket_.isValid() || packet.empty()) {
        return false;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = ::htonl(destination.value());
    // A porta do sockaddr é ignorada para SOCK_RAW: quem manda é o cabeçalho TCP.
    target.sin_port = 0;

    ssize_t sent = 0;
    do {
        sent = ::sendto(static_cast<int>(socket_.handle()), packet.data(), packet.size(), 0,
                        reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    } while (sent < 0 && errno == EINTR);

    return sent == static_cast<ssize_t>(packet.size());
}

RawTcpReceiver::RawTcpReceiver() : socket_(openRawTcpSocket(false)) {}

std::size_t RawTcpReceiver::receive(std::span<std::uint8_t> buffer,
                                    std::chrono::milliseconds timeout) noexcept {
    if (!socket_.isValid() || buffer.empty()) {
        return 0;
    }

    const int fd = static_cast<int>(socket_.handle());

    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(fd, &readSet);

    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);

    int ready = 0;
    do {
        ready = ::select(fd + 1, &readSet, nullptr, nullptr, &tv);
    } while (ready < 0 && errno == EINTR);

    if (ready <= 0) {
        return 0;
    }

    ssize_t received = 0;
    do {
        received = ::recv(fd, buffer.data(), buffer.size(), 0);
    } while (received < 0 && errno == EINTR);

    return (received > 0) ? static_cast<std::size_t>(received) : 0;
}

namespace {

/// Espera legível no descritor até o timeout. Compartilhada pelos sockets que recebem.
bool waitReadable(int fd, std::chrono::milliseconds timeout) noexcept {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(fd, &readSet);

    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);

    int ready = 0;
    do {
        ready = ::select(fd + 1, &readSet, nullptr, nullptr, &tv);
    } while (ready < 0 && errno == EINTR);

    return ready > 0;
}

std::size_t receiveInto(int fd, std::span<std::uint8_t> buffer,
                        std::chrono::milliseconds timeout) noexcept {
    if (buffer.empty() || !waitReadable(fd, timeout)) {
        return 0;
    }

    ssize_t received = 0;
    do {
        received = ::recv(fd, buffer.data(), buffer.size(), 0);
    } while (received < 0 && errno == EINTR);

    return (received > 0) ? static_cast<std::size_t>(received) : 0;
}

} // namespace

RawIcmpSocket::RawIcmpSocket() {
    const int raw = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw >= 0) {
        socket_ = Socket(static_cast<NativeHandle>(raw));
    }
}

bool RawIcmpSocket::send(std::span<const std::uint8_t> message, IpAddress destination) noexcept {
    if (!socket_.isValid() || message.empty()) {
        return false;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = ::htonl(destination.value());

    ssize_t sent = 0;
    do {
        sent = ::sendto(static_cast<int>(socket_.handle()), message.data(), message.size(), 0,
                        reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    } while (sent < 0 && errno == EINTR);

    return sent == static_cast<ssize_t>(message.size());
}

std::size_t RawIcmpSocket::receive(std::span<std::uint8_t> buffer,
                                   std::chrono::milliseconds timeout) noexcept {
    if (!socket_.isValid()) {
        return 0;
    }
    return receiveInto(static_cast<int>(socket_.handle()), buffer, timeout);
}

UdpProbeSocket::UdpProbeSocket() {
    const int raw = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (raw >= 0) {
        socket_ = Socket(static_cast<NativeHandle>(raw));
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

    // Datagrama vazio é válido: payload.data() pode ser nulo com tamanho zero.
    ssize_t sent = 0;
    do {
        sent = ::sendto(static_cast<int>(socket_.handle()), payload.data(), payload.size(), 0,
                        reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    } while (sent < 0 && errno == EINTR);

    return sent >= 0;
}

UdpProbeSocket::Datagram UdpProbeSocket::receiveFrom(std::span<std::uint8_t> buffer,
                                                     std::chrono::milliseconds timeout) noexcept {
    Datagram result;
    if (!socket_.isValid() || buffer.empty()) {
        return result;
    }

    const int fd = static_cast<int>(socket_.handle());
    if (!waitReadable(fd, timeout)) {
        return result;
    }

    sockaddr_in from{};
    socklen_t length = sizeof(from);

    ssize_t received = 0;
    do {
        received = ::recvfrom(fd, buffer.data(), buffer.size(), 0,
                              reinterpret_cast<sockaddr*>(&from), &length);
    } while (received < 0 && errno == EINTR);

    if (received <= 0) {
        return result;
    }

    result.size = static_cast<std::size_t>(received);
    result.source = IpAddress(::ntohl(from.sin_addr.s_addr));
    result.sourcePort = static_cast<Port>(::ntohs(from.sin_port));
    return result;
}

std::optional<IpAddress> localAddressFor(IpAddress destination) noexcept {
    const int probe = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe < 0) {
        return std::nullopt;
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = ::htonl(destination.value());
    target.sin_port = ::htons(53);

    // UDP não estabelece conexão: isto apenas consulta a rota, sem emitir pacote.
    if (::connect(probe, reinterpret_cast<const sockaddr*>(&target), sizeof(target)) != 0) {
        ::close(probe);
        return std::nullopt;
    }

    sockaddr_in local{};
    socklen_t length = sizeof(local);
    if (::getsockname(probe, reinterpret_cast<sockaddr*>(&local), &length) != 0) {
        ::close(probe);
        return std::nullopt;
    }

    ::close(probe);
    return IpAddress(::ntohl(local.sin_addr.s_addr));
}

} // namespace cabral::net
