#include <cabral/net/Socket.hpp>

#include <cerrno>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace cabral::net {
namespace {

SocketError translate(int code) noexcept {
    switch (code) {
    case 0:
        return SocketError::None;
    case ECONNREFUSED:
        return SocketError::Refused;
    case ETIMEDOUT:
        return SocketError::TimedOut;
    case ENETUNREACH:
    case EHOSTUNREACH:
        return SocketError::Unreachable;
    case EACCES:
    case EPERM:
        return SocketError::PermissionDenied;
    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM:
        return SocketError::ResourceExhausted;
    default:
        return SocketError::Other;
    }
}

} // namespace

NativeHandle invalidHandle() noexcept {
    return static_cast<NativeHandle>(-1);
}

// Winsock exige inicialização explícita; no POSIX não há equivalente.
NetworkSubsystem::NetworkSubsystem() = default;
NetworkSubsystem::~NetworkSubsystem() = default;

void Socket::close() noexcept {
    if (isValid()) {
        ::close(static_cast<int>(handle_));
        handle_ = invalidHandle();
    }
}

Socket createTcpSocket() {
    int raw = -1;
#ifdef SOCK_NONBLOCK
    raw = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
#else
    raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (raw >= 0) {
        const int flags = ::fcntl(raw, F_GETFL, 0);
        if (flags < 0 || ::fcntl(raw, F_SETFL, flags | O_NONBLOCK) < 0) {
            ::close(raw);
            return Socket{};
        }
    }
#endif
    if (raw < 0) {
        return Socket{};
    }
    return Socket(static_cast<NativeHandle>(raw));
}

ConnectAttempt beginConnect(const Socket& socket, IpAddress address, Port port) {
    if (!socket.isValid()) {
        return {ConnectProgress::Failed, SocketError::ResourceExhausted};
    }

    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = ::htons(port);
    target.sin_addr.s_addr = ::htonl(address.value());

    int rc = 0;
    do {
        rc = ::connect(static_cast<int>(socket.handle()),
                       reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    } while (rc < 0 && errno == EINTR);

    if (rc == 0) {
        return {ConnectProgress::Connected, SocketError::None};
    }
    if (errno == EINPROGRESS || errno == EALREADY || errno == EWOULDBLOCK) {
        return {ConnectProgress::InProgress, SocketError::None};
    }
    return {ConnectProgress::Failed, translate(errno)};
}

SocketError completeConnect(const Socket& socket) {
    int error = 0;
    socklen_t length = sizeof(error);
    const int rc =
        ::getsockopt(static_cast<int>(socket.handle()), SOL_SOCKET, SO_ERROR, &error, &length);
    if (rc != 0) {
        return translate(errno);
    }
    return translate(error);
}

} // namespace cabral::net
