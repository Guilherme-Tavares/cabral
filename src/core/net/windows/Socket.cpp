#include <cabral/net/Socket.hpp>

#include <mutex>
#include <stdexcept>

#include <winsock2.h>
#include <ws2tcpip.h>

namespace cabral::net {
namespace {

std::mutex g_startupMutex;
int g_startupCount = 0;

SocketError translate(int code) noexcept {
    switch (code) {
    case 0:
        return SocketError::None;
    case WSAECONNREFUSED:
        return SocketError::Refused;
    case WSAETIMEDOUT:
        return SocketError::TimedOut;
    case WSAENETUNREACH:
    case WSAEHOSTUNREACH:
        return SocketError::Unreachable;
    case WSAEACCES:
        return SocketError::PermissionDenied;
    case WSAEMFILE:
    case WSAENOBUFS:
        return SocketError::ResourceExhausted;
    default:
        return SocketError::Other;
    }
}

} // namespace

NativeHandle invalidHandle() noexcept {
    return static_cast<NativeHandle>(INVALID_SOCKET);
}

NetworkSubsystem::NetworkSubsystem() {
    std::lock_guard lock(g_startupMutex);
    if (g_startupCount == 0) {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
    }
    ++g_startupCount;
}

NetworkSubsystem::~NetworkSubsystem() {
    std::lock_guard lock(g_startupMutex);
    if (--g_startupCount == 0) {
        WSACleanup();
    }
}

void Socket::close() noexcept {
    if (isValid()) {
        ::closesocket(static_cast<SOCKET>(handle_));
        handle_ = invalidHandle();
    }
}

Socket createTcpSocket() {
    const SOCKET raw = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (raw == INVALID_SOCKET) {
        return Socket{};
    }

    u_long nonBlocking = 1;
    if (::ioctlsocket(raw, static_cast<long>(FIONBIO), &nonBlocking) != 0) {
        ::closesocket(raw);
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

    const int rc = ::connect(static_cast<SOCKET>(socket.handle()),
                             reinterpret_cast<const sockaddr*>(&target), sizeof(target));
    if (rc == 0) {
        return {ConnectProgress::Connected, SocketError::None};
    }

    const int code = ::WSAGetLastError();
    if (code == WSAEWOULDBLOCK || code == WSAEINPROGRESS) {
        return {ConnectProgress::InProgress, SocketError::None};
    }
    return {ConnectProgress::Failed, translate(code)};
}

SocketError completeConnect(const Socket& socket) {
    int error = 0;
    int length = sizeof(error);
    const int rc = ::getsockopt(static_cast<SOCKET>(socket.handle()), SOL_SOCKET, SO_ERROR,
                                reinterpret_cast<char*>(&error), &length);
    if (rc != 0) {
        return translate(::WSAGetLastError());
    }
    return translate(error);
}

} // namespace cabral::net
