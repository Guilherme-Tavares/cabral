#include "TestListener.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using RawSocket = SOCKET;
constexpr RawSocket kInvalid = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using RawSocket = int;
constexpr RawSocket kInvalid = -1;
#endif

namespace cabral::test {
namespace {

void closeSocket(RawSocket socket) {
    if (socket == kInvalid) {
        return;
    }
#ifdef _WIN32
    ::closesocket(socket);
#else
    ::close(socket);
#endif
}

/// Winsock precisa de WSAStartup antes de qualquer chamada. Um objeto estático local
/// basta para a duração do binário de testes.
struct WinsockGuard {
    WinsockGuard() {
#ifdef _WIN32
        WSADATA data{};
        WSAStartup(MAKEWORD(2, 2), &data);
#endif
    }
    ~WinsockGuard() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};

void ensureNetworkReady() {
    static WinsockGuard guard;
}

/// Vincula a 127.0.0.1:0 e devolve a porta efêmera escolhida pelo sistema.
RawSocket bindEphemeral(Port& port) {
    ensureNetworkReady();
    port = 0;

    const RawSocket handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == kInvalid) {
        return kInvalid;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    address.sin_port = 0;

    if (::bind(handle, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        closeSocket(handle);
        return kInvalid;
    }

    sockaddr_in actual{};
#ifdef _WIN32
    int length = sizeof(actual);
#else
    socklen_t length = sizeof(actual);
#endif
    if (::getsockname(handle, reinterpret_cast<sockaddr*>(&actual), &length) != 0) {
        closeSocket(handle);
        return kInvalid;
    }

    port = static_cast<Port>(::ntohs(actual.sin_port));
    return handle;
}

} // namespace

TestListener::TestListener() {
    Port port = 0;
    const RawSocket handle = bindEphemeral(port);
    if (handle == kInvalid) {
        return;
    }

    if (::listen(handle, SOMAXCONN) != 0) {
        closeSocket(handle);
        return;
    }

    handle_ = static_cast<unsigned long long>(handle);
    port_ = port;
}

TestListener::~TestListener() {
    if (port_ != 0) {
        closeSocket(static_cast<RawSocket>(handle_));
    }
}

Port reserveAndReleasePort() {
    Port port = 0;
    const RawSocket handle = bindEphemeral(port);
    if (handle == kInvalid) {
        return 0;
    }
    // Fecha sem escutar: a porta volta a ficar livre e nada aceita conexões nela.
    closeSocket(handle);
    return port;
}

} // namespace cabral::test
