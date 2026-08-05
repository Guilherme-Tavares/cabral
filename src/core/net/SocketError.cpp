#include <cabral/net/Socket.hpp>

namespace cabral::net {

std::string_view describe(SocketError error) noexcept {
    switch (error) {
    case SocketError::None:
        return "no error";
    case SocketError::Refused:
        return "connection refused";
    case SocketError::TimedOut:
        return "timed out";
    case SocketError::Unreachable:
        return "host or network unreachable";
    case SocketError::PermissionDenied:
        return "permission denied";
    case SocketError::ResourceExhausted:
        return "out of file descriptors or ephemeral ports";
    case SocketError::Other:
        return "socket error";
    }
    return "socket error";
}

} // namespace cabral::net
