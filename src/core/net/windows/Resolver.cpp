#include <cabral/discovery/TargetExpander.hpp>
#include <cabral/net/Socket.hpp>

#include <winsock2.h>
#include <ws2tcpip.h>

namespace cabral::discovery {

std::optional<IpAddress> resolveHostname(const std::string& hostname) {
    // getaddrinfo exige Winsock inicializado; ancorar aqui evita que o chamador precise
    // saber disso.
    std::optional<net::NetworkSubsystem> subsystem;
    try {
        subsystem.emplace();
    } catch (...) {
        return std::nullopt;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET; // apenas IPv4 no escopo do projeto
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* results = nullptr;
    if (::getaddrinfo(hostname.c_str(), nullptr, &hints, &results) != 0 || results == nullptr) {
        return std::nullopt;
    }

    std::optional<IpAddress> address;
    for (const addrinfo* it = results; it != nullptr; it = it->ai_next) {
        if (it->ai_family == AF_INET && it->ai_addr != nullptr) {
            const auto* in = reinterpret_cast<const sockaddr_in*>(it->ai_addr);
            address = IpAddress(::ntohl(in->sin_addr.s_addr));
            break;
        }
    }

    ::freeaddrinfo(results);
    return address;
}

} // namespace cabral::discovery
