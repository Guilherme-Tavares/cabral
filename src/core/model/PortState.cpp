#include <cabral/model/PortState.hpp>

namespace cabral {

std::string_view toString(Protocol protocol) noexcept {
    switch (protocol) {
    case Protocol::Tcp:
        return "tcp";
    case Protocol::Udp:
        return "udp";
    }
    return "unknown";
}

std::string_view toString(PortState state) noexcept {
    switch (state) {
    case PortState::Open:
        return "open";
    case PortState::Closed:
        return "closed";
    case PortState::Filtered:
        return "filtered";
    case PortState::OpenFiltered:
        return "open|filtered";
    case PortState::Unknown:
        return "unknown";
    }
    return "unknown";
}

} // namespace cabral
