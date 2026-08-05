#include <cabral/net/RawSocket.hpp>

namespace cabral::net {

std::string rawCapabilityAdvice(RawCapability capability) {
    switch (capability) {
    case RawCapability::Available:
        return {};

    // Orientar setcap, nunca root: o binário precisa de duas capabilities, não de todos
    // os privilégios da máquina.
    case RawCapability::MissingPrivilege:
        return "raw sockets require CAP_NET_RAW\n"
               "  grant it once with:\n"
               "      sudo setcap cap_net_raw,cap_net_admin=eip <path to cabral>\n"
               "  or use -sT, which needs no privileges";

    case RawCapability::UnsupportedPlatform:
        return "SYN scan is not available on Windows\n"
               "  raw TCP sending has been blocked by the operating system since XP SP2,\n"
               "  and no privilege level lifts that restriction\n"
               "  use -sT instead";
    }
    return {};
}

} // namespace cabral::net
