#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/PortRange.hpp>
#include <cabral/model/PortState.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace cabral {

struct PortResult {
    Port port = 0;
    Protocol protocol = Protocol::Tcp;
    PortState state = PortState::Unknown;
    std::string service; // vazio se desconhecido
    std::chrono::milliseconds rtt{0};
};

struct HostResult {
    IpAddress address;
    std::string hostname; // vazio se não resolvido
    bool isUp = false;
    std::vector<PortResult> ports;
};

} // namespace cabral
