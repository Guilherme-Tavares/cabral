#include <cabral/net/Poller.hpp>
#include <cabral/net/Socket.hpp>
#include <cabral/scan/ConnectScanner.hpp>

#include <algorithm>
#include <chrono>
#include <unordered_map>

namespace cabral::scan {
namespace {

using Clock = std::chrono::steady_clock;

struct Probe {
    net::Socket socket;
    Port port = 0;
    Clock::time_point deadline;
};

std::chrono::milliseconds toMillis(Clock::duration duration) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration);
}

} // namespace

PortState stateForConnectResult(net::SocketError error) noexcept {
    switch (error) {
    case net::SocketError::None:
        return PortState::Open;
    case net::SocketError::Refused:
        return PortState::Closed;
    // Rede inalcançável não diz nada sobre a porta em si, apenas que a sonda não chegou.
    case net::SocketError::TimedOut:
    case net::SocketError::Unreachable:
        return PortState::Filtered;
    default:
        return PortState::Filtered;
    }
}

std::vector<PortResult> ConnectScanner::scan(const IpAddress& target, std::span<const Port> ports,
                                             const ScanConfig& config, std::stop_token stop) {
    std::vector<PortResult> results;
    results.reserve(ports.size());

    if (ports.empty()) {
        return results;
    }

    const net::NetworkSubsystem subsystem;
    const auto timeout = config.effectiveTimeout();
    const auto timing = parametersFor(config.timing);

    // Limite de sondas simultâneas: mais que isso esgota descritores e portas efêmeras,
    // e o excesso de RST no alvo distorce o resultado.
    const std::size_t batchSize = std::max<std::size_t>(1, timing.portConcurrency);

    net::Poller poller;
    std::unordered_map<net::NativeHandle, Probe> inFlight;
    inFlight.reserve(batchSize);

    std::vector<net::PollEvent> events;
    std::size_t next = 0;

    const auto finish = [&](Port port, PortState state, Clock::duration elapsed) {
        PortResult result;
        result.port = port;
        result.protocol = Protocol::Tcp;
        result.state = state;
        result.rtt = toMillis(elapsed);
        results.push_back(result);
    };

    while ((next < ports.size() || !inFlight.empty()) && !stop.stop_requested()) {
        while (next < ports.size() && inFlight.size() < batchSize && !stop.stop_requested()) {
            const Port port = ports[next++];

            auto socket = net::createTcpSocket();
            if (!socket.isValid()) {
                finish(port, PortState::Unknown, Clock::duration::zero());
                continue;
            }

            const auto started = Clock::now();
            const auto attempt = net::beginConnect(socket, target, port);

            if (attempt.progress == net::ConnectProgress::Connected) {
                finish(port, PortState::Open, Clock::now() - started);
                continue;
            }
            if (attempt.progress == net::ConnectProgress::Failed) {
                finish(port, stateForConnectResult(attempt.error), Clock::now() - started);
                continue;
            }

            const auto handle = socket.handle();
            if (!poller.add(handle)) {
                finish(port, PortState::Unknown, Clock::now() - started);
                continue;
            }

            inFlight.emplace(handle, Probe{std::move(socket), port, started + timeout});
        }

        if (inFlight.empty()) {
            continue;
        }

        // Esperar só até o vencimento mais próximo evita reter uma sonda expirada até que
        // outra qualquer responda.
        const auto now = Clock::now();
        auto nearest = Clock::time_point::max();
        for (const auto& [handle, probe] : inFlight) {
            nearest = std::min(nearest, probe.deadline);
        }

        auto slice = toMillis(nearest - now);
        if (slice.count() < 0) {
            slice = std::chrono::milliseconds::zero();
        }

        poller.wait(events, slice);

        for (const auto& event : events) {
            const auto it = inFlight.find(event.handle);
            if (it == inFlight.end()) {
                continue;
            }
            if (!event.writable && !event.errored) {
                continue;
            }

            const auto error = net::completeConnect(it->second.socket);
            const auto elapsed = timeout - (it->second.deadline - Clock::now());

            finish(it->second.port, stateForConnectResult(error), elapsed);
            poller.remove(event.handle);
            inFlight.erase(it);
        }

        const auto checkpoint = Clock::now();
        for (auto it = inFlight.begin(); it != inFlight.end();) {
            if (it->second.deadline <= checkpoint) {
                finish(it->second.port, PortState::Filtered, timeout);
                poller.remove(it->first);
                it = inFlight.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Cancelamento: o que não chegou a ser sondado fica Unknown, não Filtered — não houve
    // evidência, e afirmar filtragem seria inventar resultado.
    for (auto& [handle, probe] : inFlight) {
        poller.remove(handle);
        finish(probe.port, PortState::Unknown, Clock::duration::zero());
    }
    for (std::size_t i = next; i < ports.size(); ++i) {
        finish(ports[i], PortState::Unknown, Clock::duration::zero());
    }

    std::sort(results.begin(), results.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
    return results;
}

} // namespace cabral::scan
