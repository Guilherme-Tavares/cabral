#include <cabral/net/PacketBuilder.hpp>
#include <cabral/net/RawSocket.hpp>
#include <cabral/scan/UdpPayloads.hpp>
#include <cabral/scan/UdpScanner.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <unordered_map>

namespace cabral::scan {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kReceiveBufferSize = 1500;
constexpr auto kMaxReceiveSlice = std::chrono::milliseconds(100);

constexpr std::uint8_t kProtocolUdp = 17;

struct Probe {
    Port port = 0;
    Clock::time_point deadline;
    int attemptsLeft = 0;
};

} // namespace

std::vector<PortResult> UdpScanner::scan(const IpAddress& target, std::span<const Port> ports,
                                         const ScanConfig& config, std::stop_token stop) {
    std::vector<PortResult> results;
    results.reserve(ports.size());

    const auto record = [&](Port port, PortState state, std::chrono::milliseconds rtt) {
        PortResult result;
        result.port = port;
        result.protocol = Protocol::Udp;
        result.state = state;
        result.rtt = rtt;
        results.push_back(result);
    };

    const auto finishAll = [&](PortState state) {
        for (Port port : ports) {
            record(port, state, std::chrono::milliseconds::zero());
        }
        std::sort(results.begin(), results.end(),
                  [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
        return results;
    };

    if (ports.empty()) {
        return results;
    }

    net::UdpProbeSocket prober;
    if (!prober.isValid()) {
        return finishAll(PortState::Unknown);
    }

    // Sem ICMP não há como observar port unreachable. A varredura ainda distingue Open por
    // resposta direta, mas o resto permanece OpenFiltered — que é a resposta honesta, não
    // uma degradação silenciosa.
    net::RawIcmpSocket icmp;
    const bool canObserveIcmp = icmp.isValid();

    const auto timing = parametersFor(config.timing);
    const auto timeout = config.effectiveTimeout();
    const std::size_t batchSize = std::max<std::size_t>(1, timing.portConcurrency);
    const int attempts = std::max(1, timing.retries + 1);

    std::unordered_map<Port, Probe> inFlight;
    inFlight.reserve(batchSize);

    std::array<std::uint8_t, kReceiveBufferSize> buffer{};
    std::size_t next = 0;

    const auto sendProbe = [&](Port port) { return prober.sendTo(payloadFor(port), target, port); };

    while ((next < ports.size() || !inFlight.empty()) && !stop.stop_requested()) {
        while (next < ports.size() && inFlight.size() < batchSize && !stop.stop_requested()) {
            const Port port = ports[next++];
            if (!sendProbe(port)) {
                record(port, PortState::Unknown, std::chrono::milliseconds::zero());
                continue;
            }
            inFlight.emplace(port, Probe{port, Clock::now() + timeout, attempts - 1});
        }

        if (inFlight.empty()) {
            continue;
        }

        auto nearest = Clock::time_point::max();
        for (const auto& [port, probe] : inFlight) {
            nearest = std::min(nearest, probe.deadline);
        }

        auto slice = std::chrono::duration_cast<std::chrono::milliseconds>(nearest - Clock::now());
        if (slice.count() < 0) {
            slice = std::chrono::milliseconds::zero();
        }
        slice = std::min(slice, kMaxReceiveSlice);

        // Resposta UDP direta: evidência inequívoca de porta aberta. A origem identifica
        // qual sonda foi respondida — atribuí-la por proximidade marcaria a porta errada.
        if (const auto datagram = prober.receiveFrom(buffer, slice); datagram.size > 0) {
            if (datagram.source == target) {
                const auto it = inFlight.find(datagram.sourcePort);
                if (it != inFlight.end()) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        timeout - (it->second.deadline - Clock::now()));
                    record(it->first, PortState::Open, elapsed);
                    inFlight.erase(it);
                }
            }
        }

        if (stop.stop_requested()) {
            break;
        }

        if (canObserveIcmp) {
            if (const std::size_t received = icmp.receive(buffer, kMaxReceiveSlice); received > 0) {
                const auto message = net::parseIcmpMessage({buffer.data(), received});

                // Correlação pelo datagrama citado: precisa ser o nosso UDP, para o nosso
                // alvo. O raw socket ICMP entrega todo erro que chega ao host.
                if (message && message->hasOriginalDatagram &&
                    message->originalProtocol == kProtocolUdp &&
                    message->originalDestination == target) {

                    const auto it = inFlight.find(message->originalDestinationPort);
                    if (it != inFlight.end()) {
                        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                            timeout - (it->second.deadline - Clock::now()));

                        if (message->isPortUnreachable()) {
                            record(it->first, PortState::Closed, elapsed);
                            inFlight.erase(it);
                        } else if (message->isFilteredIndication()) {
                            record(it->first, PortState::Filtered, elapsed);
                            inFlight.erase(it);
                        }
                    }
                }
            }
        }

        const auto checkpoint = Clock::now();
        for (auto it = inFlight.begin(); it != inFlight.end();) {
            if (it->second.deadline > checkpoint) {
                ++it;
                continue;
            }

            if (it->second.attemptsLeft > 0) {
                --it->second.attemptsLeft;
                it->second.deadline = checkpoint + timeout;
                sendProbe(it->first);
                ++it;
            } else {
                // Silêncio no UDP não distingue aberta de filtrada. OpenFiltered é a única
                // afirmação sustentável.
                record(it->first, PortState::OpenFiltered, timeout);
                it = inFlight.erase(it);
            }
        }
    }

    for (const auto& [port, probe] : inFlight) {
        record(port, PortState::Unknown, std::chrono::milliseconds::zero());
    }
    for (std::size_t i = next; i < ports.size(); ++i) {
        record(ports[i], PortState::Unknown, std::chrono::milliseconds::zero());
    }

    std::sort(results.begin(), results.end(),
              [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
    return results;
}

} // namespace cabral::scan
