#include <cabral/net/PacketBuilder.hpp>
#include <cabral/net/RawSocket.hpp>
#include <cabral/scan/SynScanner.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <random>
#include <unordered_map>

namespace cabral::scan {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kReceiveBufferSize = 1500; // MTU típica de Ethernet

/// Teto da espera por resposta, para que o cancelamento seja notado em tempo útil sem
/// transformar a recepção em polling ativo.
constexpr auto kMaxReceiveSlice = std::chrono::milliseconds(100);

struct Probe {
    Port port = 0;
    Clock::time_point deadline;
    int attemptsLeft = 0;
};

/// Porta de origem alta e aleatória, escolhida uma vez por varredura. É o critério de
/// correlação: respostas destinadas a outra porta pertencem a outra conexão.
Port pickEphemeralPort() {
    std::random_device device;
    std::mt19937 engine(device());
    std::uniform_int_distribution<int> distribution(40000, 60000);
    return static_cast<Port>(distribution(engine));
}

std::uint32_t pickSequence() {
    std::random_device device;
    std::mt19937 engine(device());
    // result_type do mt19937 é unsigned long, mais largo que 32 bits em LP64.
    return static_cast<std::uint32_t>(engine() & 0xFFFFFFFFu);
}

} // namespace

std::vector<PortResult> SynScanner::scan(const IpAddress& target, std::span<const Port> ports,
                                         const ScanConfig& config, std::stop_token stop) {
    std::vector<PortResult> results;
    results.reserve(ports.size());

    const auto record = [&](Port port, PortState state, std::chrono::milliseconds rtt) {
        PortResult result;
        result.port = port;
        result.protocol = Protocol::Tcp;
        result.state = state;
        result.rtt = rtt;
        results.push_back(result);
    };

    if (ports.empty()) {
        return results;
    }

    const auto unresolved = [&](PortState state) {
        for (Port port : ports) {
            record(port, state, std::chrono::milliseconds::zero());
        }
        std::sort(results.begin(), results.end(),
                  [](const PortResult& a, const PortResult& b) { return a.port < b.port; });
        return results;
    };

    if (net::probeRawCapability() != net::RawCapability::Available) {
        return unresolved(PortState::Unknown);
    }

    const auto source = net::localAddressFor(target);
    if (!source) {
        return unresolved(PortState::Unknown);
    }

    net::RawTcpSender sender;
    net::RawTcpReceiver receiver;
    if (!sender.isValid() || !receiver.isValid()) {
        return unresolved(PortState::Unknown);
    }

    const auto timing = parametersFor(config.timing);
    const auto timeout = config.effectiveTimeout();
    const std::size_t batchSize = std::max<std::size_t>(1, timing.portConcurrency);
    const int attempts = std::max(1, timing.retries + 1);

    const Port sourcePort = pickEphemeralPort();
    const std::uint32_t sequence = pickSequence();

    std::unordered_map<Port, Probe> inFlight;
    inFlight.reserve(batchSize);

    std::array<std::uint8_t, kReceiveBufferSize> buffer{};
    std::size_t next = 0;
    std::uint16_t ipId = 1;

    const auto sendProbe = [&](Port port) {
        net::SynPacketParams params;
        params.source = *source;
        params.destination = target;
        params.sourcePort = sourcePort;
        params.destinationPort = port;
        params.sequence = sequence;
        params.ipId = ipId++;

        const auto packet = net::buildSynPacket(params);
        return sender.send(packet, target);
    };

    while ((next < ports.size() || !inFlight.empty()) && !stop.stop_requested()) {
        while (next < ports.size() && inFlight.size() < batchSize && !stop.stop_requested()) {
            const Port port = ports[next++];
            const auto now = Clock::now();

            if (!sendProbe(port)) {
                record(port, PortState::Unknown, std::chrono::milliseconds::zero());
                continue;
            }
            inFlight.emplace(port, Probe{port, now + timeout, attempts - 1});
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

        const std::size_t received = receiver.receive(buffer, slice);
        if (stop.stop_requested()) {
            break;
        }
        if (received > 0) {
            const auto response = net::parseTcpResponse({buffer.data(), received});

            // Filtro de correlação: precisa vir do alvo e chegar à porta de origem desta
            // varredura. O raw socket entrega todo tráfego TCP do host, inclusive alheio.
            if (response && response->source == target && response->destinationPort == sourcePort) {
                const auto it = inFlight.find(response->sourcePort);
                if (it != inFlight.end()) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        timeout - (it->second.deadline - Clock::now()));

                    if (response->isSynAck()) {
                        record(it->first, PortState::Open, elapsed);
                        inFlight.erase(it);
                    } else if (response->isRst()) {
                        record(it->first, PortState::Closed, elapsed);
                        inFlight.erase(it);
                    }
                }
            }
        }

        // Sondas vencidas: retransmitir enquanto houver tentativa, e só então desistir.
        // Silêncio persistente é Filtered, não Closed: não houve resposta que o afirme.
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
                record(it->first, PortState::Filtered, timeout);
                it = inFlight.erase(it);
            }
        }
    }

    // Cancelamento não permite afirmar estado: o que não foi resolvido fica Unknown.
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
