#include <cabral/discovery/HostDiscovery.hpp>
#include <cabral/net/PacketBuilder.hpp>
#include <cabral/net/Poller.hpp>
#include <cabral/net/RawSocket.hpp>
#include <cabral/net/Socket.hpp>

#include <array>
#include <atomic>
#include <chrono>

namespace cabral::discovery {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kReceiveBufferSize = 1500;

/// Portas do fallback: um host que não responde ICMP frequentemente escuta em uma delas.
constexpr std::array<Port, 2> kFallbackPorts{80, 443};

/// Identificador do echo, para reconhecer a própria resposta entre as que chegam ao host.
std::uint16_t echoIdentifier() noexcept {
    static std::atomic<std::uint16_t> counter{0};
    // O PID distingue instâncias simultâneas; o contador, sondas dentro da mesma execução.
    return static_cast<std::uint16_t>(0xC000u | (counter.fetch_add(1) & 0x0FFFu));
}

bool pingByIcmp(IpAddress address, std::chrono::milliseconds timeout, int attempts,
                std::stop_token stop) {
    net::RawIcmpSocket socket;
    if (!socket.isValid()) {
        return false;
    }

    const std::uint16_t identifier = echoIdentifier();
    std::array<std::uint8_t, kReceiveBufferSize> buffer{};

    for (int attempt = 0; attempt < attempts && !stop.stop_requested(); ++attempt) {
        net::EchoParams params;
        params.identifier = identifier;
        params.sequence = static_cast<std::uint16_t>(attempt + 1);

        const auto request = net::buildEchoRequest(params);
        if (!socket.send(request, address)) {
            return false;
        }

        const auto deadline = Clock::now() + timeout;
        while (Clock::now() < deadline && !stop.stop_requested()) {
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
            const std::size_t received = socket.receive(buffer, remaining);
            if (received == 0) {
                break;
            }

            const auto message = net::parseIcmpMessage({buffer.data(), received});
            // O raw socket ICMP entrega toda resposta que chega ao host: só conta a que
            // vem do alvo e carrega o identificador desta sonda.
            if (message && message->type == net::kIcmpEchoReply && message->source == address &&
                message->identifier == identifier) {
                return true;
            }
        }
    }

    return false;
}

/// Qualquer desfecho conclusivo de connect() prova que o host está no ar: conexão aceita
/// mostra serviço escutando, e recusa mostra que a pilha do alvo respondeu.
bool pingByTcp(IpAddress address, std::chrono::milliseconds timeout, std::stop_token stop) {
    const net::NetworkSubsystem subsystem;

    for (Port port : kFallbackPorts) {
        if (stop.stop_requested()) {
            return false;
        }

        auto socket = net::createTcpSocket();
        if (!socket.isValid()) {
            continue;
        }

        const auto attempt = net::beginConnect(socket, address, port);
        if (attempt.progress == net::ConnectProgress::Connected) {
            return true;
        }
        if (attempt.progress == net::ConnectProgress::Failed) {
            if (attempt.error == net::SocketError::Refused) {
                return true;
            }
            continue;
        }

        net::Poller poller;
        if (!poller.add(socket.handle())) {
            continue;
        }

        std::vector<net::PollEvent> events;
        poller.wait(events, timeout);

        if (!events.empty()) {
            const auto error = net::completeConnect(socket);
            if (error == net::SocketError::None || error == net::SocketError::Refused) {
                return true;
            }
        }
    }

    return false;
}

} // namespace

bool isHostUp(IpAddress address, const ScanConfig& config, std::stop_token stop) {
    if (config.skipHostDiscovery) {
        return true;
    }

    const auto timing = parametersFor(config.timing);
    const auto timeout = config.effectiveTimeout();
    const int attempts = std::max(1, timing.retries);

    if (pingByIcmp(address, timeout, attempts, stop)) {
        return true;
    }
    return pingByTcp(address, timeout, stop);
}

} // namespace cabral::discovery
