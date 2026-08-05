#include <cabral/ScanEngine.hpp>
#include <cabral/discovery/HostDiscovery.hpp>
#include <cabral/net/RawSocket.hpp>
#include <cabral/scan/ConnectScanner.hpp>
#include <cabral/scan/SynScanner.hpp>
#include <cabral/scan/UdpScanner.hpp>
#include <cabral/services/ServiceTable.hpp>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stop_token>
#include <thread>

namespace cabral {
namespace {

std::unique_ptr<scan::IScanStrategy> makeStrategy(ScanType type) {
    switch (type) {
    case ScanType::Connect:
        return std::make_unique<scan::ConnectScanner>();
    case ScanType::Syn:
        return std::make_unique<scan::SynScanner>();
    case ScanType::Udp:
        return std::make_unique<scan::UdpScanner>();
    // -sn não varre portas: a descoberta é feita direto pelo worker.
    case ScanType::PingSweep:
        return nullptr;
    }
    return nullptr;
}

} // namespace

std::string_view toString(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::Debug:
        return "debug";
    case LogLevel::Info:
        return "info";
    case LogLevel::Warning:
        return "warning";
    case LogLevel::Error:
        return "error";
    }
    return "info";
}

struct ScanEngine::Impl {
    explicit Impl(ScanConfig cfg) : config(std::move(cfg)) {}

    ScanConfig config;
    services::ServiceTable services = services::ServiceTable::loadSystemDefault();

    std::vector<IpAddress> targets;
    ScanCallbacks callbacks;

    std::vector<std::jthread> workers;
    std::stop_source stopSource;

    std::atomic<std::size_t> nextTarget{0};
    std::atomic<std::size_t> completed{0};
    std::atomic<bool> running{false};

    /// Workers ainda não encerrados. O último a sair baixa `running`, para que um
    /// consumidor não bloqueante — a GUI — perceba o fim sem chamar wait().
    std::atomic<std::size_t> activeWorkers{0};

    // Serializa os callbacks: eles disparam de várias threads e um consumidor ingênuo
    // (a CLI escrevendo em stdout) entrelaçaria a saída.
    std::mutex callbackMutex;

    void log(LogLevel level, std::string_view message) {
        if (!callbacks.onLog) {
            return;
        }
        std::lock_guard lock(callbackMutex);
        callbacks.onLog(level, message);
    }

    void runWorker(std::stop_token stop) {
        // Baixa `running` quando o último worker sai, independentemente do caminho de
        // saída — inclusive o retorno antecipado logo abaixo.
        struct ExitGuard {
            Impl& impl;
            ~ExitGuard() {
                if (impl.activeWorkers.fetch_sub(1) == 1) {
                    impl.running = false;
                }
            }
        } guard{*this};

        const bool sweepOnly = config.scanType == ScanType::PingSweep;
        auto strategy = sweepOnly ? nullptr : makeStrategy(config.scanType);
        if (!sweepOnly && !strategy) {
            return;
        }

        while (!stop.stop_requested()) {
            const std::size_t index = nextTarget.fetch_add(1);
            if (index >= targets.size()) {
                break;
            }

            const IpAddress target = targets[index];

            HostResult host;
            host.address = target;

            if (sweepOnly) {
                host.isUp = discovery::isHostUp(target, config, stop);
            } else {
                host.ports = strategy->scan(target, config.ports, config, stop);

                // Host up exige resposta de fato: aberta ou fechada. Filtrado não prova
                // que o host existe.
                //
                // No UDP, porém, a ausência de resposta é o resultado normal e produz
                // OpenFiltered em toda porta. Tratar isso como host inativo apagaria o
                // relatório inteiro, escondendo justamente o estado que -sU existe para
                // reportar. Nesse caso a varredura fala por si.
                const bool answered =
                    std::any_of(host.ports.begin(), host.ports.end(), [](const PortResult& p) {
                        return p.state == PortState::Open || p.state == PortState::Closed;
                    });
                const bool udpAmbiguous =
                    config.scanType == ScanType::Udp &&
                    std::any_of(host.ports.begin(), host.ports.end(), [](const PortResult& p) {
                        return p.state == PortState::OpenFiltered;
                    });

                // -Pn afirma que o alvo está ativo e que a descoberta deve ser pulada.
                // Sem isto, um host que só produz portas filtradas seria dado como inativo
                // e teria o relatório inteiro suprimido — justamente o caso em que -Pn é
                // usado.
                host.isUp = answered || udpAmbiguous || config.skipHostDiscovery;
            }

            for (auto& port : host.ports) {
                const auto name = services.lookup(port.port, port.protocol);
                port.service = std::string(name);
            }

            const std::size_t done = completed.fetch_add(1) + 1;
            {
                std::lock_guard lock(callbackMutex);
                if (callbacks.onHostComplete) {
                    callbacks.onHostComplete(host);
                }
                if (callbacks.onProgress) {
                    callbacks.onProgress(done, targets.size());
                }
            }
        }
    }

    void joinWorkers() {
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        workers.clear();
        running = false;
    }
};

ScanEngine::ScanEngine(ScanConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}

ScanEngine::~ScanEngine() {
    requestStop();
    impl_->joinWorkers();
}

void ScanEngine::start(std::vector<IpAddress> targets, ScanCallbacks callbacks) {
    if (impl_->running.exchange(true)) {
        return;
    }

    impl_->targets = std::move(targets);
    impl_->callbacks = std::move(callbacks);
    impl_->nextTarget = 0;
    impl_->completed = 0;
    impl_->stopSource = std::stop_source{};

    if (impl_->targets.empty()) {
        impl_->running = false;
        return;
    }

    const bool sweepOnly = impl_->config.scanType == ScanType::PingSweep;
    auto strategy = sweepOnly ? nullptr : makeStrategy(impl_->config.scanType);

    if (!sweepOnly && !strategy) {
        impl_->log(LogLevel::Error, "selected scan type is not implemented yet");
        impl_->running = false;
        return;
    }

    // Falta de privilégio precisa virar orientação antes da varredura começar, não EPERM
    // cru no meio dela. O ping sweep é exceção: sem CAP_NET_RAW ele ainda funciona pelo
    // fallback TCP, com menos alcance.
    if (strategy && strategy->requiresRawSocket()) {
        const auto capability = net::probeRawCapability();
        if (capability != net::RawCapability::Available) {
            impl_->log(LogLevel::Error, net::rawCapabilityAdvice(capability));
            impl_->running = false;
            return;
        }
    }
    if (sweepOnly && net::probeRawCapability() != net::RawCapability::Available) {
        impl_->log(LogLevel::Warning,
                   "no CAP_NET_RAW: host discovery falls back to TCP probes on 80 and 443, "
                   "so hosts that ignore them will be reported as down");
    }

    // -sU envia por socket comum, mas sem ICMP não observa port unreachable: toda porta
    // que não responder fica OpenFiltered, sem distinguir fechada de filtrada.
    if (impl_->config.scanType == ScanType::Udp &&
        net::probeRawCapability() != net::RawCapability::Available) {
        impl_->log(LogLevel::Warning,
                   "no raw ICMP access: closed UDP ports cannot be distinguished from "
                   "filtered ones, so unanswered ports are reported as open|filtered");
    }

    const auto timing = parametersFor(impl_->config.timing);
    const std::size_t poolSize =
        std::max<std::size_t>(1, std::min(timing.hostConcurrency, impl_->targets.size()));

    // Contabiliza antes de criar: um worker que termine de imediato não pode zerar a conta
    // enquanto os demais ainda estão sendo lançados.
    impl_->activeWorkers = poolSize;

    impl_->workers.reserve(poolSize);
    for (std::size_t i = 0; i < poolSize; ++i) {
        impl_->workers.emplace_back([this](std::stop_token stop) { impl_->runWorker(stop); });
    }
}

void ScanEngine::requestStop() {
    impl_->stopSource.request_stop();
    for (auto& worker : impl_->workers) {
        worker.request_stop();
    }
}

bool ScanEngine::isRunning() const noexcept {
    return impl_->running.load();
}

void ScanEngine::wait() {
    impl_->joinWorkers();
}

} // namespace cabral
