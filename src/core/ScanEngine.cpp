#include <cabral/ScanEngine.hpp>
#include <cabral/scan/ConnectScanner.hpp>
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
    // -sS, -sU e -sn entram nas fases 3 e 4; até lá, connect é o único caminho real.
    case ScanType::Syn:
    case ScanType::Udp:
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
        auto strategy = makeStrategy(config.scanType);
        if (!strategy) {
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
            host.ports = strategy->scan(target, config.ports, config, stop);

            // Host up se alguma porta respondeu de fato, aberta ou fechada. Só filtrado
            // não é evidência de host ativo.
            host.isUp = std::any_of(host.ports.begin(), host.ports.end(), [](const PortResult& p) {
                return p.state == PortState::Open || p.state == PortState::Closed;
            });

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

    if (!makeStrategy(impl_->config.scanType)) {
        impl_->log(LogLevel::Error, "selected scan type is not implemented yet");
        impl_->running = false;
        return;
    }

    const auto timing = parametersFor(impl_->config.timing);
    const std::size_t poolSize =
        std::max<std::size_t>(1, std::min(timing.hostConcurrency, impl_->targets.size()));

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
