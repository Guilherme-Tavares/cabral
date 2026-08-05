#include "ScanController.hpp"

#include <cabral/discovery/TargetExpander.hpp>
#include <cabral/model/PortRange.hpp>

#include <string>

namespace cabral::gui {

bool ScanController::isRunning() const noexcept {
    return engine_ != nullptr && engine_->isRunning();
}

bool ScanController::start(const Request& request, std::string& error) {
    if (isRunning()) {
        error = "a scan is already running";
        return false;
    }

    discovery::ExpansionOptions expansion;
    expansion.allowLargeRange = request.allowLargeRange;

    auto targets = discovery::expandTarget(request.targetSpec, expansion);
    if (!targets) {
        error = std::string(discovery::describe(targets.error()));
        return false;
    }
    if (targets.value().empty()) {
        error = "no targets to scan";
        return false;
    }

    ScanConfig config;
    config.scanType = request.scanType;
    config.timing = request.timing;
    config.skipHostDiscovery = request.skipHostDiscovery;
    config.allowLargeRange = request.allowLargeRange;

    // Ping sweep não varre portas; para os demais tipos a especificação é obrigatória.
    if (request.scanType != ScanType::PingSweep) {
        auto ports = parsePortSpec(request.portSpec);
        if (!ports) {
            error = std::string(describe(ports.error()));
            return false;
        }
        config.ports = std::move(ports).value();
    }

    queue_.clear();
    expectedHosts_ = targets.value().size();

    // O engine anterior é destruído aqui, o que pede stop e faz join no destrutor.
    engine_ = std::make_unique<ScanEngine>(std::move(config));

    ScanCallbacks callbacks;
    // Estes três disparam de threads worker: apenas enfileiram, nunca tocam ImGui.
    callbacks.onHostComplete = [this](const HostResult& host) { queue_.pushHost(host); };
    callbacks.onProgress = [this](std::size_t done, std::size_t total) {
        queue_.setProgress(done, total);
    };
    callbacks.onLog = [this](LogLevel level, std::string_view message) {
        queue_.pushLog(level, message);
    };

    queue_.setProgress(0, expectedHosts_);
    engine_->start(std::move(targets).value(), std::move(callbacks));
    return true;
}

void ScanController::requestStop() {
    if (engine_) {
        engine_->requestStop();
    }
}

void ScanController::poll() {
    // O último worker baixa isRunning ao sair, então este join encontra as threads já
    // encerradas e retorna de imediato — a thread de render nunca bloqueia aqui.
    if (engine_ && !engine_->isRunning()) {
        engine_->wait();
    }
}

} // namespace cabral::gui
