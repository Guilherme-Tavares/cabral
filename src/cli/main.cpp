#include <cabral/ScanEngine.hpp>
#include <cabral/model/IpAddress.hpp>
#include <cabral/model/PortState.hpp>

#include <chrono>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "ArgParser.hpp"
#include "TableFormatter.hpp"

namespace {

using cabral::cli::ScanSummary;

std::string_view describe(cabral::ScanType type) noexcept {
    switch (type) {
    case cabral::ScanType::Connect:
        return "connect";
    case cabral::ScanType::Syn:
        return "syn";
    case cabral::ScanType::Udp:
        return "udp";
    case cabral::ScanType::PingSweep:
        return "ping sweep";
    }
    return "unknown";
}

/// Fase 2 aceita apenas IPv4 literal. Hostname, CIDR e ranges entram na fase 4, junto com
/// discovery/; até lá, recusar é mais honesto do que varrer o alvo errado.
bool resolveTargets(const std::vector<std::string>& literals, std::vector<cabral::IpAddress>& out) {
    bool ok = true;
    for (const auto& text : literals) {
        if (const auto address = cabral::IpAddress::parse(text)) {
            out.push_back(*address);
        } else {
            std::cerr << "cabral: cannot resolve '" << text
                      << "'; only literal IPv4 addresses are supported in this build\n";
            ok = false;
        }
    }
    return ok;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> args(argv + 1, argv + argc);

    auto parsed = cabral::cli::parseArguments(args);
    if (!parsed) {
        std::cerr << "cabral: " << parsed.error().message << '\n';
        return 2;
    }

    const auto& options = parsed.value();

    switch (options.action) {
    case cabral::cli::Action::ShowHelp:
        std::cout << cabral::cli::usageText();
        return 0;
    case cabral::cli::Action::ShowVersion:
        std::cout << cabral::cli::versionText();
        return 0;
    case cabral::cli::Action::Scan:
        break;
    }

    if (options.config.scanType != cabral::ScanType::Connect) {
        std::cerr << "cabral: " << describe(options.config.scanType)
                  << " scan is not implemented yet; use -sT\n";
        return 3;
    }
    if (!options.targetListFile.empty()) {
        std::cerr << "cabral: -iL is not implemented yet\n";
        return 3;
    }
    if (options.topPorts > 0) {
        std::cerr << "cabral: --top-ports is not implemented yet; use -p\n";
        return 3;
    }

    std::vector<cabral::IpAddress> targets;
    if (!resolveTargets(options.targets, targets) || targets.empty()) {
        return 2;
    }

    std::cout << "Starting cabral 0.1.0\n";

    ScanSummary summary;
    summary.hostsScanned = targets.size();

    const auto started = std::chrono::steady_clock::now();

    cabral::ScanEngine engine(options.config);

    cabral::ScanCallbacks callbacks;
    callbacks.onHostComplete = [&](const cabral::HostResult& host) {
        if (host.isUp) {
            ++summary.hostsUp;
        }
        for (const auto& port : host.ports) {
            if (port.state == cabral::PortState::Open) {
                ++summary.openPorts;
            }
        }
        std::cout << cabral::cli::formatHost(host, options.config.verbosity);
    };
    callbacks.onLog = [&](cabral::LogLevel level, std::string_view message) {
        if (level >= cabral::LogLevel::Warning || options.config.verbosity > 0) {
            std::cerr << "cabral: " << message << '\n';
        }
    };

    engine.start(std::move(targets), std::move(callbacks));
    engine.wait();

    summary.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    std::cout << cabral::cli::formatSummary(summary);
    return 0;
}
