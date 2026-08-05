#include <cabral/ScanEngine.hpp>
#include <cabral/discovery/TargetExpander.hpp>
#include <cabral/model/IpAddress.hpp>
#include <cabral/model/PortState.hpp>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "ArgParser.hpp"
#include "ResultWriter.hpp"
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

/// Expande alvos literais e o arquivo de -iL em endereços concretos.
bool resolveTargets(const cabral::cli::ParsedArguments& options,
                    std::vector<cabral::IpAddress>& out) {
    cabral::discovery::ExpansionOptions expansion;
    expansion.allowLargeRange = options.config.allowLargeRange;

    if (!options.targets.empty()) {
        auto expanded = cabral::discovery::expandTargets(options.targets, expansion);
        if (!expanded) {
            std::cerr << "cabral: " << cabral::discovery::describe(expanded.error()) << '\n';
            return false;
        }
        const auto& values = expanded.value();
        out.insert(out.end(), values.begin(), values.end());
    }

    if (!options.targetListFile.empty()) {
        auto expanded = cabral::discovery::expandTargetFile(options.targetListFile, expansion);
        if (!expanded) {
            std::cerr << "cabral: " << options.targetListFile << ": "
                      << cabral::discovery::describe(expanded.error()) << '\n';
            return false;
        }
        const auto& values = expanded.value();
        out.insert(out.end(), values.begin(), values.end());
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return true;
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

    std::vector<cabral::IpAddress> targets;
    if (!resolveTargets(options, targets)) {
        return 2;
    }
    if (targets.empty()) {
        std::cerr << "cabral: no targets to scan\n";
        return 2;
    }

    std::cout << "Starting cabral 0.1.0 (" << describe(options.config.scanType) << " scan, "
              << targets.size() << " host" << (targets.size() == 1 ? "" : "s") << ")\n";

    ScanSummary summary;
    summary.hostsScanned = targets.size();

    const auto started = std::chrono::steady_clock::now();

    cabral::ScanEngine engine(options.config);

    // Guardados para a exportação. O ScanEngine já serializa os callbacks, mas o vetor é
    // lido depois do wait(), quando nenhuma worker resta.
    const bool exporting = !options.config.outputPath.empty();
    std::vector<cabral::HostResult> collected;

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
        if (exporting) {
            collected.push_back(host);
        }
        std::cout << cabral::cli::formatHost(host, options.config.verbosity);
    };
    bool failed = false;
    callbacks.onLog = [&](cabral::LogLevel level, std::string_view message) {
        if (level == cabral::LogLevel::Error) {
            failed = true;
        }
        if (level >= cabral::LogLevel::Warning || options.config.verbosity > 0) {
            std::cerr << "cabral: " << message << '\n';
        }
    };

    engine.start(std::move(targets), std::move(callbacks));
    engine.wait();

    // Varredura abortada não deve sair com sucesso nem imprimir um resumo vazio como se
    // tivesse concluído.
    if (failed) {
        return 4;
    }

    summary.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started);

    std::cout << cabral::cli::formatSummary(summary);

    if (exporting) {
        // Ordena por endereço: os hosts chegam na ordem em que as workers terminam, que
        // varia entre execuções e tornaria os arquivos difíceis de comparar.
        std::sort(collected.begin(), collected.end(),
                  [](const cabral::HostResult& a, const cabral::HostResult& b) {
                      return a.address < b.address;
                  });

        const std::string contents = (options.config.outputFormat == cabral::OutputFormat::Json)
                                         ? cabral::cli::toJson(collected, summary, options.config)
                                         : cabral::cli::toText(collected, summary);

        std::string error;
        if (!cabral::cli::writeToFile(options.config.outputPath, contents, error)) {
            std::cerr << "cabral: " << error << '\n';
            return 5;
        }
        std::cout << "Results written to " << options.config.outputPath << '\n';
    }

    return 0;
}
