#include <cabral/model/PortState.hpp>

#include <iostream>
#include <span>
#include <string_view>
#include <vector>

#include "ArgParser.hpp"

namespace {

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

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> args(argv + 1, argv + argc);

    auto parsed = cabral::cli::parseArguments(args);
    if (!parsed) {
        std::cerr << "cabral: " << parsed.error().message << '\n';
        return 2;
    }

    const auto& result = parsed.value();

    switch (result.action) {
    case cabral::cli::Action::ShowHelp:
        std::cout << cabral::cli::usageText();
        return 0;
    case cabral::cli::Action::ShowVersion:
        std::cout << cabral::cli::versionText();
        return 0;
    case cabral::cli::Action::Scan:
        break;
    }

    // Fase 1 encerra na intenção: o ScanEngine entra na Fase 2.
    std::cout << "scan type: " << describe(result.config.scanType) << '\n';
    std::cout << "ports:     " << result.config.ports.size() << '\n';
    std::cout << "timeout:   " << result.config.effectiveTimeout().count() << " ms\n";
    std::cout << "targets:   ";
    for (std::size_t i = 0; i < result.targets.size(); ++i) {
        std::cout << (i > 0 ? ", " : "") << result.targets[i];
    }
    std::cout << '\n';
    std::cout << "\nscanning is not implemented yet (phase 1)\n";
    return 0;
}
