#pragma once

#include <cabral/model/PortRange.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cabral {

enum class ScanType : std::uint8_t {
    Connect,   // -sT
    Syn,       // -sS
    Udp,       // -sU
    PingSweep, // -sn
};

enum class OutputFormat : std::uint8_t { Text, Json };

/// Perfis -T0 a -T5. Ajustam timeout, retransmissões e paralelismo em conjunto; o padrão
/// é Normal (-T3).
enum class TimingProfile : std::uint8_t {
    Paranoid = 0,
    Sneaky = 1,
    Polite = 2,
    Normal = 3,
    Aggressive = 4,
    Insane = 5,
};

struct TimingParameters {
    std::chrono::milliseconds timeout{1000};
    int retries = 2;
    std::size_t hostConcurrency = 16;
    std::size_t portConcurrency = 128;
};

TimingParameters parametersFor(TimingProfile profile) noexcept;

struct ScanConfig {
    ScanType scanType = ScanType::Connect;
    TimingProfile timing = TimingProfile::Normal;

    std::vector<Port> ports;
    bool skipHostDiscovery = false; // -Pn
    bool allowLargeRange = false;   // --allow-large-range

    /// Sobrepõe o timeout do perfil quando presente (--timeout).
    std::optional<std::chrono::milliseconds> timeoutOverride;

    int verbosity = 0;

    std::string outputPath;
    OutputFormat outputFormat = OutputFormat::Text;

    /// Resolve o timeout efetivo: --timeout vence o perfil de temporização.
    std::chrono::milliseconds effectiveTimeout() const noexcept {
        return timeoutOverride.value_or(parametersFor(timing).timeout);
    }
};

} // namespace cabral
