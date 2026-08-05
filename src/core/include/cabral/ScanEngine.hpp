#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/ScanConfig.hpp>
#include <cabral/model/ScanResult.hpp>

#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

namespace cabral {

enum class LogLevel : std::uint8_t { Debug, Info, Warning, Error };

std::string_view toString(LogLevel level) noexcept;

/// Os callbacks disparam a partir de threads worker. A CLI pode escrever direto; a GUI
/// não pode tocar estado de ImGui aqui — precisa enfileirar e drenar no próprio frame.
struct ScanCallbacks {
    std::function<void(const HostResult&)> onHostComplete;
    std::function<void(std::size_t done, std::size_t total)> onProgress;
    std::function<void(LogLevel, std::string_view)> onLog;
};

class ScanEngine {
public:
    explicit ScanEngine(ScanConfig config);
    ~ScanEngine();

    ScanEngine(const ScanEngine&) = delete;
    ScanEngine& operator=(const ScanEngine&) = delete;

    /// Dispara a varredura e retorna de imediato. Chamar com uma varredura em curso é
    /// ignorado.
    void start(std::vector<IpAddress> targets, ScanCallbacks callbacks);

    void requestStop();
    bool isRunning() const noexcept;

    /// Bloqueia até o fim. A CLI usa isto; a GUI não deve.
    void wait();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cabral
