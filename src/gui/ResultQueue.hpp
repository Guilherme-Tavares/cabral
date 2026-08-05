#pragma once

#include <cabral/ScanEngine.hpp>
#include <cabral/model/ScanResult.hpp>

#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

namespace cabral::gui {

struct LogEntry {
    LogLevel level = LogLevel::Info;
    std::string message;
};

/// Ponte entre as threads worker do ScanEngine e o loop de render.
///
/// Os callbacks do engine disparam de threads worker. Tocar estado de ImGui a partir delas
/// corrompe o contexto em silêncio, sem erro visível. Por isso os resultados são apenas
/// enfileirados aqui, e a janela os drena no início de cada frame — na thread de render.
///
/// Toda a API é segura para chamada concorrente.
class ResultQueue {
public:
    void pushHost(HostResult host);
    void pushLog(LogLevel level, std::string_view message);
    void setProgress(std::size_t done, std::size_t total);

    /// Move o que foi acumulado para o chamador, esvaziando a fila. Chamado uma vez por
    /// frame, na thread de render.
    std::vector<HostResult> drainHosts();
    std::vector<LogEntry> drainLogs();

    struct Progress {
        std::size_t done = 0;
        std::size_t total = 0;
    };
    Progress progress() const;

    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<HostResult> hosts_;
    std::vector<LogEntry> logs_;
    Progress progress_;
};

} // namespace cabral::gui
