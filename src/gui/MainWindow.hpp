#pragma once

#include <cabral/model/ScanResult.hpp>

#include <string>
#include <vector>

#include "ResultQueue.hpp"
#include "ScanController.hpp"

namespace cabral::gui {

/// Janela única do aplicativo. Contém apenas apresentação: qualquer socket aqui violaria a
/// separação que a arquitetura exige.
class MainWindow {
public:
    MainWindow();

    /// Desenha um frame. Chamado pela thread de render, entre o início e o fim do frame do
    /// backend.
    void draw();

    bool wantsToClose() const noexcept { return closeRequested_; }

private:
    void drawControls();
    void drawProgress();
    void drawResults();
    void drawLog();

    /// Move o que as threads worker acumularam para o estado local, uma vez por frame.
    void drainQueue();

    ScanController controller_;

    // Campos de entrada. Buffers fixos porque InputText do ImGui escreve em char[].
    char targetBuffer_[256] = "127.0.0.1";
    char portBuffer_[256] = "1-1024";
    int scanTypeIndex_ = 0;
    int timingIndex_ = 3;
    bool skipHostDiscovery_ = false;
    bool allowLargeRange_ = false;

    bool rawAvailable_ = false;
    std::string rawUnavailableReason_;

    std::vector<HostResult> hosts_;
    std::vector<LogEntry> logs_;
    std::string errorMessage_;

    bool closeRequested_ = false;
    bool logAutoScroll_ = true;
};

} // namespace cabral::gui
