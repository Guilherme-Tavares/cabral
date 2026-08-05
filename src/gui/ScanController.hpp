#pragma once

#include <cabral/ScanEngine.hpp>
#include <cabral/model/ScanConfig.hpp>

#include <memory>
#include <string>

#include "ResultQueue.hpp"

namespace cabral::gui {

/// Estado de uma varredura vista pela janela. A GUI não fala com sockets: pede uma
/// varredura aqui e lê o que a fila entrega.
class ScanController {
public:
    struct Request {
        std::string targetSpec;
        std::string portSpec;
        ScanType scanType = ScanType::Connect;
        TimingProfile timing = TimingProfile::Normal;
        bool skipHostDiscovery = false;
        bool allowLargeRange = false;
    };

    ResultQueue& queue() noexcept { return queue_; }

    bool isRunning() const noexcept;

    /// Valida a requisição e inicia a varredura. Em erro de validação devolve a mensagem e
    /// não inicia nada.
    bool start(const Request& request, std::string& error);

    void requestStop();

    /// Libera o engine quando a varredura termina, para que isRunning reflita a realidade.
    void poll();

private:
    ResultQueue queue_;
    std::unique_ptr<ScanEngine> engine_;
    std::size_t expectedHosts_ = 0;
};

} // namespace cabral::gui
