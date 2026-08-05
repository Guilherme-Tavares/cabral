#pragma once

#include <cabral/net/Socket.hpp>
#include <cabral/scan/IScanStrategy.hpp>

namespace cabral::scan {

/// Traduz o desfecho de connect() no estado da porta. Exposto para teste: é a regra que
/// define a semântica de -sT e precisa ser verificável sem depender da rede do host.
PortState stateForConnectResult(net::SocketError error) noexcept;

/// Varredura por connect() completo (-sT). Não exige privilégio: é a base de referência
/// contra a qual -sS e -sU são conferidos.
///
/// connect() bem-sucedido -> Open; ECONNREFUSED -> Closed; sem resposta -> Filtered.
class ConnectScanner final : public IScanStrategy {
public:
    Protocol protocol() const noexcept override { return Protocol::Tcp; }
    bool requiresRawSocket() const noexcept override { return false; }
    std::string_view name() const noexcept override { return "connect"; }

    std::vector<PortResult> scan(const IpAddress& target, std::span<const Port> ports,
                                 const ScanConfig& config, std::stop_token stop) override;
};

} // namespace cabral::scan
