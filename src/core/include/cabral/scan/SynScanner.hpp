#pragma once

#include <cabral/scan/IScanStrategy.hpp>

namespace cabral::scan {

/// Varredura por SYN sem completar o handshake (-sS). Exige CAP_NET_RAW.
///
/// SYN/ACK -> Open; RST -> Closed; silêncio após as retransmissões -> Filtered.
///
/// A correlação usa uma porta de origem efêmera escolhida no início da varredura: o raw
/// socket de recepção entrega todo segmento TCP que chega ao host, e sem esse filtro a
/// varredura leria respostas de conexões alheias como se fossem suas.
class SynScanner final : public IScanStrategy {
public:
    Protocol protocol() const noexcept override { return Protocol::Tcp; }
    bool requiresRawSocket() const noexcept override { return true; }
    std::string_view name() const noexcept override { return "syn"; }

    std::vector<PortResult> scan(const IpAddress& target, std::span<const Port> ports,
                                 const ScanConfig& config, std::stop_token stop) override;
};

} // namespace cabral::scan
