#pragma once

#include <cabral/scan/IScanStrategy.hpp>

namespace cabral::scan {

/// Varredura UDP (-sU). Envia por socket UDP comum e escuta ICMP por raw socket.
///
/// Resposta UDP da porta -> Open; ICMP tipo 3 código 3 -> Closed; demais códigos de tipo 3
/// -> Filtered; silêncio após retransmissões -> OpenFiltered.
///
/// OpenFiltered é irredutível: sem resposta, não há como distinguir uma porta aberta que
/// ignora a sonda de uma porta filtrada. Colapsá-lo em Open ou Filtered seria incorreto.
///
/// A varredura é inerentemente lenta. O kernel Linux limita a taxa de ICMP unreachable
/// (net.ipv4.icmp_ratelimit), e esse limite é respeitado, não contornado.
class UdpScanner final : public IScanStrategy {
public:
    Protocol protocol() const noexcept override { return Protocol::Udp; }

    /// O envio usa socket UDP comum; só a recepção de ICMP exige privilégio. Sem ela a
    /// varredura ainda distingue Open por resposta direta e reporta OpenFiltered no resto,
    /// que é a degradação prevista para o Windows. Recusar a varredura inteira por falta de
    /// raw socket eliminaria -sU de uma plataforma onde ele é suportado.
    bool requiresRawSocket() const noexcept override { return false; }

    std::string_view name() const noexcept override { return "udp"; }

    std::vector<PortResult> scan(const IpAddress& target, std::span<const Port> ports,
                                 const ScanConfig& config, std::stop_token stop) override;
};

} // namespace cabral::scan
