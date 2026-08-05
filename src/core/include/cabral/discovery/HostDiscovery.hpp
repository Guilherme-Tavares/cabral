#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/ScanConfig.hpp>

#include <chrono>
#include <stop_token>

namespace cabral::discovery {

/// Verifica se um host responde, tentando em ordem e parando no primeiro sucesso:
///   1. ICMP echo request, quando há CAP_NET_RAW
///   2. TCP connect em 80 e 443, tratando qualquer resposta — inclusive recusa — como
///      evidência de host ativo
///
/// O fallback TCP não exige privilégio, então a descoberta continua funcionando sem
/// capabilities, apenas com menos alcance: um host que ignora ICMP e não escuta em 80 nem
/// 443 será dado como inativo.
bool isHostUp(IpAddress address, const ScanConfig& config, std::stop_token stop);

} // namespace cabral::discovery
