#pragma once

#include <cabral/model/ScanResult.hpp>

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace cabral::cli {

struct ScanSummary {
    std::size_t hostsScanned = 0;
    std::size_t hostsUp = 0;
    std::size_t openPorts = 0;
    std::chrono::milliseconds elapsed{0};
};

/// Tabela de um host. Portas fechadas são resumidas em uma linha: listar 998 linhas
/// "closed" afogaria as poucas que interessam.
///
/// Hosts inativos produzem saída vazia sem -v, pela mesma razão: numa varredura de /24 os
/// 247 hosts ausentes esconderiam os 9 que respondem. A contagem aparece no resumo final.
std::string formatHost(const HostResult& host, int verbosity);

std::string formatSummary(const ScanSummary& summary);

} // namespace cabral::cli
