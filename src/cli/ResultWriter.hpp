#pragma once

#include <cabral/model/ScanConfig.hpp>
#include <cabral/model/ScanResult.hpp>

#include <span>
#include <string>

#include "TableFormatter.hpp"

namespace cabral::cli {

/// Escapa uma string para uso dentro de aspas em JSON (RFC 8259): aspas, contrabarra, os
/// controles nomeados, e o restante abaixo de 0x20 em \uXXXX.
std::string escapeJson(std::string_view text);

/// Serializa o resultado completo da varredura em JSON.
std::string toJson(std::span<const HostResult> hosts, const ScanSummary& summary,
                   const ScanConfig& config);

/// Serializa em texto, no mesmo formato que o terminal mostra com -v: o arquivo é para ser
/// lido depois, então omitir portas fechadas ali perderia informação que já foi coletada.
std::string toText(std::span<const HostResult> hosts, const ScanSummary& summary);

/// Grava o conteúdo no caminho indicado. Devolve falso e preenche error se falhar.
bool writeToFile(const std::string& path, std::string_view contents, std::string& error);

} // namespace cabral::cli
