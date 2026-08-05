#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/Result.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cabral::discovery {

enum class TargetError : std::uint8_t {
    Empty,
    MalformedAddress,
    MalformedCidr,
    PrefixOutOfRange,
    MalformedRange,
    InvertedRange,
    RangeTooLarge, // acima de /24 sem --allow-large-range
    UnresolvedHostname,
};

std::string_view describe(TargetError error) noexcept;

/// Faixa máxima padrão. Acima disso é preciso --allow-large-range: uma varredura de /16
/// são 65 mil hosts, quase sempre digitação errada em vez de intenção.
constexpr std::size_t kMaxDefaultTargets = 256;

struct ExpansionOptions {
    bool allowLargeRange = false;
    /// Resolução de nome consulta a rede; desligar mantém a expansão determinística nos
    /// testes.
    bool resolveHostnames = true;
};

/// Expande uma especificação de alvo em endereços concretos.
///
/// Aceita: IP único, CIDR (192.168.1.0/24), range com hífen no último octeto
/// (192.168.1.10-40), lista separada por vírgula, e hostname.
///
/// Endereços de rede e de broadcast são mantidos: em /31 e /32 eles são hosts legítimos,
/// e descartá-los silenciosamente esconderia alvos válidos.
Result<std::vector<IpAddress>, TargetError> expandTarget(std::string_view spec,
                                                         const ExpansionOptions& options = {});

/// Expande várias especificações, removendo duplicatas e mantendo ordem crescente.
Result<std::vector<IpAddress>, TargetError> expandTargets(const std::vector<std::string>& specs,
                                                          const ExpansionOptions& options = {});

/// Lê alvos de um arquivo (-iL): um por linha, ignorando linhas vazias e comentários com
/// '#'. Cada linha passa pelas mesmas regras de expandTarget.
Result<std::vector<IpAddress>, TargetError> expandTargetFile(const std::string& path,
                                                             const ExpansionOptions& options = {});

/// Resolve um nome em endereço IPv4. Vazio se não resolver.
std::optional<IpAddress> resolveHostname(const std::string& hostname);

} // namespace cabral::discovery
