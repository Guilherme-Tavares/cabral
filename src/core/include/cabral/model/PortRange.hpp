#pragma once

#include <cabral/model/Result.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cabral {

using Port = std::uint16_t;

enum class PortSpecError : std::uint8_t {
    Empty,
    InvalidCharacter,
    PortOutOfRange,
    InvertedRange,
    MalformedRange,
};

std::string_view describe(PortSpecError error) noexcept;

/// Interpreta a sintaxe de -p: "22", "1-1024", "22,80,443", "-" (todas), e combinações
/// como "22,1000-1010". Extremo omitido assume o limite: "-100" é 1-100, "1000-" é
/// 1000-65535.
///
/// O resultado vem ordenado e sem duplicatas, de modo que "80,80,22" e "22,80" produzem
/// a mesma varredura.
Result<std::vector<Port>, PortSpecError> parsePortSpec(std::string_view spec);

} // namespace cabral
