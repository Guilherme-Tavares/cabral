#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace cabral {

/// Endereço IPv4 como valor puro. Parsing textual apenas: resolução de nomes é
/// responsabilidade de discovery/, não de model/.
class IpAddress {
public:
    constexpr IpAddress() noexcept = default;
    constexpr explicit IpAddress(std::uint32_t value) noexcept : value_(value) {}

    /// Aceita apenas a forma decimal pontuada com quatro octetos. Formas que inet_addr
    /// aceita (octal, hex, "10.1" abreviado) são rejeitadas de propósito: em um scanner,
    /// aceitá-las silenciosamente faria varrer um alvo diferente do digitado.
    static std::optional<IpAddress> parse(std::string_view text);

    constexpr std::uint32_t value() const noexcept { return value_; }

    constexpr std::array<std::uint8_t, 4> octets() const noexcept {
        return {static_cast<std::uint8_t>((value_ >> 24) & 0xFFu),
                static_cast<std::uint8_t>((value_ >> 16) & 0xFFu),
                static_cast<std::uint8_t>((value_ >> 8) & 0xFFu),
                static_cast<std::uint8_t>(value_ & 0xFFu)};
    }

    std::string toString() const;

    friend constexpr bool operator==(IpAddress, IpAddress) noexcept = default;
    friend constexpr auto operator<=>(IpAddress, IpAddress) noexcept = default;

private:
    std::uint32_t value_ = 0;
};

} // namespace cabral
