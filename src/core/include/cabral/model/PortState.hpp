#pragma once

#include <cstdint>
#include <string_view>

namespace cabral {

enum class Protocol : std::uint8_t { Tcp, Udp };

/// OpenFiltered é irredutível: é o estado correto para UDP sem resposta e para SYN scan
/// contra host que descarta silenciosamente. Colapsá-lo em Open ou Filtered é incorreto.
enum class PortState : std::uint8_t { Open, Closed, Filtered, OpenFiltered, Unknown };

std::string_view toString(Protocol protocol) noexcept;
std::string_view toString(PortState state) noexcept;

} // namespace cabral
