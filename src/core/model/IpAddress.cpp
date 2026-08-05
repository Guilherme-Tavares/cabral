#include <cabral/model/IpAddress.hpp>

#include <charconv>
#include <system_error>

namespace cabral {
namespace {

/// Um octeto válido tem de 1 a 3 dígitos, sem sinal e sem zero à esquerda. "01" é
/// rejeitado porque em notação clássica seria octal, e resolver essa ambiguidade a favor
/// de decimal faria o scanner mirar um endereço diferente do informado.
std::optional<std::uint8_t> parseOctet(std::string_view text) {
    if (text.empty() || text.size() > 3) {
        return std::nullopt;
    }
    if (text.size() > 1 && text.front() == '0') {
        return std::nullopt;
    }
    for (char c : text) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
    }

    unsigned int parsed = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end || parsed > 255) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(parsed);
}

} // namespace

std::optional<IpAddress> IpAddress::parse(std::string_view text) {
    std::uint32_t value = 0;
    std::size_t start = 0;

    for (int index = 0; index < 4; ++index) {
        const bool isLast = (index == 3);
        const std::size_t dot = text.find('.', start);

        if (isLast != (dot == std::string_view::npos)) {
            return std::nullopt;
        }

        const std::size_t stop = isLast ? text.size() : dot;
        const auto octet = parseOctet(text.substr(start, stop - start));
        if (!octet) {
            return std::nullopt;
        }

        value = (value << 8) | *octet;
        start = stop + 1;
    }

    return IpAddress(value);
}

std::string IpAddress::toString() const {
    const auto parts = octets();
    std::string out;
    out.reserve(15);

    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            out.push_back('.');
        }
        char buffer[4];
        const auto [ptr, ec] = std::to_chars(buffer, buffer + sizeof(buffer), parts[i]);
        if (ec == std::errc{}) {
            out.append(buffer, ptr);
        }
    }
    return out;
}

} // namespace cabral
