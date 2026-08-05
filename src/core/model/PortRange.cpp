#include <cabral/model/PortRange.hpp>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <system_error>

namespace cabral {
namespace {

constexpr Port kMinPort = 1;
constexpr Port kMaxPort = 65535;

std::string_view trim(std::string_view text) {
    const auto isSpace = [](char c) { return c == ' ' || c == '\t'; };
    while (!text.empty() && isSpace(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && isSpace(text.back())) {
        text.remove_suffix(1);
    }
    return text;
}

Result<Port, PortSpecError> parsePort(std::string_view text) {
    if (text.empty()) {
        return Failure(PortSpecError::Empty);
    }
    for (char c : text) {
        if (c < '0' || c > '9') {
            return Failure(PortSpecError::InvalidCharacter);
        }
    }

    unsigned long parsed = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, parsed);
    if (ec != std::errc{} || ptr != end) {
        return Failure(PortSpecError::PortOutOfRange);
    }
    // Porta 0 é sintaticamente válida mas não é alvo de varredura.
    if (parsed < kMinPort || parsed > kMaxPort) {
        return Failure(PortSpecError::PortOutOfRange);
    }
    return static_cast<Port>(parsed);
}

Result<std::vector<Port>, PortSpecError> parseToken(std::string_view token,
                                                    std::vector<Port>& out) {
    token = trim(token);
    if (token.empty()) {
        return Failure(PortSpecError::Empty);
    }

    const std::size_t dash = token.find('-');
    if (dash == std::string_view::npos) {
        const auto port = parsePort(token);
        if (!port) {
            return Failure(port.error());
        }
        out.push_back(port.value());
        return out;
    }

    if (token.find('-', dash + 1) != std::string_view::npos) {
        return Failure(PortSpecError::MalformedRange);
    }

    const std::string_view lowText = trim(token.substr(0, dash));
    const std::string_view highText = trim(token.substr(dash + 1));

    Port low = kMinPort;
    if (!lowText.empty()) {
        const auto parsed = parsePort(lowText);
        if (!parsed) {
            return Failure(parsed.error());
        }
        low = parsed.value();
    }

    Port high = kMaxPort;
    if (!highText.empty()) {
        const auto parsed = parsePort(highText);
        if (!parsed) {
            return Failure(parsed.error());
        }
        high = parsed.value();
    }

    if (low > high) {
        return Failure(PortSpecError::InvertedRange);
    }

    out.reserve(out.size() + static_cast<std::size_t>(high - low) + 1);
    for (unsigned int p = low; p <= high; ++p) {
        out.push_back(static_cast<Port>(p));
    }
    return out;
}

} // namespace

std::string_view describe(PortSpecError error) noexcept {
    switch (error) {
    case PortSpecError::Empty:
        return "empty port specification";
    case PortSpecError::InvalidCharacter:
        return "port specification contains a non-numeric character";
    case PortSpecError::PortOutOfRange:
        return "port must be between 1 and 65535";
    case PortSpecError::InvertedRange:
        return "port range start is greater than its end";
    case PortSpecError::MalformedRange:
        return "malformed port range";
    }
    return "invalid port specification";
}

Result<std::vector<Port>, PortSpecError> parsePortSpec(std::string_view spec) {
    spec = trim(spec);
    if (spec.empty()) {
        return Failure(PortSpecError::Empty);
    }

    std::vector<Port> ports;

    std::size_t start = 0;
    while (start <= spec.size()) {
        const std::size_t comma = spec.find(',', start);
        const std::size_t stop = (comma == std::string_view::npos) ? spec.size() : comma;

        auto parsed = parseToken(spec.substr(start, stop - start), ports);
        if (!parsed) {
            return Failure(parsed.error());
        }

        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1;
    }

    std::sort(ports.begin(), ports.end());
    ports.erase(std::unique(ports.begin(), ports.end()), ports.end());
    return ports;
}

} // namespace cabral
