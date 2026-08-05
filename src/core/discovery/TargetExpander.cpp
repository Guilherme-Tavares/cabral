#include <cabral/discovery/TargetExpander.hpp>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <system_error>

namespace cabral::discovery {
namespace {

std::string_view trim(std::string_view text) {
    const auto isSpace = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!text.empty() && isSpace(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && isSpace(text.back())) {
        text.remove_suffix(1);
    }
    return text;
}

std::optional<unsigned int> parseNumber(std::string_view text, unsigned int limit) {
    if (text.empty() || text.size() > 3) {
        return std::nullopt;
    }
    for (char c : text) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
    }
    unsigned int value = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (ec != std::errc{} || ptr != end || value > limit) {
        return std::nullopt;
    }
    return value;
}

/// Um alvo parece um hostname quando não é composto só de dígitos, pontos, barras e
/// hífens na forma numérica. Distinguir cedo evita tratar "10.0.0.1" como nome.
bool looksNumeric(std::string_view text) {
    return std::all_of(text.begin(), text.end(), [](char c) {
        return (c >= '0' && c <= '9') || c == '.' || c == '/' || c == '-';
    });
}

Result<std::vector<IpAddress>, TargetError> expandCidr(std::string_view spec, std::size_t slash,
                                                       const ExpansionOptions& options) {
    const auto base = IpAddress::parse(spec.substr(0, slash));
    if (!base) {
        return Failure(TargetError::MalformedAddress);
    }

    const auto prefix = parseNumber(spec.substr(slash + 1), 32);
    if (!prefix) {
        return Failure(TargetError::MalformedCidr);
    }
    if (*prefix > 32) {
        return Failure(TargetError::PrefixOutOfRange);
    }

    const std::uint32_t hostBits = 32u - *prefix;
    const std::uint64_t count = std::uint64_t{1} << hostBits;

    if (count > kMaxDefaultTargets && !options.allowLargeRange) {
        return Failure(TargetError::RangeTooLarge);
    }

    // Zera os bits de host: 192.168.1.37/24 vira a rede 192.168.1.0/24, como se espera.
    const std::uint32_t mask =
        (hostBits >= 32) ? 0u : static_cast<std::uint32_t>(~((std::uint64_t{1} << hostBits) - 1));
    const std::uint32_t network = base->value() & mask;

    std::vector<IpAddress> addresses;
    addresses.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t i = 0; i < count; ++i) {
        addresses.emplace_back(static_cast<std::uint32_t>(network + i));
    }
    return addresses;
}

Result<std::vector<IpAddress>, TargetError>
expandHyphenRange(std::string_view spec, std::size_t dash, const ExpansionOptions& options) {
    // Forma aceita: a.b.c.X-Y, com o hífen no último octeto.
    const std::string_view head = spec.substr(0, dash);
    const std::string_view tail = spec.substr(dash + 1);

    const auto first = IpAddress::parse(head);
    if (!first) {
        return Failure(TargetError::MalformedRange);
    }

    const auto last = parseNumber(tail, 255);
    if (!last) {
        return Failure(TargetError::MalformedRange);
    }

    const std::uint32_t start = first->value();
    const std::uint32_t end = (start & 0xFFFFFF00u) | *last;

    if (end < start) {
        return Failure(TargetError::InvertedRange);
    }

    const std::uint64_t count = static_cast<std::uint64_t>(end - start) + 1;
    if (count > kMaxDefaultTargets && !options.allowLargeRange) {
        return Failure(TargetError::RangeTooLarge);
    }

    std::vector<IpAddress> addresses;
    addresses.reserve(static_cast<std::size_t>(count));
    for (std::uint32_t value = start; value <= end; ++value) {
        addresses.emplace_back(value);
    }
    return addresses;
}

Result<std::vector<IpAddress>, TargetError> expandSingle(std::string_view spec,
                                                         const ExpansionOptions& options) {
    spec = trim(spec);
    if (spec.empty()) {
        return Failure(TargetError::Empty);
    }

    if (const std::size_t slash = spec.find('/'); slash != std::string_view::npos) {
        return expandCidr(spec, slash, options);
    }

    if (looksNumeric(spec)) {
        if (const std::size_t dash = spec.find('-'); dash != std::string_view::npos) {
            return expandHyphenRange(spec, dash, options);
        }
        if (const auto address = IpAddress::parse(spec)) {
            return std::vector<IpAddress>{*address};
        }
        return Failure(TargetError::MalformedAddress);
    }

    if (!options.resolveHostnames) {
        return Failure(TargetError::UnresolvedHostname);
    }
    if (const auto resolved = resolveHostname(std::string(spec))) {
        return std::vector<IpAddress>{*resolved};
    }
    return Failure(TargetError::UnresolvedHostname);
}

void sortUnique(std::vector<IpAddress>& addresses) {
    std::sort(addresses.begin(), addresses.end());
    addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
}

} // namespace

std::string_view describe(TargetError error) noexcept {
    switch (error) {
    case TargetError::Empty:
        return "empty target specification";
    case TargetError::MalformedAddress:
        return "malformed IPv4 address";
    case TargetError::MalformedCidr:
        return "malformed CIDR notation";
    case TargetError::PrefixOutOfRange:
        return "CIDR prefix must be between 0 and 32";
    case TargetError::MalformedRange:
        return "malformed address range";
    case TargetError::InvertedRange:
        return "address range start is greater than its end";
    case TargetError::RangeTooLarge:
        return "range is wider than /24; pass --allow-large-range to scan it anyway";
    case TargetError::UnresolvedHostname:
        return "cannot resolve hostname";
    }
    return "invalid target";
}

Result<std::vector<IpAddress>, TargetError> expandTarget(std::string_view spec,
                                                         const ExpansionOptions& options) {
    spec = trim(spec);
    if (spec.empty()) {
        return Failure(TargetError::Empty);
    }

    std::vector<IpAddress> addresses;

    std::size_t start = 0;
    while (start <= spec.size()) {
        const std::size_t comma = spec.find(',', start);
        const std::size_t stop = (comma == std::string_view::npos) ? spec.size() : comma;

        auto part = expandSingle(spec.substr(start, stop - start), options);
        if (!part) {
            return Failure(part.error());
        }
        const auto& values = part.value();
        addresses.insert(addresses.end(), values.begin(), values.end());

        if (comma == std::string_view::npos) {
            break;
        }
        start = comma + 1;
    }

    sortUnique(addresses);
    if (addresses.size() > kMaxDefaultTargets && !options.allowLargeRange) {
        return Failure(TargetError::RangeTooLarge);
    }
    return addresses;
}

Result<std::vector<IpAddress>, TargetError> expandTargets(const std::vector<std::string>& specs,
                                                          const ExpansionOptions& options) {
    std::vector<IpAddress> addresses;

    for (const auto& spec : specs) {
        auto part = expandTarget(spec, options);
        if (!part) {
            return Failure(part.error());
        }
        const auto& values = part.value();
        addresses.insert(addresses.end(), values.begin(), values.end());
    }

    sortUnique(addresses);
    if (addresses.size() > kMaxDefaultTargets && !options.allowLargeRange) {
        return Failure(TargetError::RangeTooLarge);
    }
    return addresses;
}

Result<std::vector<IpAddress>, TargetError> expandTargetFile(const std::string& path,
                                                             const ExpansionOptions& options) {
    std::ifstream file(path);
    if (!file) {
        return Failure(TargetError::Empty);
    }

    std::vector<std::string> specs;
    std::string line;
    while (std::getline(file, line)) {
        std::string_view view = line;
        if (const std::size_t hash = view.find('#'); hash != std::string_view::npos) {
            view = view.substr(0, hash);
        }
        view = trim(view);
        if (!view.empty()) {
            specs.emplace_back(view);
        }
    }

    if (specs.empty()) {
        return Failure(TargetError::Empty);
    }
    return expandTargets(specs, options);
}

} // namespace cabral::discovery
