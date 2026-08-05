#include "ArgParser.hpp"

#include <cabral/model/PortRange.hpp>

#include <charconv>
#include <string>
#include <system_error>

namespace cabral::cli {
namespace {

ParseError error(std::string message) {
    return ParseError{std::move(message)};
}

std::string quoted(std::string_view text) {
    return "'" + std::string(text) + "'";
}

/// Consome o valor que acompanha uma flag, recusando quando ele falta. Sem isso,
/// "cabral -p" engoliria o alvo seguinte como se fosse a lista de portas.
Result<std::string_view, ParseError> takeValue(std::span<const std::string_view> args,
                                               std::size_t& index, std::string_view flag) {
    if (index + 1 >= args.size()) {
        return Failure(error("option " + quoted(flag) + " requires a value"));
    }
    return args[++index];
}

Result<int, ParseError> parseInt(std::string_view text, std::string_view flag) {
    int value = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, value);
    if (ec != std::errc{} || ptr != end) {
        return Failure(
            error("option " + quoted(flag) + " expects an integer, got " + quoted(text)));
    }
    return value;
}

bool applyScanType(std::string_view arg, ScanConfig& config) {
    if (arg == "-sT") {
        config.scanType = ScanType::Connect;
    } else if (arg == "-sS") {
        config.scanType = ScanType::Syn;
    } else if (arg == "-sU") {
        config.scanType = ScanType::Udp;
    } else if (arg == "-sn") {
        config.scanType = ScanType::PingSweep;
    } else {
        return false;
    }
    return true;
}

} // namespace

Result<ParsedArguments, ParseError> parseArguments(std::span<const std::string_view> args) {
    ParsedArguments parsed;
    bool portsGiven = false;

    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string_view arg = args[i];

        if (arg == "-h" || arg == "--help") {
            parsed.action = Action::ShowHelp;
            return parsed;
        }
        if (arg == "--version") {
            parsed.action = Action::ShowVersion;
            return parsed;
        }

        if (applyScanType(arg, parsed.config)) {
            continue;
        }

        if (arg == "-Pn") {
            parsed.config.skipHostDiscovery = true;
        } else if (arg == "--allow-large-range") {
            parsed.config.allowLargeRange = true;
        } else if (arg == "-v") {
            parsed.config.verbosity = 1;
        } else if (arg == "-vv") {
            parsed.config.verbosity = 2;
        } else if (arg == "-p") {
            auto value = takeValue(args, i, arg);
            if (!value) {
                return Failure(std::move(value).error());
            }
            auto ports = parsePortSpec(value.value());
            if (!ports) {
                return Failure(
                    error(std::string(describe(ports.error())) + ": " + quoted(value.value())));
            }
            parsed.config.ports = std::move(ports).value();
            portsGiven = true;
        } else if (arg == "--timeout") {
            auto value = takeValue(args, i, arg);
            if (!value) {
                return Failure(std::move(value).error());
            }
            auto ms = parseInt(value.value(), arg);
            if (!ms) {
                return Failure(std::move(ms).error());
            }
            if (ms.value() <= 0) {
                return Failure(error("--timeout expects a positive number of milliseconds"));
            }
            parsed.config.timeoutOverride = std::chrono::milliseconds(ms.value());
        } else if (arg == "-iL") {
            auto value = takeValue(args, i, arg);
            if (!value) {
                return Failure(std::move(value).error());
            }
            parsed.targetListFile = std::string(value.value());
        } else if (arg == "-oN" || arg == "-oJ") {
            auto value = takeValue(args, i, arg);
            if (!value) {
                return Failure(std::move(value).error());
            }
            parsed.config.outputPath = std::string(value.value());
            parsed.config.outputFormat = (arg == "-oJ") ? OutputFormat::Json : OutputFormat::Text;
        } else if (arg.size() == 3 && arg.starts_with("-T")) {
            const char digit = arg[2];
            if (digit < '0' || digit > '5') {
                return Failure(error("timing profile must be between -T0 and -T5"));
            }
            parsed.config.timing = static_cast<TimingProfile>(digit - '0');
        } else if (!arg.empty() && arg.front() == '-' && arg != "-") {
            return Failure(error("unknown option " + quoted(arg)));
        } else {
            parsed.targets.emplace_back(arg);
        }
    }

    if (parsed.targets.empty() && parsed.targetListFile.empty()) {
        return Failure(error("no target specified; see --help"));
    }
    // Sem -p, varrer as portas privilegiadas é o padrão sensato: cobre os serviços usuais
    // sem transformar a chamada sem argumentos em uma varredura completa.
    if (!portsGiven && parsed.config.scanType != ScanType::PingSweep) {
        auto defaults = parsePortSpec("1-1024");
        if (defaults) {
            parsed.config.ports = std::move(defaults).value();
        }
    }

    return parsed;
}

std::string usageText() {
    return R"(cabral - TCP/UDP port scanner

Usage:
  cabral [options] <target>

Scan types:
  -sT              connect scan (default, no privileges required)
  -sS              SYN scan (requires CAP_NET_RAW, Linux only)
  -sU              UDP scan (needs CAP_NET_RAW to tell closed from filtered)
  -sn              host discovery only

Host discovery:
  -Pn              skip discovery, treat every target as up

Ports:
  -p <spec>        22 | 1-1024 | 22,80,443 | - (all)

Timing:
  -T<0-5>          timing profile (default -T3)
  --timeout <ms>   per-probe timeout, overrides the profile

Input and output:
  -iL <file>       read targets from file
  -oN <file>       write results as text
  -oJ <file>       write results as JSON
  -v, -vv          increase verbosity

Other:
  --allow-large-range   permit ranges wider than /24
  -h, --help            show this help
  --version             show version

Use only against hosts you own or are authorized to scan.
)";
}

std::string versionText() {
    return "cabral 0.1.0\n";
}

} // namespace cabral::cli
