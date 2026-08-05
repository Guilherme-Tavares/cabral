#include "ResultWriter.hpp"

#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace cabral::cli {
namespace {

std::string_view scanTypeName(ScanType type) noexcept {
    switch (type) {
    case ScanType::Connect:
        return "connect";
    case ScanType::Syn:
        return "syn";
    case ScanType::Udp:
        return "udp";
    case ScanType::PingSweep:
        return "ping-sweep";
    }
    return "unknown";
}

} // namespace

std::string escapeJson(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);

    for (const char c : text) {
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        default: {
            // Controles sem forma curta viram \uXXXX; o resto passa intacto, inclusive
            // UTF-8 multibyte, que é sequência válida em JSON.
            const auto byte = static_cast<unsigned char>(c);
            if (byte < 0x20) {
                char buffer[7];
                std::snprintf(buffer, sizeof(buffer), "\\u%04x", byte);
                out += buffer;
            } else {
                out += c;
            }
            break;
        }
        }
    }
    return out;
}

std::string toJson(std::span<const HostResult> hosts, const ScanSummary& summary,
                   const ScanConfig& config) {
    std::ostringstream out;

    out << "{\n";
    out << "  \"tool\": \"cabral\",\n";
    out << "  \"version\": \"0.1.0\",\n";
    out << "  \"scan\": {\n";
    out << "    \"type\": \"" << scanTypeName(config.scanType) << "\",\n";
    out << "    \"timing\": \"T" << static_cast<int>(config.timing) << "\",\n";
    out << "    \"timeout_ms\": " << config.effectiveTimeout().count() << "\n";
    out << "  },\n";

    out << "  \"summary\": {\n";
    out << "    \"hosts_scanned\": " << summary.hostsScanned << ",\n";
    out << "    \"hosts_up\": " << summary.hostsUp << ",\n";
    out << "    \"open_ports\": " << summary.openPorts << ",\n";
    out << "    \"elapsed_ms\": " << summary.elapsed.count() << "\n";
    out << "  },\n";

    out << "  \"hosts\": [";
    for (std::size_t h = 0; h < hosts.size(); ++h) {
        const auto& host = hosts[h];

        out << (h > 0 ? ",\n" : "\n");
        out << "    {\n";
        out << "      \"address\": \"" << escapeJson(host.address.toString()) << "\",\n";
        out << "      \"hostname\": \"" << escapeJson(host.hostname) << "\",\n";
        out << "      \"up\": " << (host.isUp ? "true" : "false") << ",\n";
        out << "      \"ports\": [";

        for (std::size_t p = 0; p < host.ports.size(); ++p) {
            const auto& port = host.ports[p];

            out << (p > 0 ? ",\n" : "\n");
            out << "        {\n";
            out << "          \"port\": " << port.port << ",\n";
            out << "          \"protocol\": \"" << toString(port.protocol) << "\",\n";
            out << "          \"state\": \"" << toString(port.state) << "\",\n";
            out << "          \"service\": \"" << escapeJson(port.service) << "\",\n";
            out << "          \"rtt_ms\": " << port.rtt.count() << "\n";
            out << "        }";
        }

        out << (host.ports.empty() ? "]\n" : "\n      ]\n");
        out << "    }";
    }
    out << (hosts.empty() ? "]\n" : "\n  ]\n");
    out << "}\n";

    return out.str();
}

std::string toText(std::span<const HostResult> hosts, const ScanSummary& summary) {
    std::ostringstream out;

    out << "cabral 0.1.0 scan report\n";
    for (const auto& host : hosts) {
        // Verbosidade 1: o arquivo guarda tudo o que foi observado, inclusive portas
        // filtradas e hosts inativos.
        out << formatHost(host, 1);
    }
    out << formatSummary(summary);

    return out.str();
}

bool writeToFile(const std::string& path, std::string_view contents, std::string& error) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        error = "cannot open '" + path + "' for writing";
        return false;
    }

    file.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    if (!file) {
        error = "failed while writing to '" + path + "'";
        return false;
    }
    return true;
}

} // namespace cabral::cli
