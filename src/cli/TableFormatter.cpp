#include "TableFormatter.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace cabral::cli {
namespace {

bool isInteresting(const PortResult& port) noexcept {
    return port.state == PortState::Open || port.state == PortState::OpenFiltered;
}

std::string portLabel(const PortResult& port) {
    return std::to_string(port.port) + "/" + std::string(toString(port.protocol));
}

void appendPadded(std::string& out, std::string_view text, std::size_t width) {
    out.append(text);
    if (text.size() < width) {
        out.append(width - text.size(), ' ');
    }
}

} // namespace

std::string formatHost(const HostResult& host, int verbosity) {
    std::ostringstream out;

    out << "\nScan report for " << host.address.toString();
    if (!host.hostname.empty()) {
        out << " (" << host.hostname << ")";
    }
    out << '\n';

    if (!host.isUp) {
        out << "Host seems to be down or unresponsive.\n";
        return out.str();
    }

    // -v mostra tudo o que não é fechado; sem -v, apenas o que está aberto.
    std::vector<const PortResult*> shown;
    std::size_t closedCount = 0;
    std::size_t filteredCount = 0;

    for (const auto& port : host.ports) {
        switch (port.state) {
        case PortState::Closed:
            ++closedCount;
            break;
        case PortState::Filtered:
            ++filteredCount;
            break;
        default:
            break;
        }

        const bool visible =
            isInteresting(port) || (verbosity > 0 && port.state != PortState::Closed);
        if (visible) {
            shown.push_back(&port);
        }
    }

    // Uma única linha de resumo: duas linhas "Not shown" separadas sugeririam que se trata
    // de contagens de coisas distintas, quando ambas são portas omitidas da tabela.
    std::vector<std::string> omitted;
    if (closedCount > 0) {
        omitted.push_back(std::to_string(closedCount) + " closed");
    }
    if (filteredCount > 0 && verbosity == 0) {
        omitted.push_back(std::to_string(filteredCount) + " filtered");
    }

    if (!omitted.empty()) {
        const std::size_t total = closedCount + (verbosity == 0 ? filteredCount : 0);
        out << "Not shown: ";
        for (std::size_t i = 0; i < omitted.size(); ++i) {
            out << (i > 0 ? ", " : "") << omitted[i];
        }
        out << " port" << (total == 1 ? "" : "s") << '\n';
    }

    if (shown.empty()) {
        out << "No open ports found.\n";
        return out.str();
    }

    std::size_t portWidth = std::string_view("PORT").size();
    std::size_t stateWidth = std::string_view("STATE").size();
    for (const auto* port : shown) {
        portWidth = std::max(portWidth, portLabel(*port).size());
        stateWidth = std::max(stateWidth, toString(port->state).size());
    }

    std::string header;
    appendPadded(header, "PORT", portWidth + 2);
    appendPadded(header, "STATE", stateWidth + 2);
    header.append("SERVICE");
    out << header << '\n';

    for (const auto* port : shown) {
        std::string row;
        appendPadded(row, portLabel(*port), portWidth + 2);
        appendPadded(row, toString(port->state), stateWidth + 2);
        row.append(port->service.empty() ? "unknown" : port->service);
        out << row << '\n';
    }

    return out.str();
}

std::string formatSummary(const ScanSummary& summary) {
    std::ostringstream out;

    const double seconds = static_cast<double>(summary.elapsed.count()) / 1000.0;

    out << '\n'
        << "Scanned " << summary.hostsScanned << " host" << (summary.hostsScanned == 1 ? "" : "s")
        << ", " << summary.hostsUp << " up, " << summary.openPorts << " open port"
        << (summary.openPorts == 1 ? "" : "s") << '\n'
        << "Completed in " << std::fixed << std::setprecision(2) << seconds << " seconds\n";

    return out.str();
}

} // namespace cabral::cli
