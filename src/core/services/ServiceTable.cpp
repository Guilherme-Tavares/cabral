#include <cabral/services/ServiceTable.hpp>

#include <array>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <system_error>

namespace cabral::services {
namespace {

struct BuiltinEntry {
    Port port;
    Protocol protocol;
    std::string_view name;
};

/// Serviços de atribuição bem conhecida da IANA, escritos à mão. Cobre o suficiente para
/// a saída ser legível quando /etc/services não está disponível, como no Windows.
constexpr std::array kBuiltins{
    BuiltinEntry{20, Protocol::Tcp, "ftp-data"},
    BuiltinEntry{21, Protocol::Tcp, "ftp"},
    BuiltinEntry{22, Protocol::Tcp, "ssh"},
    BuiltinEntry{23, Protocol::Tcp, "telnet"},
    BuiltinEntry{25, Protocol::Tcp, "smtp"},
    BuiltinEntry{53, Protocol::Tcp, "domain"},
    BuiltinEntry{53, Protocol::Udp, "domain"},
    BuiltinEntry{67, Protocol::Udp, "bootps"},
    BuiltinEntry{68, Protocol::Udp, "bootpc"},
    BuiltinEntry{69, Protocol::Udp, "tftp"},
    BuiltinEntry{80, Protocol::Tcp, "http"},
    BuiltinEntry{110, Protocol::Tcp, "pop3"},
    BuiltinEntry{111, Protocol::Tcp, "sunrpc"},
    BuiltinEntry{123, Protocol::Udp, "ntp"},
    BuiltinEntry{135, Protocol::Tcp, "epmap"},
    BuiltinEntry{137, Protocol::Udp, "netbios-ns"},
    BuiltinEntry{138, Protocol::Udp, "netbios-dgm"},
    BuiltinEntry{139, Protocol::Tcp, "netbios-ssn"},
    BuiltinEntry{143, Protocol::Tcp, "imap"},
    BuiltinEntry{161, Protocol::Udp, "snmp"},
    BuiltinEntry{162, Protocol::Udp, "snmptrap"},
    BuiltinEntry{389, Protocol::Tcp, "ldap"},
    BuiltinEntry{443, Protocol::Tcp, "https"},
    BuiltinEntry{445, Protocol::Tcp, "microsoft-ds"},
    BuiltinEntry{465, Protocol::Tcp, "submissions"},
    BuiltinEntry{514, Protocol::Udp, "syslog"},
    BuiltinEntry{587, Protocol::Tcp, "submission"},
    BuiltinEntry{631, Protocol::Tcp, "ipp"},
    BuiltinEntry{636, Protocol::Tcp, "ldaps"},
    BuiltinEntry{993, Protocol::Tcp, "imaps"},
    BuiltinEntry{995, Protocol::Tcp, "pop3s"},
    BuiltinEntry{1433, Protocol::Tcp, "ms-sql-s"},
    BuiltinEntry{1521, Protocol::Tcp, "oracle"},
    BuiltinEntry{3306, Protocol::Tcp, "mysql"},
    BuiltinEntry{3389, Protocol::Tcp, "ms-wbt-server"},
    BuiltinEntry{5432, Protocol::Tcp, "postgresql"},
    BuiltinEntry{5900, Protocol::Tcp, "vnc"},
    BuiltinEntry{6379, Protocol::Tcp, "redis"},
    BuiltinEntry{8080, Protocol::Tcp, "http-alt"},
    BuiltinEntry{8443, Protocol::Tcp, "https-alt"},
    BuiltinEntry{27017, Protocol::Tcp, "mongodb"},
};

std::string_view trim(std::string_view text) {
    const auto isSpace = [](char c) { return c == ' ' || c == '\t' || c == '\r'; };
    while (!text.empty() && isSpace(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && isSpace(text.back())) {
        text.remove_suffix(1);
    }
    return text;
}

/// Localiza o arquivo de serviços do sistema. No Windows ele vive sob o diretório de
/// drivers e tem o mesmo formato do POSIX.
std::string systemServicesPath() {
#ifdef _WIN32
    const char* root = std::getenv("SystemRoot");
    const std::string base = (root != nullptr) ? root : "C:\\Windows";
    return base + "\\System32\\drivers\\etc\\services";
#else
    return "/etc/services";
#endif
}

} // namespace

void ServiceTable::insertBuiltins() {
    for (const auto& entry : kBuiltins) {
        entries_.try_emplace(Key{entry.port, entry.protocol}, entry.name);
    }
}

ServiceTable ServiceTable::builtinOnly() {
    ServiceTable table;
    table.insertBuiltins();
    return table;
}

ServiceTable ServiceTable::loadSystemDefault() {
    ServiceTable table;

    std::ifstream file(systemServicesPath());
    if (file) {
        std::ostringstream buffer;
        buffer << file.rdbuf();
        table.loadedFromSystem_ = table.parseFrom(buffer.str());
    }

    // Os embutidos entram depois: try_emplace preserva o que veio do sistema.
    table.insertBuiltins();
    return table;
}

bool ServiceTable::parseFrom(std::string_view contents) {
    std::size_t parsed = 0;
    std::size_t start = 0;

    while (start <= contents.size()) {
        const std::size_t newline = contents.find('\n', start);
        const std::size_t stop = (newline == std::string_view::npos) ? contents.size() : newline;

        std::string_view line = contents.substr(start, stop - start);
        if (const std::size_t comment = line.find('#'); comment != std::string_view::npos) {
            line = line.substr(0, comment);
        }
        line = trim(line);

        // Formato: nome porta/protocolo [apelidos...]
        if (!line.empty()) {
            const std::size_t nameEnd = line.find_first_of(" \t");
            if (nameEnd != std::string_view::npos) {
                const std::string_view name = line.substr(0, nameEnd);
                const std::string_view rest = trim(line.substr(nameEnd));
                const std::size_t slash = rest.find('/');

                if (slash != std::string_view::npos) {
                    const std::string_view portText = rest.substr(0, slash);
                    std::string_view protocolText = rest.substr(slash + 1);
                    if (const std::size_t end = protocolText.find_first_of(" \t");
                        end != std::string_view::npos) {
                        protocolText = protocolText.substr(0, end);
                    }

                    unsigned int port = 0;
                    const auto* begin = portText.data();
                    const auto* finish = portText.data() + portText.size();
                    const auto [ptr, ec] = std::from_chars(begin, finish, port);

                    if (ec == std::errc{} && ptr == finish && port > 0 && port <= 65535) {
                        if (protocolText == "tcp" || protocolText == "udp") {
                            const Protocol protocol =
                                (protocolText == "tcp") ? Protocol::Tcp : Protocol::Udp;
                            entries_.try_emplace(Key{static_cast<Port>(port), protocol},
                                                 std::string(name));
                            ++parsed;
                        }
                    }
                }
            }
        }

        if (newline == std::string_view::npos) {
            break;
        }
        start = newline + 1;
    }

    return parsed > 0;
}

std::string_view ServiceTable::lookup(Port port, Protocol protocol) const noexcept {
    const auto it = entries_.find(Key{port, protocol});
    return (it == entries_.end()) ? std::string_view{} : std::string_view(it->second);
}

} // namespace cabral::services
