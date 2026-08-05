#pragma once

#include <cabral/model/PortRange.hpp>
#include <cabral/model/PortState.hpp>

#include <string>
#include <string_view>
#include <unordered_map>

namespace cabral::services {

/// Mapeia porta e protocolo para nome de serviço.
///
/// A fonte é /etc/services (ou o equivalente do Windows). O projeto não usa nmap-services:
/// é dado licenciado sob NPSL. Quando o arquivo do sistema não existe ou não cobre a
/// porta, vale uma tabela embutida reduzida com os serviços mais comuns.
class ServiceTable {
public:
    /// Carrega o arquivo do sistema; sempre utilizável, pois o fallback é embutido.
    static ServiceTable loadSystemDefault();

    /// Sem consultar o sistema de arquivos: útil para testes determinísticos.
    static ServiceTable builtinOnly();

    bool parseFrom(std::string_view contents);

    /// Nome do serviço, ou vazio se desconhecido.
    std::string_view lookup(Port port, Protocol protocol) const noexcept;

    std::size_t size() const noexcept { return entries_.size(); }
    bool loadedFromSystem() const noexcept { return loadedFromSystem_; }

private:
    struct Key {
        Port port;
        Protocol protocol;

        bool operator==(const Key&) const noexcept = default;
    };

    struct KeyHash {
        std::size_t operator()(const Key& key) const noexcept {
            return (static_cast<std::size_t>(key.port) << 1) |
                   static_cast<std::size_t>(key.protocol);
        }
    };

    void insertBuiltins();

    std::unordered_map<Key, std::string, KeyHash> entries_;
    bool loadedFromSystem_ = false;
};

} // namespace cabral::services
