#pragma once

#include <cabral/model/IpAddress.hpp>
#include <cabral/model/PortRange.hpp>

#include <cstdint>
#include <string_view>
#include <utility>

namespace cabral::net {

/// Descritor nativo apagado: int no POSIX, UINT_PTR no Windows. Manter o tipo largo aqui
/// evita expor <winsock2.h> a todo consumidor do header.
using NativeHandle = std::uintptr_t;

NativeHandle invalidHandle() noexcept;

enum class SocketError : std::uint8_t {
    None,
    Refused,     // ECONNREFUSED -> Closed
    TimedOut,    // sem resposta -> Filtered
    Unreachable, // rede/host inalcançável
    PermissionDenied,
    ResourceExhausted, // sem descritores ou portas efêmeras
    Other,
};

std::string_view describe(SocketError error) noexcept;

/// Inicialização obrigatória do Winsock; no-op no POSIX. Contada por referência para
/// suportar múltiplos escopos, e ancorada em um objeto para não depender de ordem de
/// destruição de estáticos.
class NetworkSubsystem {
public:
    NetworkSubsystem();
    ~NetworkSubsystem();

    NetworkSubsystem(const NetworkSubsystem&) = delete;
    NetworkSubsystem& operator=(const NetworkSubsystem&) = delete;
};

/// Dono exclusivo de um descritor. Fecha no destrutor; nenhum close() manual solto no
/// resto do código.
class Socket {
public:
    Socket() noexcept = default;
    explicit Socket(NativeHandle handle) noexcept : handle_(handle) {}

    ~Socket() { close(); }

    Socket(Socket&& other) noexcept : handle_(std::exchange(other.handle_, invalidHandle())) {}

    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = std::exchange(other.handle_, invalidHandle());
        }
        return *this;
    }

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    bool isValid() const noexcept { return handle_ != invalidHandle(); }
    NativeHandle handle() const noexcept { return handle_; }

    NativeHandle release() noexcept { return std::exchange(handle_, invalidHandle()); }
    void close() noexcept;

private:
    NativeHandle handle_ = invalidHandle();
};

/// Cria um socket TCP já em modo não bloqueante.
Socket createTcpSocket();

enum class ConnectProgress : std::uint8_t {
    Connected,  // conexão concluída de imediato (comum em loopback)
    InProgress, // aguardar prontidão de escrita
    Failed,
};

struct ConnectAttempt {
    ConnectProgress progress = ConnectProgress::Failed;
    SocketError error = SocketError::Other;
};

ConnectAttempt beginConnect(const Socket& socket, IpAddress address, Port port);

/// Lê o resultado de um connect() não bloqueante já sinalizado pelo poll, via SO_ERROR.
SocketError completeConnect(const Socket& socket);

} // namespace cabral::net
