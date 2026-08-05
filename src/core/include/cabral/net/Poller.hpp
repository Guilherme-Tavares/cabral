#pragma once

#include <cabral/net/Socket.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <vector>

namespace cabral::net {

struct PollEvent {
    NativeHandle handle = invalidHandle();
    bool writable = false;
    bool errored = false;
};

/// Espera por prontidão de escrita em vários sockets de uma vez. Um connect() não
/// bloqueante conclui sinalizando escrita, tanto no sucesso quanto na recusa; o motivo
/// vem depois de completeConnect().
///
/// epoll no Linux, WSAPoll no Windows: a escolha é do CMake, não de #ifdef.
class Poller {
public:
    Poller();
    ~Poller();

    Poller(Poller&&) noexcept;
    Poller& operator=(Poller&&) noexcept;

    Poller(const Poller&) = delete;
    Poller& operator=(const Poller&) = delete;

    bool add(NativeHandle handle);
    void remove(NativeHandle handle);

    /// Bloqueia até haver eventos ou esgotar o timeout. Devolve o número de eventos
    /// escritos em out.
    std::size_t wait(std::vector<PollEvent>& out, std::chrono::milliseconds timeout);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cabral::net
