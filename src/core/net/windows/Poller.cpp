#include <cabral/net/Poller.hpp>

// clang-format off
// FD_SETSIZE precisa estar definido antes de <winsock2.h>: o padrão de 64 sockets por
// select() estrangularia os lotes de sondagem, que chegam a centenas nos perfis rápidos.
// A barreira de formatação impede que uma reordenação de includes quebre isso em silêncio.
#define FD_SETSIZE 1024
#include <winsock2.h>
// clang-format on

#include <algorithm>

namespace cabral::net {
namespace {

// FD_SETSIZE limita quantos sockets cabem em um select(); acima disso a varredura é
// fatiada em várias chamadas.
constexpr std::size_t kChunkSize = FD_SETSIZE;

} // namespace

struct Poller::Impl {
    std::vector<SOCKET> handles;
};

Poller::Poller() : impl_(std::make_unique<Impl>()) {}
Poller::~Poller() = default;
Poller::Poller(Poller&&) noexcept = default;
Poller& Poller::operator=(Poller&&) noexcept = default;

bool Poller::add(NativeHandle handle) {
    if (handle == invalidHandle()) {
        return false;
    }
    impl_->handles.push_back(static_cast<SOCKET>(handle));
    return true;
}

void Poller::remove(NativeHandle handle) {
    auto& handles = impl_->handles;
    handles.erase(std::remove(handles.begin(), handles.end(), static_cast<SOCKET>(handle)),
                  handles.end());
}

/// Usa select() em vez de WSAPoll: a WSAPoll da Microsoft não sinaliza falha de conexão em
/// socket não bloqueante, defeito reconhecido e nunca corrigido. Com ela, toda porta
/// recusada expiraria por timeout e apareceria como Filtered em vez de Closed. O select()
/// reporta o mesmo evento no conjunto de exceção.
std::size_t Poller::wait(std::vector<PollEvent>& out, std::chrono::milliseconds timeout) {
    out.clear();
    if (impl_->handles.empty()) {
        return 0;
    }

    const auto clamped = std::max(timeout, std::chrono::milliseconds::zero());
    bool waited = false;

    for (std::size_t offset = 0; offset < impl_->handles.size(); offset += kChunkSize) {
        const std::size_t count = std::min(kChunkSize, impl_->handles.size() - offset);

        // select() consome o timeval in-place no Windows; reconstruí-lo a cada chamada
        // evita que as fatias seguintes façam uma espera de duração zero. Só a primeira
        // bloqueia: depois dela, as demais apenas colhem o que já está pronto.
        timeval tv{};
        if (!waited) {
            tv.tv_sec = static_cast<long>(clamped.count() / 1000);
            tv.tv_usec = static_cast<long>((clamped.count() % 1000) * 1000);
        }
        waited = true;

        fd_set writeSet;
        fd_set exceptSet;
        FD_ZERO(&writeSet);
        FD_ZERO(&exceptSet);

        for (std::size_t i = 0; i < count; ++i) {
            const SOCKET socket = impl_->handles[offset + i];
            FD_SET(socket, &writeSet);
            FD_SET(socket, &exceptSet);
        }

        // O primeiro argumento é ignorado no Winsock.
        const int ready = ::select(0, nullptr, &writeSet, &exceptSet, &tv);
        if (ready <= 0) {
            continue;
        }

        for (std::size_t i = 0; i < count; ++i) {
            const SOCKET socket = impl_->handles[offset + i];
            const bool writable = FD_ISSET(socket, &writeSet) != 0;
            const bool errored = FD_ISSET(socket, &exceptSet) != 0;
            if (!writable && !errored) {
                continue;
            }

            PollEvent event{};
            event.handle = static_cast<NativeHandle>(socket);
            event.writable = writable;
            event.errored = errored;
            out.push_back(event);
        }
    }

    return out.size();
}

} // namespace cabral::net
