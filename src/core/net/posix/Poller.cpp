#include <cabral/net/Poller.hpp>

#include <cerrno>

#include <sys/epoll.h>
#include <unistd.h>

namespace cabral::net {

struct Poller::Impl {
    int epollFd = -1;
    std::size_t registered = 0;
    std::vector<epoll_event> scratch;

    ~Impl() {
        if (epollFd >= 0) {
            ::close(epollFd);
        }
    }
};

Poller::Poller() : impl_(std::make_unique<Impl>()) {
    impl_->epollFd = ::epoll_create1(EPOLL_CLOEXEC);
}

Poller::~Poller() = default;
Poller::Poller(Poller&&) noexcept = default;
Poller& Poller::operator=(Poller&&) noexcept = default;

bool Poller::add(NativeHandle handle) {
    if (impl_->epollFd < 0 || handle == invalidHandle()) {
        return false;
    }

    const int fd = static_cast<int>(handle);
    epoll_event event{};
    // EPOLLOUT: connect() não bloqueante conclui sinalizando escrita, com ou sem sucesso.
    event.events = EPOLLOUT;
    event.data.fd = fd;

    if (::epoll_ctl(impl_->epollFd, EPOLL_CTL_ADD, fd, &event) != 0) {
        return false;
    }
    ++impl_->registered;
    if (impl_->scratch.size() < impl_->registered) {
        impl_->scratch.resize(impl_->registered);
    }
    return true;
}

void Poller::remove(NativeHandle handle) {
    if (impl_->epollFd < 0 || handle == invalidHandle()) {
        return;
    }
    // Um fd já fechado sai do epoll sozinho; ENOENT aqui não é erro.
    if (::epoll_ctl(impl_->epollFd, EPOLL_CTL_DEL, static_cast<int>(handle), nullptr) == 0) {
        if (impl_->registered > 0) {
            --impl_->registered;
        }
    }
}

std::size_t Poller::wait(std::vector<PollEvent>& out, std::chrono::milliseconds timeout) {
    out.clear();
    if (impl_->epollFd < 0 || impl_->registered == 0) {
        return 0;
    }

    if (impl_->scratch.size() < impl_->registered) {
        impl_->scratch.resize(impl_->registered);
    }

    int ready = 0;
    do {
        ready = ::epoll_wait(impl_->epollFd, impl_->scratch.data(),
                             static_cast<int>(impl_->scratch.size()),
                             static_cast<int>(timeout.count()));
    } while (ready < 0 && errno == EINTR);

    if (ready <= 0) {
        return 0;
    }

    out.reserve(static_cast<std::size_t>(ready));
    for (int i = 0; i < ready; ++i) {
        const auto& raw = impl_->scratch[static_cast<std::size_t>(i)];
        PollEvent event{};
        event.handle = static_cast<NativeHandle>(raw.data.fd);
        event.writable = (raw.events & EPOLLOUT) != 0;
        event.errored = (raw.events & (EPOLLERR | EPOLLHUP)) != 0;
        out.push_back(event);
    }
    return out.size();
}

} // namespace cabral::net
