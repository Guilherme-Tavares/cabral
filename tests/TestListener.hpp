#pragma once

#include <cabral/model/PortRange.hpp>

namespace cabral::test {

/// Socket TCP escutando em 127.0.0.1 numa porta efêmera atribuída pelo sistema. Substitui
/// o `nc -l` do roadmap dentro dos testes automatizados, sem depender de processo externo
/// nem de porta fixa que poderia estar ocupada.
class TestListener {
public:
    TestListener();
    ~TestListener();

    TestListener(const TestListener&) = delete;
    TestListener& operator=(const TestListener&) = delete;

    bool isValid() const noexcept { return port_ != 0; }
    Port port() const noexcept { return port_; }

private:
    unsigned long long handle_ = 0;
    Port port_ = 0;
};

/// Porta que foi vinculada e liberada em seguida: a melhor aproximação disponível de uma
/// porta sem listener, sem chutar um número fixo.
Port reserveAndReleasePort();

} // namespace cabral::test
