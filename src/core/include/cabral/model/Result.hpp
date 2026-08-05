#pragma once

#include <cstddef>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>

namespace cabral {

/// Erro esperado, carregado por valor de retorno.
///
/// Substitui std::expected, que exige C++23. A forma imita a do padrão para que a
/// migração seja mecânica caso o projeto suba de versão: value(), error(), operator bool.
template<typename E>
class Failure {
public:
    explicit Failure(E error) : error_(std::move(error)) {}

    const E& get() const& noexcept { return error_; }
    E& get() & noexcept { return error_; }
    E&& get() && noexcept { return std::move(error_); }

private:
    E error_;
};

template<typename E>
Failure(E) -> Failure<E>;

template<typename T, typename E>
class Result {
    static_assert(!std::is_same_v<std::remove_cv_t<T>, std::remove_cv_t<E>>,
                  "Result<T, E> requires distinct value and error types");

public:
    using value_type = T;
    using error_type = E;

    Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(Failure<E> failure) : storage_(std::in_place_index<1>, std::move(failure).get()) {}

    static Result ok(T value) { return Result(std::move(value)); }
    static Result err(E error) { return Result(Failure<E>(std::move(error))); }

    bool hasValue() const noexcept { return storage_.index() == 0; }
    explicit operator bool() const noexcept { return hasValue(); }

    const T& value() const& {
        requireValue();
        return std::get<0>(storage_);
    }

    T&& value() && {
        requireValue();
        return std::get<0>(std::move(storage_));
    }

    const E& error() const& {
        requireError();
        return std::get<1>(storage_);
    }

    E&& error() && {
        requireError();
        return std::get<1>(std::move(storage_));
    }

    template<typename U>
    T valueOr(U&& fallback) const& {
        return hasValue() ? std::get<0>(storage_) : static_cast<T>(std::forward<U>(fallback));
    }

private:
    void requireValue() const {
        if (!hasValue()) {
            throw std::logic_error("Result::value() called on an error result");
        }
    }

    void requireError() const {
        if (hasValue()) {
            throw std::logic_error("Result::error() called on a value result");
        }
    }

    std::variant<T, E> storage_;
};

} // namespace cabral
