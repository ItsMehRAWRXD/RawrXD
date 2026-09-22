#pragma once

// Minimal RawrXD::Expected<T,E> — avoids MSVC C++23 <expected> / std::free name clash
// Used by unified_memory_executor.h and amd_gpu_accelerator.cpp
#include <type_traits>
#include <utility>
#include <new>
#include <stdexcept>

namespace RawrXD {

// Unexpected<E> helper (mirrors C++23 std::unexpected)
template <typename E>
class Unexpected {
    E m_error;
public:
    Unexpected() = delete;
    explicit Unexpected(const E& e) : m_error(e) {}
    explicit Unexpected(E&& e) : m_error(std::move(e)) {}

    const E& error() const&  { return m_error; }
    E&       error() &        { return m_error; }
    E&&      error() &&       { return std::move(m_error); }
};

template <typename T, typename E>
class Expected {
    bool m_hasValue = false;
    alignas(alignof(T)) unsigned char m_valueStorage[sizeof(T)];
    alignas(alignof(E)) unsigned char m_errorStorage[sizeof(E)];

    T* valuePtr() { return reinterpret_cast<T*>(m_valueStorage); }
    const T* valuePtr() const { return reinterpret_cast<const T*>(m_valueStorage); }
    E* errorPtr() { return reinterpret_cast<E*>(m_errorStorage); }
    const E* errorPtr() const { return reinterpret_cast<const E*>(m_errorStorage); }

public:
    Expected() = default;
    Expected(const T& v) : m_hasValue(true) { new (m_valueStorage) T(v); }
    Expected(T&& v)      : m_hasValue(true) { new (m_valueStorage) T(std::move(v)); }
    Expected(const E& e) : m_hasValue(false) { new (m_errorStorage) E(e); }
    Expected(E&& e)      : m_hasValue(false) { new (m_errorStorage) E(std::move(e)); }
    Expected(const Unexpected<E>& u) : m_hasValue(false) { new (m_errorStorage) E(u.error()); }
    Expected(Unexpected<E>&& u)    : m_hasValue(false) { new (m_errorStorage) E(std::move(u.error())); }

    ~Expected() {
        if (m_hasValue) { valuePtr()->~T(); }
        else            { errorPtr()->~E(); }
    }

    Expected(const Expected& other) : m_hasValue(other.m_hasValue) {
        if (m_hasValue) new (m_valueStorage) T(*other.valuePtr());
        else            new (m_errorStorage) E(*other.errorPtr());
    }
    Expected(Expected&& other) noexcept(std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_constructible_v<E>)
        : m_hasValue(other.m_hasValue) {
        if (m_hasValue) new (m_valueStorage) T(std::move(*other.valuePtr()));
        else            new (m_errorStorage) E(std::move(*other.errorPtr()));
    }
    Expected& operator=(const Expected& other) {
        if (this == &other) return *this;
        this->~Expected();
        new (this) Expected(other);
        return *this;
    }
    Expected& operator=(Expected&& other) noexcept(std::is_nothrow_move_constructible_v<T> && std::is_nothrow_move_constructible_v<E>) {
        if (this == &other) return *this;
        this->~Expected();
        new (this) Expected(std::move(other));
        return *this;
    }

    bool has_value() const { return m_hasValue; }
    explicit operator bool() const { return m_hasValue; }

    T& value() {
        if (!m_hasValue) throw std::runtime_error("Expected holds error, not value");
        return *valuePtr();
    }
    const T& value() const {
        if (!m_hasValue) throw std::runtime_error("Expected holds error, not value");
        return *valuePtr();
    }
    E& error() {
        if (m_hasValue) throw std::runtime_error("Expected holds value, not error");
        return *errorPtr();
    }
    const E& error() const {
        if (m_hasValue) throw std::runtime_error("Expected holds value, not error");
        return *errorPtr();
    }
};

// Specialization for void value type
template <typename E>
class Expected<void, E> {
    bool m_hasValue = false;
    alignas(alignof(E)) unsigned char m_errorStorage[sizeof(E)];

    E* errorPtr() { return reinterpret_cast<E*>(m_errorStorage); }
    const E* errorPtr() const { return reinterpret_cast<const E*>(m_errorStorage); }

public:
    Expected() : m_hasValue(true) {}
    Expected(const E& e) : m_hasValue(false) { new (m_errorStorage) E(e); }
    Expected(E&& e)      : m_hasValue(false) { new (m_errorStorage) E(std::move(e)); }
    Expected(const Unexpected<E>& u) : m_hasValue(false) { new (m_errorStorage) E(u.error()); }
    Expected(Unexpected<E>&& u)    : m_hasValue(false) { new (m_errorStorage) E(std::move(u.error())); }

    ~Expected() {
        if (!m_hasValue) errorPtr()->~E();
    }

    Expected(const Expected& other) : m_hasValue(other.m_hasValue) {
        if (!m_hasValue) new (m_errorStorage) E(*other.errorPtr());
    }
    Expected(Expected&& other) noexcept(std::is_nothrow_move_constructible_v<E>)
        : m_hasValue(other.m_hasValue) {
        if (!m_hasValue) new (m_errorStorage) E(std::move(*other.errorPtr()));
    }
    Expected& operator=(const Expected& other) {
        if (this == &other) return *this;
        this->~Expected();
        new (this) Expected(other);
        return *this;
    }
    Expected& operator=(Expected&& other) noexcept(std::is_nothrow_move_constructible_v<E>) {
        if (this == &other) return *this;
        this->~Expected();
        new (this) Expected(std::move(other));
        return *this;
    }

    bool has_value() const { return m_hasValue; }
    explicit operator bool() const { return m_hasValue; }

    void value() const {
        if (!m_hasValue) throw std::runtime_error("Expected holds error, not value");
    }
    E& error() {
        if (m_hasValue) throw std::runtime_error("Expected holds value, not error");
        return *errorPtr();
    }
    const E& error() const {
        if (m_hasValue) throw std::runtime_error("Expected holds value, not error");
        return *errorPtr();
    }
};

// Factory function — returns Unexpected<E> which converts to Expected<T,E>
template <typename E>
Unexpected<std::decay_t<E>> unexpected(E&& error) {
    return Unexpected<std::decay_t<E>>(std::forward<E>(error));
}

} // namespace RawrXD
