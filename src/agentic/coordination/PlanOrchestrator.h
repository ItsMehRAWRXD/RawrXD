#pragma once
#include <string>
#include <vector>
#include <unordered_map>

#if __cplusplus >= 202302L || (defined(_MSVC_LANG) && _MSVC_LANG >= 202302L)
#include <expected>
#else
#include <variant>
namespace std {
    template<typename T, typename E>
    class expected {
        std::variant<T, E> m_val;
        bool m_has_value;
    public:
        expected(const T& val) : m_val(val), m_has_value(true) {}
        expected(const E& err) : m_val(err), m_has_value(false) {}
        bool has_value() const { return m_has_value; }
        explicit operator bool() const { return m_has_value; }
        T& value() { return std::get<T>(m_val); }
        const T& value() const { return std::get<T>(m_val); }
        E& error() { return std::get<E>(m_val); }
        const E& error() const { return std::get<E>(m_val); }
        T& operator*() { return value(); }
        const T& operator*() const { return value(); }
    };

    template<typename E>
    class expected<void, E> {
        E m_err;
        bool m_has_value;
    public:
        expected() : m_has_value(true) {}
        expected(const E& err) : m_err(err), m_has_value(false) {}
        bool has_value() const { return m_has_value; }
        explicit operator bool() const { return m_has_value; }
        E& error() { return m_err; }
        const E& error() const { return m_err; }
    };
}
#endif

namespace RawrXD {

class PlanOrchestrator {
public:
    PlanOrchestrator() = default;
    ~PlanOrchestrator() = default;

    // Add necessary methods here if SwarmOrchestrator uses them later
};

}
