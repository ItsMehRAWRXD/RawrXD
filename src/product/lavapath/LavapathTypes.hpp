// LavapathTypes.hpp — reverse-completion scratch (no plan array)
#pragma once
#include <cstdint>
#include <functional>

namespace rawr::lavapath {

enum class Result : uint8_t {
    Complete, Incomplete, Unavailable, Unknown, Failed
};
enum class ArcState : uint8_t {
    Complete, Available, Unavailable, Unknown
};
enum class Phase : uint8_t { Product, Stream, Teardown };

struct Scalar {
    uint64_t current{}, target{};
    bool known{true}, attainable{true};
    uint64_t delta() const noexcept {
        return target > current ? target - current : 0;
    }
    bool complete() const noexcept { return known && delta() == 0; }
};

template <size_t N>
struct Vector {
    Scalar v[N]{};
    bool complete() const noexcept {
        for (auto& x : v) if (!x.complete()) return false;
        return true;
    }
    bool unknown() const noexcept {
        for (auto& x : v) if (!x.known) return true;
        return false;
    }
    bool unavailable() const noexcept {
        for (auto& x : v)
            if (x.known && x.delta() && !x.attainable) return true;
        return false;
    }
};

struct Receipt {
    uint64_t generation{}, action{};
    Phase phase{};
    bool success{};
    uint64_t before{}, after{};
};

struct Action {
    uint64_t id{};
    Phase phase{};
    uint64_t dimension{}, amount{};
    std::function<bool()> execute;
};

struct Scratch {
    Vector<32> current{};
    uint64_t generation{};
    Receipt last{};
    Result result{Result::Unknown};
    ArcState arc{ArcState::Unknown};
    uint64_t excludeActionId{0}; // no-progress / failed-path ban
    bool permanentFail{false};
};

} // namespace rawr::lavapath
