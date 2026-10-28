// SafeWriteState.hpp — shared rollback stack for SafeWriteAtomic TUs
#pragma once
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD {
namespace SafeWrite {
namespace detail {

struct Slot {
    uint64_t id = 0;
    std::string path;
    std::string prior;
    bool hadFile = false;
};

inline std::mutex& Mu() {
    static std::mutex m;
    return m;
}
inline std::vector<Slot>& Stack() {
    static std::vector<Slot> s;
    return s;
}
inline uint64_t& NextId() {
    static uint64_t n = 1;
    return n;
}
inline uint64_t& Writes() {
    static uint64_t n = 0;
    return n;
}
inline uint64_t& Rollbacks() {
    static uint64_t n = 0;
    return n;
}

constexpr size_t kMaxWrite = 50ULL * 1024 * 1024;
constexpr size_t kMaxRollback = 64;

}  // namespace detail
}  // namespace SafeWrite
}  // namespace RawrXD
