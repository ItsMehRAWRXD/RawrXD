#pragma once
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::swarm48 {
using AgentId = std::uint32_t;
using TeamId = std::uint16_t;
using DeviceId = std::uint16_t;
using SessionId = std::uint64_t;
using ModelHandle = std::uint64_t;
using KvHandle = std::uint64_t;

inline std::uint64_t now_us() {
    using namespace std::chrono;
    return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

inline std::uint64_t fnv1a64(std::string_view s) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ull; }
    return h;
}
} // namespace rawrxd::swarm48
