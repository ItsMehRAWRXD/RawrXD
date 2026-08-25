#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD::Deep2 {

struct DeterministicState {
    uint64_t hash = 1469598103934665603ull;
    size_t count = 0;
};

inline void DeterministicReset(
    DeterministicState& s)
{
    s.hash = 1469598103934665603ull;
    s.count = 0;
}

inline void DeterministicAdd(
    DeterministicState& s,
    const void* data,
    size_t bytes)
{
    const auto* p =
        static_cast<const uint8_t*>(data);

    for (size_t i = 0; i < bytes; ++i) {
        s.hash ^= p[i];
        s.hash *= 1099511628211ull;
    }

    s.count += bytes;
}

inline void DeterministicAddFloat(
    DeterministicState& s,
    const float* values,
    size_t count)
{
    DeterministicAdd(
        s,
        values,
        count * sizeof(float));
}

inline bool DeterministicEqual(
    const DeterministicState& a,
    const DeterministicState& b)
{
    return a.hash == b.hash &&
           a.count == b.count;
}

}
