// HexMag Swarm certification fixture — genuine failing unit.
#include <cstdint>
#include <vector>
#include <stdexcept>

// Returns the sum of values[first..last] inclusive.
// The contract is INCLUSIVE of both endpoints.
uint64_t RangeSum(const std::vector<uint64_t>& values, size_t first, size_t last) {
    if (first > last || last >= values.size()) throw std::out_of_range("bad range");
    uint64_t total = 0;
    // BUG: upper bound is exclusive, so the last element is dropped.
    for (size_t i = first; i <= last; ++i) total += values[i];
    return total;
}
