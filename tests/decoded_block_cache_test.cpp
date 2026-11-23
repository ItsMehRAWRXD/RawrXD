// c++ -std=c++17 -O2 -I. tests/decoded_block_cache_test.cpp -lz -o cache_test
#include "src/deep2/DecodedBlockCache.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>
using namespace rawrxd::weights;
int main() {
    std::mt19937 rng(42);
    std::vector<uint8_t> source(8192 + 13);
    for (auto& b : source) b = static_cast<uint8_t>(rng());
    const Tensor tensor = encode(source.data(), source.size(), 4, 1024);
    DecodedBlockCache cache(tensor, 2048);
    const auto first = cache.read(100, 1500);
    assert(std::equal(first.begin(), first.end(), source.begin() + 100));
    assert(cache.resident_bytes() <= 2048);
    const size_t previous_hits = cache.hits();
    const auto second = cache.read(1100, 200);
    assert(std::equal(second.begin(), second.end(), source.begin() + 1100));
    assert(cache.hits() > previous_hits);
    const auto third = cache.read(4090, 3000);
    assert(std::equal(third.begin(), third.end(), source.begin() + 4090));
    assert(cache.resident_bytes() <= 2048);
    assert(cache.read(source.size(), 0).empty());
    bool rejected = false;
    try { (void)cache.read(source.size(), 1); }
    catch (const std::out_of_range&) { rejected = true; }
    assert(rejected);
    DecodedBlockCache too_small(tensor, 100);
    rejected = false;
    try { (void)too_small.read(0, 1); }
    catch (const std::length_error&) { rejected = true; }
    assert(rejected);
    cache.clear();
    assert(cache.resident_bytes() == 0);
    std::cout << "PASS cache range/hit/eviction/budget/corruption boundaries\n";
}
