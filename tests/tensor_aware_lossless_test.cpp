// Standalone C++17 validation: c++ -std=c++17 -O2 -I. tests/tensor_aware_lossless_test.cpp -lz -o tensor_test
#include "src/deep2/TensorAwareLossless.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>
using namespace rawrxd::weights;
static void verify(const std::vector<uint8_t>& source, uint8_t stride, uint32_t block) {
    const auto t = encode(source.data(), source.size(), stride, block);
    const auto all = decode_range(t, 0, source.size());
    assert(all == source);
    assert(decode_range(t, source.size(), 0).empty());
    for (size_t i = 0; i < source.size(); i += 13) {
        const size_t n = std::min<size_t>(57, source.size() - i);
        const auto part = decode_range(t, i, n);
        assert(std::equal(part.begin(), part.end(), source.begin() + i));
    }
    size_t stored = 0;
    for (size_t i = 0; i < t.blocks.size(); ++i) {
        stored += t.blocks[i].payload.size();
        assert(decode_block(t, i).size() == t.blocks[i].plain_size);
        assert(t.blocks[i].payload.size() <= t.blocks[i].plain_size);
    }
    std::cout << "input=" << source.size() << " stored_payload=" << stored
              << " ratio=" << (source.empty() ? 1.0 : double(stored)/source.size())
              << " stride=" << int(stride) << " block=" << block << "\n";
    if (!t.blocks.empty()) {
        auto corrupt = t;
        corrupt.blocks[0].crc32_plain ^= 1;
        bool rejected = false;
        try { (void)decode_block(corrupt, 0); }
        catch (const std::runtime_error&) { rejected = true; }
        assert(rejected);
    }
}
int main() {
    std::mt19937 rng(0x5244584e);
    std::vector<uint8_t> random(65537), repeating(65537, 0x7f), fp(65537);
    for (auto& b : random) b = static_cast<uint8_t>(rng());
    for (size_t i = 0; i < fp.size(); ++i) fp[i] = (i % 4 == 0) ? 0x3f : static_cast<uint8_t>(rng());
    for (uint8_t stride : {1, 2, 4, 8}) {
        for (uint32_t block : {31u, 4096u, 65536u}) {
            verify(random, stride, block);
            verify(repeating, stride, block);
            verify(fp, stride, block);
        }
    }
    verify({}, 4, 4096);
    bool rejected = false;
    try { (void)encode(nullptr, 1); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    std::cout << "PASS tensor-aware lossless roundtrip/ranges/corruption\n";
}
