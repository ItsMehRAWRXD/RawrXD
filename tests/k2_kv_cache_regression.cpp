// Standalone C++20 K2 KV cache regression executable; no third-party deps.
// cl /nologo /std:c++20 /EHsc /I src/deep2 tests/k2_kv_cache_regression.cpp
#include "K2KVCache.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
using rawrxd::deep2::K2KVCache;
template<class F> bool throws(F fn) { try { fn(); } catch (const std::exception&) { return true; } return false; }
int main() {
    // 15 assertions covering allocation, state, isolation and bounds.
    assert(throws([] { K2KVCache c(0, 8, 4); }));                            // 01
    assert(throws([] { K2KVCache c(2, 0, 4); }));                            // 02
    assert(throws([] { K2KVCache c(2, 8, 0); }));                            // 03
    assert(throws([] { K2KVCache c(2, 8, (std::numeric_limits<size_t>::max)()); })); // 04
    K2KVCache c(2, 17, 4);
    assert(c.numLayers() == 2);                                              // 05
    assert(c.maxSeqLen() == 17);                                             // 06
    assert(c.kvDim() == 4);                                                  // 07
    assert(c.currentLength() == 0);                                         // 08
    assert(c.liveBytes() <= 2 * 2 * 8 * 4 * sizeof(float));                 // 09
    std::vector<float> k{1,2,3,4}, v{5,6,7,8};
    c.Write(0, k.data(), v.data());
    assert(c.Key(0,0)[0] == 1 && c.Value(0,0)[3] == 8);                     // 10
    assert(throws([&] { c.Write(2, k.data(), v.data()); }));                // 11
    c.CommitPosition();
    assert(c.currentLength() == 1);                                         // 12
    for (size_t i=1;i<17;++i) { c.Write(0,k.data(),v.data()); c.CommitPosition(); }
    assert(c.currentLength() == 17 && !c.CanAppend());                       // 13
    assert(throws([&] { c.CommitPosition(); }));                            // 14
    c.Clear();
    assert(c.currentLength() == 0 && c.Key(0,0)[0] == 0);                  // 15
    assert(throws([&] { c.Write(0, nullptr, v.data()); }));
    assert(throws([&] { c.Write(0, k.data(), nullptr); }));
    assert(c.currentLength() == 0);
    assert(throws([&] { c.Reset(0, 4, 4); }));
    assert(c.numLayers() == 2);
    assert(throws([&] { c.Reset(2, 4, (std::numeric_limits<size_t>::max)()); }));
    assert(c.maxSeqLen() == 17);
    c.Reset(2, 1, 4);
    assert(c.maxSeqLen() == 1);
    assert(c.liveBytes() == 2 * 2 * 1 * 4 * sizeof(float));
    c.Write(1, k.data(), v.data());
    assert(c.Key(1,0)[2] == 3);
    assert(c.Key(0,0)[2] == 0);
    c.CommitPosition();
    assert(!c.CanAppend());
    assert(throws([&] { c.Write(0, k.data(), v.data()); }));
    // Rollback must preserve committed history and clear speculative writes.
    c.Reset(2, 17, 4);
    c.Write(0, k.data(), v.data());
    c.CommitPosition();
    c.Write(1, k.data(), v.data());
    c.RollbackPosition();
    assert(c.currentLength() == 1);
    assert(c.Key(0,0)[0] == 1);
    assert(c.Key(1,1)[0] == 0);
    assert(c.Value(1,1)[3] == 0);
    c.Write(1, k.data(), v.data());
    assert(c.Key(1,1)[0] == 1);
    c.RollbackPosition();
    assert(c.Key(1,1)[0] == 0);
    c.CommitPosition();
    assert(c.currentLength() == 2);
    c.Clear();
    assert(c.currentLength() == 0);
    c.RollbackPosition();
    assert(c.Key(0,0)[0] == 0);
    // Truncation preserves prefix, zeroes discarded positions, and permits replay.
    c.Reset(2, 17, 4);
    for (size_t i = 0; i < 10; ++i) {
        c.Write(0, k.data(), v.data());
        c.CommitPosition();
    }
    assert(c.currentLength() == 10);
    assert(throws([&] { c.Truncate(11); }));
    assert(c.currentLength() == 10);
    c.Truncate(5);
    assert(c.currentLength() == 5);
    assert(c.Key(0,4)[0] == 1);
    assert(c.Key(0,5)[0] == 0);
    assert(c.Value(0,9)[3] == 0);
    c.Write(0, k.data(), v.data());
    c.CommitPosition();
    assert(c.currentLength() == 6);
    assert(c.Key(0,5)[0] == 1);
    // Capacity growth must retain all committed layers across 8/16/32/64.
    c.Reset(3, 65, 4);
    for (size_t pos = 0; pos < 65; ++pos) {
        for (size_t layer = 0; layer < 3; ++layer) {
            float key[4] = {float(pos), float(layer), 3.f, 4.f};
            float val[4] = {5.f, float(pos), float(layer), 8.f};
            c.Write(layer, key, val);
        }
        c.CommitPosition();
    }
    assert(c.currentLength() == 65);
    assert(!c.CanAppend());
    for (size_t pos = 0; pos < 65; ++pos)
        for (size_t layer = 0; layer < 3; ++layer) {
            assert(c.Key(layer,pos)[0] == float(pos));
            assert(c.Key(layer,pos)[1] == float(layer));
            assert(c.Value(layer,pos)[1] == float(pos));
            assert(c.Value(layer,pos)[2] == float(layer));
        }
    assert(c.liveBytes() == 2 * 3 * 65 * 4 * sizeof(float));
    c.Truncate(8);
    assert(c.currentLength() == 8);
    assert(c.Key(2,7)[0] == 7.f);
    assert(c.Key(2,8)[0] == 0.f);
    const size_t reclaimed = c.evictColdPages();
    assert(reclaimed > 0);
    assert(c.Key(2,7)[0] == 7.f);
    // Truncate must clear a speculative write even when no tokens are dropped.
    c.Reset(2, 64, 4);
    c.Write(1, k.data(), v.data());
    c.Truncate(0);
    assert(c.currentLength() == 0);
    assert(c.Key(1,0)[0] == 0.f);
    c.Write(0, k.data(), v.data());
    c.CommitPosition();
    c.Write(1, k.data(), v.data());
    c.Truncate(1);
    assert(c.Key(0,0)[0] == 1.f);
    assert(c.Key(1,1)[0] == 0.f);
    // Repeated growth and contraction must retain all committed layers.
    for (size_t pos = 1; pos < 40; ++pos) {
        for (size_t layer = 0; layer < 2; ++layer) {
            float kk[4] = {float(pos), float(layer), 3.f, 4.f};
            c.Write(layer, kk, v.data());
        }
        c.CommitPosition();
    }
    c.Truncate(9);
    const size_t oldBytes = c.liveBytes();
    assert(c.evictColdPages() > 0);
    assert(c.liveBytes() < oldBytes);
    for (size_t pos = 1; pos < 9; ++pos)
        for (size_t layer = 0; layer < 2; ++layer)
            assert(c.Key(layer,pos)[0] == float(pos));
    assert(c.Key(1,9)[0] == 0.f);
    return 0;
}
