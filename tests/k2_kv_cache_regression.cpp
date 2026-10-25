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
    return 0;
}
