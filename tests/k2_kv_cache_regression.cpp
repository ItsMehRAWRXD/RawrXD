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
    return 0;
}
