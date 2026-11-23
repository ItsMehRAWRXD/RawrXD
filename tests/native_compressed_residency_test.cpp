#include "../include/native_compressed_residency.hpp"
#include <cassert>
#include <stdexcept>
using namespace RawrXD::Compression;
int main() {
    BlockResidencyCache cache(8);
    int calls = 0;
    auto decode = [&](BlockResidencyCache::Bytes& out) {
        ++calls; out.assign(4, 0xAB); return true;
    };
    auto pinned = cache.acquire({1, 0}, 4, decode);
    assert(pinned->size() == 4 && calls == 1);
    auto same = cache.acquire({1, 0}, 4, decode);
    assert(same == pinned && calls == 1);
    cache.acquire({1, 1}, 4, decode);
    cache.acquire({1, 2}, 4, decode);
    assert(cache.resident_bytes() == 8 && pinned->at(0) == 0xAB);
    cache.acquire({1, 0}, 4, decode);
    assert(calls == 4);
    bool rejected = false;
    try { cache.acquire({2, 0}, 9, decode); }
    catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    rejected = false;
    try { cache.acquire({2, 0}, 4, [](auto& b) { b.assign(3, 0); return true; }); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
    cache.clear();
    assert(cache.resident_bytes() == 0 && pinned->at(0) == 0xAB);
}
