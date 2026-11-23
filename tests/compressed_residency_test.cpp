#include "../src/core/CompressedResidencyCache.hpp"
#include <cassert>
#include <stdexcept>
using Cache = RawrXD::CompressedResidencyCache;
int main() {
    Cache cache(8);
    int decodes = 0;
    auto decoder = [&decodes](const Cache::Bytes& in, std::size_t expected) {
        ++decodes;
        Cache::Bytes out(expected);
        for (std::size_t i = 0; i < expected; ++i) out[i] = in[i % in.size()];
        return out;
    };
    cache.insert({1, 0}, {7}, 4, decoder);
    cache.insert({1, 1}, {9}, 4, decoder);
    cache.insert({1, 2}, {11}, 4, decoder);
    assert(cache.compressedStoredBytes() == 3);
    {
        auto a = cache.acquire({1, 0});
        auto b = cache.acquire({1, 1});
        assert(a->size() == 4 && (*a)[0] == 7);
        assert(b->size() == 4 && (*b)[0] == 9);
        assert(cache.decodedResidentBytes() == 8);
        bool refused = false;
        try { (void)cache.acquire({1, 2}); }
        catch (const std::runtime_error&) { refused = true; }
        assert(refused && cache.decodedResidentBytes() == 8);
        assert(decodes == 3);
    }
    auto c = cache.acquire({1, 2});
    assert((*c)[0] == 11 && cache.decodedResidentBytes() == 8);
    bool rejected = false;
    try { cache.insert({1, 2}, {12}, 4, decoder); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
    c.reset();
    Cache invalid(4);
    invalid.insert({0, 0}, {1}, 4, [](const Cache::Bytes&, std::size_t) {
        return Cache::Bytes(3);
    });
    rejected = false;
    try { (void)invalid.acquire({0, 0}); }
    catch (const std::runtime_error&) { rejected = true; }
    assert(rejected && invalid.decodedResidentBytes() == 0);
    return 0;
}
