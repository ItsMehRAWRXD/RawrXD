#include "../src/core/NativeCompressedResidency.hpp"
#include <cassert>
#include <cstdint>
#include <vector>
using namespace RawrXD::Compression;
static bool check(const uint8_t* p, size_t n, void* ctx) {
    auto* expected = static_cast<std::vector<uint8_t>*>(ctx);
    return n == expected->size() && std::equal(p, p + n, expected->begin());
}
int main() {
    NativeCompressedResidency cache(4);
    Record r;
    r.encoded = {1,2,3,4,5,6,7,8};
    r.decodedBytes = 8;
    r.decode = copyDecodedSlice;
    assert(cache.insert(42, std::move(r)) == Status::Ok);
    assert(cache.encodedResidentBytes() == 8);
    std::vector<uint8_t> expected = {3,4,5,6};
    assert(cache.consume({42,2,4},check,&expected) == Status::Ok);
    assert(cache.consume({42,0,5},check,&expected) == Status::BudgetExceeded);
    assert(cache.consume({42,7,2},check,&expected) == Status::Invalid);
    assert(cache.consume({43,0,1},check,&expected) == Status::Missing);
    assert(cache.erase(42) == Status::Ok);
    assert(cache.encodedResidentBytes() == 0);
}
