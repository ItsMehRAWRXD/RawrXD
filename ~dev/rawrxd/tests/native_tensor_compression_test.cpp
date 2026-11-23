#include "NativeTensorCompression.hpp"
#include "TensorResidencyCache.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <memory>
#include <vector>

using RawrXD::TensorCompression::ChunkedF32Storage;

int main() {
    // Exactly representable F32 values must compact to a uniform 16-bit stream.
    std::vector<float> values(8192);
    for (std::size_t i=0;i<values.size();++i)
        values[i]=static_cast<float>(static_cast<int>(i%127)-63) * 0.25f;
    auto compact=ChunkedF32Storage::Build(values.data(),values.size(),0.0f,1024);
    assert(compact.storedBytes()==values.size()*2);
    RawrXD::TensorCompression::Encoding encoding{};
    std::vector<std::uint8_t> packed;
    assert(compact.ExportUniform16Bit(encoding,packed));
    assert(packed.size()==values.size()*2);
    std::vector<float> decoded(values.size());
    assert(compact.DecodeRange(137,decoded.size()-274,decoded.data()));
    for (std::size_t i=0;i<decoded.size()-274;++i)
        assert(decoded[i]==values[i+137]);

    // Lossless fallback must preserve values that are not representable in 16 bits.
    const float difficult[] = {1.0001234f, -3.1415927f, 1.0e-20f, 65520.0f};
    auto exact=ChunkedF32Storage::Build(difficult,4,0.0f,4);
    assert(exact.storedBytes()==sizeof(difficult));
    float exactOut[4]{};
    assert(exact.DecodeRange(0,4,exactOut));
    for (int i=0;i<4;++i) assert(exactOut[i]==difficult[i]);

    // Bounded cache: active leases prevent eviction; releasing permits trimming.
    Deep2::TensorResidencyCache cache(compact.storedBytes());
    auto payload=std::make_shared<const ChunkedF32Storage>(std::move(compact));
    assert(cache.Insert("layer0.weight",payload));
    auto lease=cache.Acquire("layer0.weight");
    assert(lease);
    assert(cache.Trim(0)==0);
    assert(cache.GetStats().pinnedEntries==1);
    lease=Deep2::TensorResidencyCache::Lease{};
    assert(cache.Trim(0)==payload->storedBytes());
    assert(cache.GetStats().residentBytes==0);
    return 0;
}
