#include "NativeTensorCompression.hpp"
#include "TensorResidencyCache.hpp"
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

using RawrXD::TensorCompression::ChunkedF32Storage;

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "CHECK failed at line %d: %s\\n", __LINE__, #condition); \
    return __LINE__; \
} } while (0)

int main() {
    // Exactly representable F32 values must compact to a uniform 16-bit stream.
    std::vector<float> values(8192);
    for (std::size_t i=0;i<values.size();++i)
        values[i]=static_cast<float>(static_cast<int>(i%127)-63) * 0.25f;
    auto compact=ChunkedF32Storage::Build(values.data(),values.size(),0.0f,1024);
    CHECK(compact.storedBytes()==values.size()*2);
    RawrXD::TensorCompression::Encoding encoding{};
    std::vector<std::uint8_t> packed;
    CHECK(compact.ExportUniform16Bit(encoding,packed));
    CHECK(packed.size()==values.size()*2);
    std::vector<float> decoded(values.size());
    CHECK(compact.DecodeRange(137,decoded.size()-274,decoded.data()));
    for (std::size_t i=0;i<decoded.size()-274;++i)
        CHECK(decoded[i]==values[i+137]);

    // Lossless fallback must preserve values that are not representable in 16 bits.
    const float difficult[] = {1.0001234f, -3.1415927f, 1.0e-20f, 65520.0f};
    auto exact=ChunkedF32Storage::Build(difficult,4,0.0f,4);
    CHECK(exact.storedBytes()==sizeof(difficult));
    float exactOut[4]{};
    CHECK(exact.DecodeRange(0,4,exactOut));
    for (int i=0;i<4;++i) CHECK(exactOut[i]==difficult[i]);

    // Bounded cache: active leases prevent eviction; releasing permits trimming.
    Deep2::TensorResidencyCache cache(compact.storedBytes());
    const std::size_t residentBytes=compact.storedBytes();
    auto payload=std::make_shared<const ChunkedF32Storage>(std::move(compact));
    CHECK(cache.Insert("layer0.weight",payload));
    payload.reset();
    auto lease=cache.Acquire("layer0.weight");
    CHECK(lease);
    CHECK(cache.Trim(0)==0);
    CHECK(cache.GetStats().pinnedEntries==1);
    lease=Deep2::TensorResidencyCache::Lease{};
    CHECK(cache.Trim(0)==residentBytes);
    CHECK(cache.GetStats().residentBytes==0);
    return 0;
}
