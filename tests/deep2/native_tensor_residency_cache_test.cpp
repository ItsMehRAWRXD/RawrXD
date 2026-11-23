#include "../../src/deep2/NativeTensorResidencyCache.hpp"
#include <cassert>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

int main() {
    std::vector<float> source(10003);
    for(size_t i=0;i<source.size();++i)
        source[i]=float(int(i%31)-15); // exactly representable in IEEE F16
    Deep2::TensorResidencyCache cache(24000);
    size_t sourceReads=0;
    auto reader=[&](size_t offset,size_t count,float* out) {
        ++sourceReads;
        if(offset>source.size() || count>source.size()-offset) return false;
        std::copy(source.begin()+offset,source.begin()+offset+count,out);
        return true;
    };
    assert(cache.RegisterF32FromReader("layer.0.weight",source.size(),0.0f,reader,1024));
    assert(sourceReads==10); // source was consumed in bounded chunks, not one tensor read
    assert(cache.Contains("layer.0.weight"));
    auto before=cache.GetStats();
    assert(before.tensorCount==1);
    assert(before.logicalBytes==source.size()*sizeof(float));
    assert(before.compressedBytes<=before.logicalBytes/2);
    assert(before.compressedBytes<=before.budgetBytes);

    // Device-facing export: complete F16 chunks are exposed in their compact
    // representation without materializing an intermediate F32 tile.
    RawrXD::TensorCompression::Encoding compactEncoding =
        RawrXD::TensorCompression::Encoding::Raw;
    std::vector<uint8_t> compactTile;
    assert(cache.ExportUniform16BitRange("layer.0.weight", 0, 2048,
                                         compactEncoding, compactTile));
    assert(compactEncoding == RawrXD::TensorCompression::Encoding::F16);
    assert(compactTile.size() == 2048 * sizeof(uint16_t));
    for (size_t i = 0; i < 2048; ++i) {
        const uint16_t h = static_cast<uint16_t>(compactTile[2*i]) |
                           (static_cast<uint16_t>(compactTile[2*i+1]) << 8);
        assert(RawrXD::TensorCompression::FromHalf(h) == source[i]);
    }
    // Arbitrary ranges, including partial first/last chunks and ranges that
    // cross chunk boundaries, remain in compact F16 form without F32 decode.
    assert(cache.ExportUniform16BitRange("layer.0.weight", 1, 1024,
                                         compactEncoding, compactTile));
    assert(compactEncoding == RawrXD::TensorCompression::Encoding::F16);
    assert(compactTile.size() == 1024 * sizeof(uint16_t));
    for (size_t i = 0; i < 1024; ++i) {
        const uint16_t h = static_cast<uint16_t>(compactTile[2*i]) |
                           (static_cast<uint16_t>(compactTile[2*i+1]) << 8);
        assert(RawrXD::TensorCompression::FromHalf(h) == source[i + 1]);
    }
    assert(cache.ExportUniform16BitRange("layer.0.weight", 1000, 500,
                                         compactEncoding, compactTile));
    assert(compactTile.size() == 500 * sizeof(uint16_t));
    for (size_t i = 0; i < 500; ++i) {
        const uint16_t h = static_cast<uint16_t>(compactTile[2*i]) |
                           (static_cast<uint16_t>(compactTile[2*i+1]) << 8);
        assert(RawrXD::TensorCompression::FromHalf(h) == source[i + 1000]);
    }
    assert(!cache.ExportUniform16BitRange("layer.0.weight", source.size(), 1,
                                          compactEncoding, compactTile));
    assert(compactTile.empty());
    assert(cache.GetStats().activeReaders == 0);

    // BF16 fallback: values outside the finite F16 range but exactly
    // representable in BF16 must remain packed and round-trip exactly.
    std::vector<float> bf16Source(2048);
    for (size_t i = 0; i < bf16Source.size(); ++i)
        bf16Source[i] = (i & 1u) ? 131072.0f : 65536.0f;
    Deep2::TensorResidencyCache bf16Cache(8192);
    assert(bf16Cache.RegisterF32FromReader("bf16.exact", bf16Source.size(), 0.0f,
        [&](size_t offset, size_t count, float* out) {
            std::copy(bf16Source.begin() + offset,
                      bf16Source.begin() + offset + count, out);
            return true;
        }, 1024));
    RawrXD::TensorCompression::Encoding bf16Encoding =
        RawrXD::TensorCompression::Encoding::Raw;
    std::vector<uint8_t> bf16Packed;
    assert(bf16Cache.ExportUniform16BitRange(
        "bf16.exact", 0, bf16Source.size(), bf16Encoding, bf16Packed));
    assert(bf16Encoding == RawrXD::TensorCompression::Encoding::BF16);
    assert(bf16Packed.size() == bf16Source.size() * sizeof(uint16_t));
    for (size_t i = 0; i < bf16Source.size(); ++i) {
        const uint16_t h = static_cast<uint16_t>(bf16Packed[2*i]) |
                           (static_cast<uint16_t>(bf16Packed[2*i+1]) << 8);
        assert(RawrXD::TensorCompression::FromBFloat16(h) == bf16Source[i]);
    }
    assert(bf16Cache.ExportUniform16BitRange(
        "bf16.exact", 7, 19, bf16Encoding, bf16Packed));
    assert(bf16Encoding == RawrXD::TensorCompression::Encoding::BF16);
    assert(bf16Packed.size() == 19 * sizeof(uint16_t));
    for (size_t i = 0; i < 19; ++i) {
        const uint16_t h = static_cast<uint16_t>(bf16Packed[2*i]) |
                           (static_cast<uint16_t>(bf16Packed[2*i+1]) << 8);
        assert(RawrXD::TensorCompression::FromBFloat16(h) == bf16Source[i + 7]);
    }

    std::vector<float> tile(1537,-999.0f);
    assert(cache.ReadRange("layer.0.weight",900,tile.size(),tile.data()));
    for(size_t i=0;i<tile.size();++i) assert(tile[i]==source[900+i]);
    std::vector<uint8_t> reusableScratch;
    std::vector<float> tile2(777,-123.0f);
    assert(cache.ReadRange("layer.0.weight",2048,tile2.size(),tile2.data(),reusableScratch));
    for(size_t i=0;i<tile2.size();++i) assert(tile2[i]==source[2048+i]);

    auto after=cache.GetStats();
    assert(after.cacheHits==2);
    assert(after.activeReaders==0);
    assert(after.bytesDecoded==(tile.size()+tile2.size())*sizeof(float));

    // The engine's WeightTensor path uses the same bounded streaming
    // builder. Verify that it never needs a full-size F32 intermediate and
    // that the compressed-storage budget rejects before retaining excess data.
    size_t directReads = 0;
    auto direct = RawrXD::TensorCompression::ChunkedF32Storage::BuildFromReader(
        source.size(), 0.0f,
        [&](size_t offset, size_t count, float* out) {
            ++directReads;
            std::copy(source.begin() + offset,
                      source.begin() + offset + count, out);
            return true;
        }, 1024, false, source.size() * sizeof(uint16_t));
    assert(directReads == 10);
    assert(direct.storedBytes() <= source.size() * sizeof(uint16_t));
    std::vector<float> directTile(513);
    direct.ReadRange(4093, directTile.size(), directTile.data());
    for (size_t i = 0; i < directTile.size(); ++i)
        assert(directTile[i] == source[4093 + i]);
    bool budgetRejected = false;
    try {
        (void)RawrXD::TensorCompression::ChunkedF32Storage::BuildFromReader(
            source.size(), 0.0f,
            [&](size_t offset, size_t count, float* out) {
                std::copy(source.begin() + offset,
                          source.begin() + offset + count, out);
                return true;
            }, 1024, false, 1024);
    } catch (const RawrXD::TensorCompression::StorageAdmissionRejected&) {
        budgetRejected = true;
    }
    assert(budgetRejected);

    // A failed streamed registration must not leave a partial cache entry.
    auto badReader=[](size_t,size_t,float*) { return false; };
    assert(!cache.RegisterF32FromReader("broken",512,0.0f,badReader,128));
    assert(!cache.Contains("broken"));
    assert(!cache.IsRawFallback("broken")); // transient source read failure is retryable

    // A tensor larger than the budget is rejected without evicting a valid
    // entry; eviction only happens when a fitting insertion needs capacity.
    std::vector<float> tooLarge(20000);
    for(size_t i=0;i<tooLarge.size();++i) tooLarge[i]=float(i%1000);
    size_t tooLargeReads=0;
    assert(!cache.RegisterF32FromReader("too.large",tooLarge.size(),0.0f,
        [&](size_t o,size_t n,float* out) {
            ++tooLargeReads;
            std::copy(tooLarge.begin()+o,tooLarge.begin()+o+n,out); return true;
        },1024));
    assert(tooLargeReads > 0 && tooLargeReads < (tooLarge.size()+1023)/1024); // stop as soon as the encoded budget is exceeded
    assert(cache.Contains("layer.0.weight"));

    // With a zero error budget, arbitrary F32 values must not be stored as a
    // same-size raw duplicate. The engine then reads raw pager tiles directly.
    const std::vector<float> arbitrary={1.0001f,2.0001f,3.0001f,4.0001f};
    size_t arbitraryReads=0;
    assert(!cache.RegisterF32FromReader("not.compressible",arbitrary.size(),0.0f,
        [&](size_t o,size_t n,float* out) {
            ++arbitraryReads;
            std::copy(arbitrary.begin()+o,arbitrary.begin()+o+n,out); return true;
        },2));
    assert(arbitraryReads==2); // both chunks are evaluated before whole-tensor rejection
    assert(!cache.Contains("not.compressible"));
    assert(cache.IsRawFallback("not.compressible")); // rejection is memoized before releasing the build lock
    cache.MarkRawFallback("not.compressible");
    assert(cache.IsRawFallback("not.compressible"));
    size_t repeatedProbeReads=0;
    assert(!cache.RegisterF32FromReader("not.compressible",arbitrary.size(),0.0f,
        [&](size_t o,size_t n,float* out) {
            ++repeatedProbeReads;
            std::copy(arbitrary.begin()+o,arbitrary.begin()+o+n,out);
            return true;
        },2));
    assert(repeatedProbeReads==0);
    assert(!cache.Contains("not.compressible"));
    cache.SetBudget(cache.GetStats().budgetBytes); // unchanged budget preserves memoization
    size_t unchangedBudgetReads=0;
    assert(!cache.RegisterF32FromReader("not.compressible",arbitrary.size(),0.0f,
        [&](size_t o,size_t n,float* out) {
            ++unchangedBudgetReads;
            std::copy(arbitrary.begin()+o,arbitrary.begin()+o+n,out);
            return true;
        },2));
    assert(unchangedBudgetReads==0);
    cache.SetBudget(cache.GetStats().budgetBytes+1); // new capacity permits a fresh probe
    size_t newBudgetReads=0;
    assert(!cache.RegisterF32FromReader("not.compressible",arbitrary.size(),0.0f,
        [&](size_t o,size_t n,float* out) {
            ++newBudgetReads;
            std::copy(arbitrary.begin()+o,arbitrary.begin()+o+n,out);
            return true;
        },2));
    assert(newBudgetReads==2);
    cache.MarkRawFallback("not.compressible");

    // Mixed F32 tensor: an incompressible first chunk followed by F16-exact
    // zero chunks. Whole-tensor accounting must retain the net savings.
    std::vector<float> mixedF32(4096, 0.0f);
    uint32_t mixedState = 0x6d2b79f5u;
    for (size_t i = 0; i < 1024; ++i) {
        mixedState ^= mixedState << 13;
        mixedState ^= mixedState >> 17;
        mixedState ^= mixedState << 5;
        mixedF32[i] = static_cast<float>(static_cast<int32_t>(mixedState % 100000u) - 50000) / 137.0f;
    }
    Deep2::TensorResidencyCache mixedF32Cache(16*1024);
    size_t mixedF32Reads = 0;
    assert(mixedF32Cache.RegisterF32FromReader("mixed.f32", mixedF32.size(), 0.0f,
        [&](size_t offset, size_t count, float* out) {
            ++mixedF32Reads;
            std::copy(mixedF32.begin()+offset, mixedF32.begin()+offset+count, out);
            return true;
        }, 1024));
    assert(mixedF32Reads == 4);
    const auto mixedF32Stats = mixedF32Cache.GetStats();
    assert(mixedF32Stats.compressedBytes < mixedF32Stats.logicalBytes);
    assert(mixedF32Stats.compressedBytes <= mixedF32Stats.budgetBytes);
    std::vector<float> mixedF32Tile(3072);
    assert(mixedF32Cache.ReadRange("mixed.f32", 1024, mixedF32Tile.size(), mixedF32Tile.data()));
    assert(std::all_of(mixedF32Tile.begin(), mixedF32Tile.end(), [](float v) { return v == 0.0f; }));

    // A fitting insertion evicts the least-recently-used compressed tensor.
    std::vector<float> second(10003);
    for(size_t i=0;i<second.size();++i) second[i]=float(i%100);
    cache.SetBudget(20500);
    assert(cache.RegisterF32FromReader("layer.1.weight",second.size(),0.0f,
        [&](size_t o,size_t n,float* out) {
            std::copy(second.begin()+o,second.begin()+o+n,out); return true;
        },128));
    assert(!cache.Contains("layer.0.weight"));
    assert(cache.Contains("layer.1.weight"));
    assert(cache.GetStats().evictions>=1);

    // Explicit eviction releases the compressed representation.
    assert(cache.Evict("layer.1.weight"));
    assert(!cache.Contains("layer.1.weight"));
    assert(cache.IsRawFallback("not.compressible"));
    cache.Clear();
    assert(!cache.IsRawFallback("not.compressible")); // Clear() resets fallback memoization
    auto finalStats=cache.GetStats();
    assert(finalStats.compressedBytes==0 && finalStats.logicalBytes==0);
    assert(finalStats.evictions>=2);

    // Unexpected runtime/allocation-style failures are retryable; only a
    // typed admission rejection is memoized as a permanent raw fallback.
    Deep2::TensorResidencyCache retryable(4096);
    size_t transientAttempts = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const bool admitted = retryable.RegisterF32FromReader("transient", 64,
            0.0f, [&](size_t, size_t, float*) -> bool {
                ++transientAttempts;
                throw std::runtime_error("simulated transient runtime failure");
            }, 16);
        assert(!admitted);
    }
    assert(transientAttempts == 2);
    assert(!retryable.IsRawFallback("transient"));

    // Bounds are fail-closed and never write beyond the requested output.
    Deep2::TensorResidencyCache bounded(4096);
    std::vector<float> small(128,2.0f);
    assert(bounded.RegisterF32FromReader("small",small.size(),0.0f,
        [&](size_t o,size_t n,float* out) {
            std::copy(small.begin()+o,small.begin()+o+n,out); return true;
        },64));
    float sentinel[2]={-7.0f,-8.0f};
    assert(!bounded.ReadRange("small",127,2,sentinel));
    assert(sentinel[0]==-7.0f && sentinel[1]==-8.0f);
    std::cout<<"compressed F32 residency cache PASS\n";
}
