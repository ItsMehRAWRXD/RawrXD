// These checks are executable test operations, not debug-only diagnostics.
// Release/RelWithDebInfo define NDEBUG; preserve the assertions and their
// side effects so CI exercises admission, decoding and reference comparisons.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "../../src/deep2/NativeTensorResidencyCache.hpp"
#include <cassert>
#include <limits>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>
#include <atomic>
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
    // A second model's differently sized tensor must never silently reuse
    // an existing compressed entry merely because its key is identical.
    size_t collisionReads = 0;
    assert(!cache.RegisterF32FromReader("layer.0.weight",source.size()+1,0.0f,
        [&](size_t,size_t,float*) { ++collisionReads; return false; },1024));
    assert(collisionReads == 0);
    // A cached lossy representation must not satisfy a later stricter
    // numerical tolerance for the same tensor key. A relaxed request may
    // reuse an entry built with stricter bounds, but never the reverse.
    Deep2::TensorResidencyCache toleranceCache(8192);
    std::vector<float> toleranceSource(1024, 1.0001f);
    size_t toleranceReads = 0;
    auto toleranceReader = [&](size_t offset, size_t count, float* out) {
        ++toleranceReads;
        std::copy(toleranceSource.begin() + offset,
                  toleranceSource.begin() + offset + count, out);
        return true;
    };
    assert(toleranceCache.RegisterF32FromReader(
        "tolerance.weight", toleranceSource.size(), 0.01f, toleranceReader, 256));
    const size_t toleranceBuiltReads = toleranceReads;
    assert(!toleranceCache.RegisterF32FromReader(
        "tolerance.weight", toleranceSource.size(), 0.0f, toleranceReader, 256));
    assert(toleranceReads == toleranceBuiltReads);
    assert(toleranceCache.RegisterF32FromReader(
        "tolerance.weight", toleranceSource.size(), 0.02f, toleranceReader, 256));
    assert(toleranceReads == toleranceBuiltReads);
    assert(toleranceCache.GetStats().tensorCount == 1);
    assert(cache.Contains("layer.0.weight"));
    assert(cache.GetStats().tensorCount == 1);

    assert(cache.Contains("layer.0.weight"));
    auto before=cache.GetStats();
    assert(before.tensorCount==1);
    assert(before.logicalBytes==source.size()*sizeof(float));
    assert(before.compressedBytes < before.logicalBytes); // retained metadata/capacity is included
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
    uint32_t bf16Seed = 0x85ebca6bu;
    for (size_t i = 0; i < bf16Source.size(); ++i) {
        bf16Seed ^= bf16Seed << 13;
        bf16Seed ^= bf16Seed >> 17;
        bf16Seed ^= bf16Seed << 5;
        // BF16-exact values with exponent outside finite F16 range.
        // Vary both exponent and mantissa to prevent LZ4 from beating BF16.
        const uint32_t bits = ((uint32_t(143u + (bf16Seed % 12u))) << 23) |
                              ((bf16Seed >> 12) & 0x7fu) << 16;
        std::memcpy(&bf16Source[i], &bits, sizeof(float));
    }
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

    // BF16 direct staging must preserve the original packed encoding and
    // leave guard bytes untouched, even for a cross-chunk window.
    std::vector<uint8_t> bf16Staging(39 * sizeof(uint16_t) + 3, 0x6b);
    assert(bf16Cache.CopyUniform16BitRange(
        "bf16.exact", 1008, 39, bf16Encoding,
        bf16Staging.data(), bf16Staging.size()));
    assert(bf16Encoding == RawrXD::TensorCompression::Encoding::BF16);
    for (size_t i = 0; i < 39; ++i) {
        const uint16_t bits = static_cast<uint16_t>(bf16Staging[2*i]) |
            (static_cast<uint16_t>(bf16Staging[2*i+1]) << 8);
        assert(RawrXD::TensorCompression::FromBFloat16(bits) == bf16Source[1008+i]);
    }
    assert(bf16Staging[78] == 0x6b &&
           bf16Staging[79] == 0x6b &&
           bf16Staging[80] == 0x6b);
    assert(bf16Cache.GetStats().activeReaders == 0);

    const auto beforeF32Reads = cache.GetStats();
    std::vector<float> tile(1537,-999.0f);
    assert(cache.ReadRange("layer.0.weight",900,tile.size(),tile.data()));
    for(size_t i=0;i<tile.size();++i) assert(tile[i]==source[900+i]);
    std::vector<uint8_t> reusableScratch;
    std::vector<float> tile2(777,-123.0f);
    assert(cache.ReadRange("layer.0.weight",2048,tile2.size(),tile2.data(),reusableScratch));
    for(size_t i=0;i<tile2.size();++i) assert(tile2[i]==source[2048+i]);

    auto after=cache.GetStats();
    assert(after.cacheHits == beforeF32Reads.cacheHits + 2);
    assert(after.activeReaders==0);
    assert(after.bytesDecoded == beforeF32Reads.bytesDecoded +
           (tile.size()+tile2.size())*sizeof(float));

    // F32 range validation must match the encoded-byte cache: an invalid
    // tile must not acquire a lease, change the caller buffer, or increment
    // successful decode telemetry. Compare the valid tail against the
    // original independent F32 source, including the final element.
    const auto beforeInvalid = cache.GetStats();
    std::vector<float> sentinel(16, -789.25f);
    assert(!cache.ReadRange("layer.0.weight", source.size()-4,
                            sentinel.size(), sentinel.data(), reusableScratch));
    assert(!cache.ReadRange("layer.0.weight", SIZE_MAX,
                            1, sentinel.data(), reusableScratch));
    assert(!cache.ReadRange("layer.0.weight", 0,
                            1, nullptr, reusableScratch));
    assert(std::all_of(sentinel.begin(), sentinel.end(),
                       [](float value) { return value == -789.25f; }));
    const auto afterInvalid = cache.GetStats();
    assert(afterInvalid.cacheHits == beforeInvalid.cacheHits);
    assert(afterInvalid.cacheMisses == beforeInvalid.cacheMisses + 3);
    assert(afterInvalid.activeReaders == 0);
    assert(afterInvalid.bytesDecoded == beforeInvalid.bytesDecoded);
    assert(cache.ReadRange("layer.0.weight", source.size()-sentinel.size(),
                           sentinel.size(), sentinel.data(), reusableScratch));
    assert(std::equal(sentinel.begin(), sentinel.end(),
                      source.end()-sentinel.size()));

    // Production GPU staging API: copy only requested packed rows, preserving
    // the guard bytes and releasing the cache reader lease after each call.
    std::vector<uint8_t> gpuTile(257 * sizeof(uint16_t) + 2, 0xa5);
    RawrXD::TensorCompression::Encoding gpuEncoding =
        RawrXD::TensorCompression::Encoding::Raw;
    assert(cache.CopyUniform16BitRange("layer.0.weight", 1023, 257,
        gpuEncoding, gpuTile.data(), gpuTile.size()));
    assert(gpuEncoding == RawrXD::TensorCompression::Encoding::F16);
    for (size_t i = 0; i < 257; ++i) {
        const uint16_t bits = static_cast<uint16_t>(gpuTile[2*i]) |
            (static_cast<uint16_t>(gpuTile[2*i+1]) << 8);
        assert(RawrXD::TensorCompression::FromHalf(bits) == source[1023+i]);
    }
    assert(gpuTile[514] == 0xa5 && gpuTile[515] == 0xa5);
    assert(!cache.CopyUniform16BitRange("layer.0.weight", 1023, 257,
        gpuEncoding, gpuTile.data(), 2));
    assert(!cache.CopyUniform16BitRange("missing", 0, 1,
        gpuEncoding, gpuTile.data(), gpuTile.size()));
    assert(cache.GetStats().activeReaders == 0);

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
    // Six-agent style concurrent shared-cache read stress. Each worker owns
    // its decode/output scratch while the compressed tensor remains immutable.
    std::vector<float> sharedWeights(8192);
    for (size_t i = 0; i < sharedWeights.size(); ++i)
        sharedWeights[i] = static_cast<float>(static_cast<int>(i % 16) - 8) * 0.125f;
    Deep2::TensorResidencyCache sharedCache(256 * 1024);
    assert(sharedCache.RegisterF32FromReader("shared.concurrent", sharedWeights.size(),
        0.0f, [&](size_t offset, size_t count, float* out) {
            std::copy(sharedWeights.begin() + offset,
                      sharedWeights.begin() + offset + count, out);
            return true;
        }, 512));
    std::atomic<bool> concurrentOk{true};
    std::vector<std::thread> workers;
    for (size_t worker = 0; worker < 6; ++worker) {
        workers.emplace_back([&, worker] {
            std::vector<float> tile(256);
            for (size_t iteration = 0; iteration < 128; ++iteration) {
                const size_t first = (worker * 97 + iteration * 31) %
                    (sharedWeights.size() - tile.size());
                if (!sharedCache.ReadRange("shared.concurrent", first,
                                           tile.size(), tile.data()) ||
                    !std::equal(tile.begin(), tile.end(),
                                sharedWeights.begin() + first)) {
                    concurrentOk.store(false, std::memory_order_relaxed);
                    return;
                }
            }
        });
    }
    for (auto& worker : workers) worker.join();
    const auto sharedStats = sharedCache.GetStats();
    assert(concurrentOk.load(std::memory_order_relaxed));
    assert(sharedStats.activeReaders == 0);
    assert(sharedStats.cacheHits >= 6 * 128);


    // Equal-sized weights with the same key must not cross model boundaries.
    Deep2::TensorResidencyCache scoped(65536);
    std::vector<float> modelA(8192, 1.0f), modelB(8192, -3.0f);
    scoped.SetModelIdentity("model-A");
    assert(scoped.RegisterF32FromReader("shared.key", modelA.size(), 0.0f,
        [&](size_t o, size_t n, float* out) {
            std::copy(modelA.begin()+o, modelA.begin()+o+n, out);
            return true;
        }, 1024));
    float scopeTile[64] = {};
    assert(scoped.ReadRange("shared.key", 0, 64, scopeTile));
    assert(std::all_of(scopeTile, scopeTile+64, [](float v) { return v == 1.0f; }));
    scoped.MarkRawFallback("old.fallback");
    scoped.SetModelIdentity("model-A"); // no-op
    assert(scoped.Contains("shared.key") && scoped.IsRawFallback("old.fallback"));
    scoped.SetModelIdentity("model-B");
    assert(scoped.ModelIdentity() == "model-B");
    assert(!scoped.Contains("shared.key") && !scoped.IsRawFallback("old.fallback"));
    assert(scoped.GetStats().compressedBytes == 0);
    size_t reboundReads = 0;
    assert(scoped.RegisterF32FromReader("shared.key", modelB.size(), 0.0f,
        [&](size_t o, size_t n, float* out) {
            ++reboundReads;
            std::copy(modelB.begin()+o, modelB.begin()+o+n, out);
            return true;
        }, 1024));
    assert(reboundReads > 0);
    assert(scoped.ReadRange("shared.key", 0, 64, scopeTile));
    assert(std::all_of(scopeTile, scopeTile+64, [](float v) { return v == -3.0f; }));

    // Invalid numerical tolerances must fail closed for both first admission
    // and an already-cached key, without touching the source reader or
    // poisoning a future valid admission. This also guards NaN comparisons,
    // which otherwise make a stricter reuse check silently evaluate false.
    Deep2::TensorResidencyCache toleranceCache(65536);
    std::vector<float> toleranceSource(4096, 1.0f);
    size_t toleranceReads = 0;
    auto toleranceReader = [&](size_t o, size_t n, float* out) {
        ++toleranceReads;
        std::copy(toleranceSource.begin()+o, toleranceSource.begin()+o+n, out);
        return true;
    };
    const float invalidTolerances[] = {
        -0.01f, -std::numeric_limits<float>::infinity(),
        std::numeric_limits<float>::infinity(),
        std::numeric_limits<float>::quiet_NaN()
    };
    for (float invalid : invalidTolerances) {
        assert(!toleranceCache.RegisterF32FromReader(
            "tolerance.weight", toleranceSource.size(), invalid,
            toleranceReader, 1024));
        assert(toleranceReads == 0);
        assert(!toleranceCache.IsRawFallback("tolerance.weight"));
        assert(!toleranceCache.Contains("tolerance.weight"));
    }
    assert(toleranceCache.RegisterF32FromReader(
        "tolerance.weight", toleranceSource.size(), 0.0f,
        toleranceReader, 1024));
    const size_t validReads = toleranceReads;
    assert(validReads == 4);
    for (float invalid : invalidTolerances) {
        assert(!toleranceCache.RegisterF32FromReader(
            "tolerance.weight", toleranceSource.size(), invalid,
            toleranceReader, 1024));
        assert(toleranceReads == validReads);
    }
    float toleranceOutput[16] = {};
    assert(toleranceCache.ReadRange("tolerance.weight", 0, 16, toleranceOutput));
    assert(std::all_of(toleranceOutput, toleranceOutput+16,
                       [](float value) { return value == 1.0f; }));

    // Reopening the same model path can load different bytes (atomic GGUF
    // replacement). Deep2 must clear the cache even when identity is unchanged.
    scoped.MarkRawFallback("stale.fallback");
    scoped.Clear();
    scoped.SetModelIdentity("model-B");
    assert(!scoped.Contains("shared.key"));
    assert(!scoped.IsRawFallback("stale.fallback"));
    assert(scoped.GetStats().compressedBytes == 0);
    size_t samePathReads = 0;
    assert(scoped.RegisterF32FromReader("shared.key", modelA.size(), 0.0f,
        [&](size_t o, size_t n, float* out) {
            ++samePathReads;
            std::copy(modelA.begin()+o, modelA.begin()+o+n, out);
            return true;
        }, 1024));
    assert(samePathReads > 0);
    assert(scoped.ReadRange("shared.key", 0, 64, scopeTile));
    assert(std::all_of(scopeTile, scopeTile+64, [](float v) { return v == 1.0f; }));


    std::cout<<"compressed F32 residency cache PASS\n";
}
