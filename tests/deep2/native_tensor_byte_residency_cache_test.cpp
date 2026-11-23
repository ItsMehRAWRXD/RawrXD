// These checks are executable test operations, not debug-only diagnostics.
// Release/RelWithDebInfo define NDEBUG; preserve the assertions and their
// side effects so CI exercises admission, decoding and reference comparisons.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "../../src/deep2/NativeTensorByteResidencyCache.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <thread>
#include <atomic>
#include <stdexcept>
#include <vector>

int main() {
    std::vector<uint8_t> source(128*1024,0xA7);
    Deep2::TensorByteResidencyCache cache(16*1024);
    size_t reads=0;
    auto reader=[&](size_t offset,size_t count,uint8_t* out) {
        ++reads;
        if(offset>source.size()||count>source.size()-offset)return false;
        std::copy(source.begin()+offset,source.begin()+offset+count,out);
        return true;
    };
    assert(cache.RegisterFromReader("shard0:weight0",source.size(),reader,4096));
    assert(reads==(source.size()+4095)/4096);
    // Rebinding the same cache key to a different tensor size must fail
    // without invoking the new source or corrupting the original resident.
    size_t collisionReads = 0;
    assert(!cache.RegisterFromReader("shard0:weight0", source.size() + 4096,
        [&](size_t,size_t,uint8_t*) { ++collisionReads; return false; },4096));
    assert(collisionReads == 0);
    assert(cache.Contains("shard0:weight0"));
    assert(cache.GetStats().tensorCount == 1);

    auto stats=cache.GetStats();
    assert(stats.tensorCount==1);
    assert(stats.logicalBytes==source.size());
    assert(stats.compressedBytes<stats.logicalBytes);
    assert(stats.compressedBytes<=stats.budgetBytes);

    assert(!cache.RegisterFromReader("transient-read-failure",4096,
        [](size_t,size_t,uint8_t*) { return false; },1024));
    assert(!cache.IsRawFallback("transient-read-failure"));

    std::vector<uint8_t> decoded(9000,0);
    std::vector<uint8_t> scratch;
    assert(cache.ReadRange("shard0:weight0",4000,decoded.size(),decoded.data(),scratch));
    assert(std::all_of(decoded.begin(),decoded.end(),[](uint8_t v){return v==0xA7;}));
    stats=cache.GetStats();
    assert(stats.hits==1);
    assert(stats.activeReaders==0);
    assert(stats.bytesDecoded==decoded.size());
    std::vector<uint8_t> patterned(96*1024);
    for(size_t i=0;i<patterned.size();++i)
        patterned[i]=static_cast<uint8_t>((i%251)^((i/251)&7));
    size_t patternReads=0;
    assert(cache.RegisterFromReader("shard0:patterned",patterned.size(),
        [&](size_t offset,size_t count,uint8_t* out) {
            ++patternReads;
            std::copy(patterned.begin()+offset,patterned.begin()+offset+count,out);
            return true;
        },4096));
    assert(patternReads==(patterned.size()+4095)/4096);

    // Mixed tensor: first 4 KiB is incompressible, remaining 12 KiB repeats.
    // Whole-tensor accounting should admit it even though chunk zero cannot shrink.
    std::vector<uint8_t> mixed(16*1024, 0xA7);
    uint32_t mixedState = 0x9e3779b9u;
    for (size_t i = 0; i < 4096; ++i) {
        mixedState ^= mixedState << 13;
        mixedState ^= mixedState >> 17;
        mixedState ^= mixedState << 5;
        mixed[i] = static_cast<uint8_t>(mixedState);
    }
    Deep2::TensorByteResidencyCache mixedCache(8*1024);
    size_t mixedReads = 0;
    assert(mixedCache.RegisterFromReader("mixed", mixed.size(),
        [&](size_t offset, size_t count, uint8_t* out) {
            ++mixedReads;
            std::copy(mixed.begin()+offset, mixed.begin()+offset+count, out);
            return true;
        }, 4096));
    assert(mixedReads == 4);
    const auto mixedStats = mixedCache.GetStats();
    assert(mixedStats.compressedBytes < mixedStats.logicalBytes);
    assert(mixedStats.compressedBytes <= mixedStats.budgetBytes);
    std::vector<uint8_t> mixedTile(12*1024);
    assert(mixedCache.ReadRange("mixed", 4096, mixedTile.size(), mixedTile.data(), scratch));
    assert(std::all_of(mixedTile.begin(), mixedTile.end(), [](uint8_t v){ return v == 0xA7; }));

    std::vector<uint8_t> patternTile(12000);
    assert(cache.ReadRange("shard0:patterned",17000,patternTile.size(),
                           patternTile.data(),scratch));
    assert(std::equal(patternTile.begin(),patternTile.end(),patterned.begin()+17000));

    // Entire tensors are evaluated: an incompressible leading chunk must not
    // hide later chunks whose savings make the complete tensor worthwhile.
    std::vector<uint8_t> noise(64*1024);
    uint32_t state=0x12345678u;
    for(auto& value:noise) {
        state^=state<<13;state^=state>>17;state^=state<<5;
        value=static_cast<uint8_t>(state);
    }
    size_t noiseReads=0;
    assert(!cache.RegisterFromReader("noise",noise.size(),
        [&](size_t offset,size_t count,uint8_t* out) {
            ++noiseReads;
            std::copy(noise.begin()+offset,noise.begin()+offset+count,out);
            return true;
        },4096));
    assert(noiseReads==5); // 4 chunks fill the 16 KiB budget; the next proves it cannot fit
    assert(!cache.Contains("noise"));
    assert(cache.IsRawFallback("noise")); // deterministic rejection is atomic with first-touch admission
    cache.MarkRawFallback("noise");
    assert(cache.IsRawFallback("noise"));
    size_t repeatedNoiseReads=0;
    assert(!cache.RegisterFromReader("noise",noise.size(),
        [&](size_t offset,size_t count,uint8_t* out) {
            ++repeatedNoiseReads;
            std::copy(noise.begin()+offset,noise.begin()+offset+count,out);
            return true;
        },4096));
    assert(repeatedNoiseReads==0);
    assert(!cache.Contains("noise"));
    cache.SetBudget(cache.GetStats().budgetBytes);
    size_t sameBudgetReads=0;
    assert(!cache.RegisterFromReader("noise",noise.size(),
        [&](size_t offset,size_t count,uint8_t* out) {
            ++sameBudgetReads;
            std::copy(noise.begin()+offset,noise.begin()+offset+count,out);
            return true;
        },4096));
    assert(sameBudgetReads==0);
    cache.SetBudget(cache.GetStats().budgetBytes+1);
    size_t changedBudgetReads=0;
    assert(!cache.RegisterFromReader("noise",noise.size(),
        [&](size_t offset,size_t count,uint8_t* out) {
            ++changedBudgetReads;
            std::copy(noise.begin()+offset,noise.begin()+offset+count,out);
            return true;
        },4096));
    assert(changedBudgetReads==5);
    cache.MarkRawFallback("noise");

    assert(cache.Evict("shard0:weight0"));
    assert(!cache.Contains("shard0:weight0"));
    cache.Clear();
    assert(!cache.IsRawFallback("noise"));
    const auto finalStats=cache.GetStats();
    assert(finalStats.compressedBytes==0&&finalStats.logicalBytes==0);

    // Unexpected runtime/allocation-style exceptions are retryable, not a
    // permanent "incompressible" verdict. A later source attempt must run.
    size_t transientAttempts = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const bool admitted = cache.RegisterFromReader("transient", 4096,
            [&](size_t, size_t, uint8_t*) -> bool {
                ++transientAttempts;
                throw std::runtime_error("simulated transient runtime failure");
            }, 1024);
        assert(!admitted);
    }
    assert(transientAttempts == 2);
    assert(!cache.IsRawFallback("transient"));

    // Concurrent partial reads model multiple inference agents sharing the
    // same immutable compressed quantized-weight payload.
    std::vector<uint8_t> sharedBytes(128 * 1024);
    for (size_t i = 0; i < sharedBytes.size(); ++i)
        sharedBytes[i] = static_cast<uint8_t>((i / 64) & 0x0f);
    Deep2::TensorByteResidencyCache sharedCache(256 * 1024);
    assert(sharedCache.RegisterFromReader("shared.quantized", sharedBytes.size(),
        [&](size_t offset, size_t count, uint8_t* out) {
            std::copy(sharedBytes.begin() + offset,
                      sharedBytes.begin() + offset + count, out);
            return true;
        }, 4096));
    std::atomic<bool> concurrentOk{true};
    std::vector<std::thread> workers;
    for (size_t worker = 0; worker < 6; ++worker) {
        workers.emplace_back([&, worker] {
            std::vector<uint8_t> tile(2048), decodeScratch;
            for (size_t iteration = 0; iteration < 128; ++iteration) {
                const size_t first = (worker * 4093 + iteration * 977) %
                    (sharedBytes.size() - tile.size());
                if (!sharedCache.ReadRange("shared.quantized", first,
                                           tile.size(), tile.data(), decodeScratch) ||
                    !std::equal(tile.begin(), tile.end(),
                                sharedBytes.begin() + first)) {
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
    assert(sharedStats.hits >= 6 * 128);


    // Model rebinding must not reuse an equal-sized but different payload.
    Deep2::TensorByteResidencyCache scoped(65536);
    std::vector<uint8_t> modelA(8192, 0x11), modelB(8192, 0xE7);
    scoped.SetModelIdentity("model-A");
    assert(scoped.RegisterFromReader("shared.key", modelA.size(),
        [&](size_t o, size_t n, uint8_t* out) {
            std::copy(modelA.begin()+o, modelA.begin()+o+n, out);
            return true;
        }, 1024));
    std::vector<uint8_t> scopeTile(64), scopeScratch;
    assert(scoped.ReadRange("shared.key", 0, scopeTile.size(),
                            scopeTile.data(), scopeScratch));
    assert(std::all_of(scopeTile.begin(), scopeTile.end(),
                       [](uint8_t b) { return b == 0x11; }));
    scoped.MarkRawFallback("old.fallback");
    scoped.SetModelIdentity("model-A"); // no-op: preserve existing cache
    assert(scoped.Contains("shared.key") && scoped.IsRawFallback("old.fallback"));
    scoped.SetModelIdentity("model-B");
    assert(scoped.ModelIdentity() == "model-B");
    assert(!scoped.Contains("shared.key") && !scoped.IsRawFallback("old.fallback"));
    assert(scoped.GetStats().compressedBytes == 0);
    size_t reboundReads = 0;
    assert(scoped.RegisterFromReader("shared.key", modelB.size(),
        [&](size_t o, size_t n, uint8_t* out) {
            ++reboundReads;
            std::copy(modelB.begin()+o, modelB.begin()+o+n, out);
            return true;
        }, 1024));
    assert(reboundReads > 0);
    assert(scoped.ReadRange("shared.key", 0, scopeTile.size(),
                            scopeTile.data(), scopeScratch));
    assert(std::all_of(scopeTile.begin(), scopeTile.end(),
                       [](uint8_t b) { return b == 0xE7; }));

    std::cout<<"lossless encoded-byte tensor residency cache PASS\n";
}
