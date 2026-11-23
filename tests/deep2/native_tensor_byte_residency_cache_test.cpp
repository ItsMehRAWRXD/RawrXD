#include "../../src/deep2/NativeTensorByteResidencyCache.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
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
    std::copy(noise.begin(), noise.begin()+4096, mixed.begin());
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

    std::cout<<"lossless encoded-byte tensor residency cache PASS\n";
}
