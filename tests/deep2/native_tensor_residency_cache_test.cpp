#include "../../src/deep2/NativeTensorResidencyCache.hpp"
#include <cassert>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
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
    assert(arbitraryReads==1); // only the probe chunk was read
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
    assert(newBudgetReads==1);
    cache.MarkRawFallback("not.compressible");

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
