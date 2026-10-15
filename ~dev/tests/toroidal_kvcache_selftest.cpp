/* ToroidalKVCache Self-Test — Infinite context ring buffer certification */
#include "ToroidalKVCache.hpp"
#include <cstdio>
#include <cassert>
#include <vector>

using namespace Deep2;

int main() {
    fprintf(stderr, "=== ToroidalKVCache Self-Test ===\n\n");
    int failures = 0;

    auto check = [&](bool cond, const char* name) {
        fprintf(stderr, "%-50s %s\n", name, cond ? "PASS" : "FAIL");
        if (!cond) ++failures;
    };

    // Test 1: Basic initialization
    {
        ToroidalKVCache cache;
        ToroidalKVCacheConfig cfg{};
        cfg.numLayers = 2;
        cfg.numHeads = 4;
        cfg.headDim = 64;
        cfg.maxTokens = 1024;
        
        bool ok = cache.initialize(cfg);
        check(ok, "Basic initialization");
        check(cache.isInitialized(), "isInitialized after init");
        check(cache.capacity() == 1024, "Capacity matches config");
        check(cache.currentLength() == 0, "Initial length is 0");
    }

    // Test 2: Write and read single token
    {
        ToroidalKVCache cache;
        ToroidalKVCacheConfig cfg{};
        cfg.numLayers = 1;
        cfg.numHeads = 1;
        cfg.headDim = 8;
        cfg.maxTokens = 16;
        cache.initialize(cfg);
        
        float testK[8] = {1,2,3,4,5,6,7,8};
        float testV[8] = {8,7,6,5,4,3,2,1};
        
        float* kPtr = cache.keyPtr(0, 0, 0);
        float* vPtr = cache.valuePtr(0, 0, 0);
        check(kPtr != nullptr && vPtr != nullptr, "Pointers valid at pos 0");
        
        if (kPtr && vPtr) {
            for (int i = 0; i < 8; ++i) {
                kPtr[i] = testK[i];
                vPtr[i] = testV[i];
            }
        }
        
        cache.advance();
        check(cache.currentLength() == 1, "Length after advance");
        
        // Read back
        const float* rk = cache.keyPtr(0, 0, 0);
        const float* rv = cache.valuePtr(0, 0, 0);
        bool match = true;
        if (rk && rv) {
            for (int i = 0; i < 8; ++i) {
                if (rk[i] != testK[i] || rv[i] != testV[i]) { match = false; break; }
            }
        } else {
            match = false;
        }
        check(match, "Read back matches written data");
    }

    fprintf(stderr, "\n=== SUMMARY ===\n");
    fprintf(stderr, "Failures: %d\n", failures);
    fprintf(stderr, "ToroidalKVCache Self-Test: %s\n", failures == 0 ? "PASS" : "FAIL");
    
    return failures == 0 ? 0 : 1;
}