// ============================================================================
// IntelligentPatchingExample.cpp - Cross-Bottle Intelligence + TTL Demo
//
// Demonstrates:
//   - Patch caching and reuse across bottles
//   - Automatic TTL management and cleanup
//   - Event-driven patch lifecycle
//   - Token savings from cache hits
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "Deep2Engine.h"
#include "HotPatcher.hpp"
#include "PatchCache.hpp"
#include "BottleTTL.hpp"
#include <cstdio>
#include <thread>
#include <chrono>

using namespace Deep2;

// ============================================================================
// Threat Patterns
// ============================================================================

void SimulateXORThreat(void* location) {
    // Model XOR pattern at location
    printf("[Threat] XOR pattern detected at %p\n", location);
}

void SimulateAntiDebugThreat(void* location) {
    printf("[Threat] Anti-debug pattern detected at %p\n", location);
}

// ============================================================================
// Smart Bottle Opening with Cache
// ============================================================================

std::string OpenSmartBottle(void* threatLocation, 
                            const std::string& threatPattern,
                            size_t codeSize = 64) {
    printf("\n[SmartBottle] Opening for pattern: %s at %p\n", 
           threatPattern.c_str(), threatLocation);
    
    // Step 1: Check cache first
    float similarity = 0.0f;
    std::string cachedPatchId = TryCachedPatch(threatLocation, codeSize, 
                                                threatPattern, &similarity);
    
    if (!cachedPatchId.empty()) {
        printf("  ✓ Cache HIT! Similar patch found: %s (similarity=%.2f)\n",
               cachedPatchId.c_str(), similarity);
        
        // Apply cached patch
        CachedPatch cached;
        if (GetPatchCache().Get(cachedPatchId, cached)) {
            printf("  ✓ Applying cached patch (verified %llu times)\n",
                   cached.successCount);
            
            // Mark as used
            GetPatchCache().MarkUsed(cachedPatchId);
            
            // Register with TTL (reuse for 30 minutes)
            GetBottleTTL().Register(cachedPatchId, 30 * 60 * 1000);
            
            return cachedPatchId;
        }
    }
    
    printf("  ✗ Cache miss - generating new antidote...\n");
    
    // Step 2: Generate new patch (simulated)
    std::string newPatchId = "antidote_" + threatPattern + "_" + 
                             std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch()).count());
    
    printf("  ✓ Generated new patch: %s\n", newPatchId.c_str());
    
    // Step 3: Apply patch
    printf("  ✓ Applying new patch...\n");
    
    // Step 4: Store in cache for future bottles
    CacheSuccessfulPatch(newPatchId, threatLocation, codeSize, threatPattern);
    printf("  ✓ Stored in cache for future reuse\n");
    
    // Step 5: Register with TTL
    GetBottleTTL().Register(newPatchId, 60 * 60 * 1000);  // 1 hour TTL
    printf("  ✓ Registered with TTL (1 hour)\n");
    
    return newPatchId;
}

// ============================================================================
// Test 1: Cache Hit Demonstration
// ============================================================================

void testCacheHit() {
    printf("\n=== Test 1: Cache Hit Demonstration ===\n");
    
    // Initialize systems
    GetPatchCache().Initialize();
    GetBottleTTL().Initialize();
    
    void* location1 = reinterpret_cast<void*>(0x140200000);
    void* location2 = reinterpret_cast<void*>(0x140200100);  // Similar location
    
    // First bottle - cache miss
    printf("\n-- First bottle (should be cache miss) --");
    std::string patch1 = OpenSmartBottle(location1, "xor");
    
    // Second bottle - similar threat, should be cache hit
    printf("\n-- Second bottle (should be cache hit) --");
    std::string patch2 = OpenSmartBottle(location2, "xor");
    
    // Show statistics
    printf("\n-- Cache Statistics --\n");
    GetPatchCache().PrintStatus();
    
    printf("\n-- TTL Statistics --\n");
    GetBottleTTL().PrintStatus();
}

// ============================================================================
// Test 2: TTL Expiration
// ============================================================================

void testTTLExpiration() {
    printf("\n=== Test 2: TTL Expiration ===\n");
    
    // Set up event callback
    GetBottleTTL().SetEventCallback([](const TTLEvent& event) {
        switch (event.type) {
            case TTLEventType::CREATED:
                printf("  [Event] Patch %s created\n", event.patchId.c_str());
                break;
            case TTLEventType::EXPIRING:
                printf("  [Event] Patch %s EXPIRING SOON!\n", event.patchId.c_str());
                break;
            case TTLEventType::EXPIRED:
                printf("  [Event] Patch %s EXPIRED\n", event.patchId.c_str());
                break;
            case TTLEventType::CLEANED_UP:
                printf("  [Event] Patch %s cleaned up\n", event.patchId.c_str());
                break;
            case TTLEventType::RENEWED:
                printf("  [Event] Patch %s renewed\n", event.patchId.c_str());
                break;
        }
    });
    
    // Register patch with short TTL (5 seconds for demo)
    void* location = reinterpret_cast<void*>(0x140300000);
    std::string patchId = "test_patch_ttl";
    
    printf("\n-- Registering patch with 5 second TTL --\n");
    GetBottleTTL().Register(patchId, 5000);  // 5 seconds
    
    // Wait for expiration
    printf("-- Waiting for expiration... --\n");
    std::this_thread::sleep_for(std::chrono::seconds(6));
    
    // Check status
    printf("\n-- Final Status --\n");
    GetBottleTTL().PrintStatus();
}

// ============================================================================
// Test 3: Cross-Bottle Sharing
// ============================================================================

void testCrossBottleSharing() {
    printf("\n=== Test 3: Cross-Bottle Sharing ===\n");
    
    // Bottle A learns some patches
    printf("\n-- Bottle A learning... --\n");
    void* locA1 = reinterpret_cast<void*>(0x140400000);
    void* locA2 = reinterpret_cast<void*>(0x140400100);
    
    OpenSmartBottle(locA1, "anti-debug");
    OpenSmartBottle(locA2, "obfuscated");
    
    // Export cache from Bottle A
    printf("\n-- Exporting Bottle A's cache... --\n");
    auto cacheData = GetPatchCache().ExportCache();
    printf("  Exported %zu bytes of cache data\n", cacheData.size());
    
    // Model Bottle B (new instance)
    printf("\n-- Bottle B importing cache... --\n");
    PatchCache bottleBCache;
    bottleBCache.Initialize();
    size_t imported = bottleBCache.ImportCache(cacheData);
    printf("  Imported %zu patches\n", imported);
    
    // Bottle B now knows Bottle A's patches
    printf("\n-- Bottle B checking for known patterns --\n");
    void* locB1 = reinterpret_cast<void*>(0x140500000);  // Similar to locA1
    
    float sim = 0.0f;
    std::string cached = bottleBCache.FindSimilar(locB1, 64, "anti-debug", &sim);
    if (!cached.empty()) {
        printf("  ✓ Bottle B found cached patch from Bottle A! (sim=%.2f)\n", sim);
    }
}

// ============================================================================
// Test 4: Token Savings Calculation
// ============================================================================

void testTokenSavings() {
    printf("\n=== Test 4: Token Savings Calculation ===\n");
    
    // Model 100 bottles opening
    printf("\n-- Modeling 100 bottle openings --\n");
    
    int cacheHits = 0;
    int cacheMisses = 0;
    
    for (int i = 0; i < 100; i++) {
        void* loc = reinterpret_cast<void*>(0x140600000 + (i * 0x100));
        std::string pattern = (i % 2 == 0) ? "xor" : "anti-debug";
        
        float sim = 0.0f;
        std::string cached = TryCachedPatch(loc, 64, pattern, &sim);
        
        if (!cached.empty()) {
            cacheHits++;
            GetPatchCache().MarkUsed(cached);
        } else {
            cacheMisses++;
            // Store for future
            std::string patchId = "simulated_" + std::to_string(i);
            CacheSuccessfulPatch(patchId, loc, 64, pattern);
        }
    }
    
    // Calculate savings
    // Assume: cache hit saves ~1000 tokens, cache miss costs ~1000 tokens to generate
    int tokensSaved = cacheHits * 1000;
    int tokensSpent = cacheMisses * 1000;
    
    printf("\n-- Results --\n");
    printf("  Cache Hits:   %d\n", cacheHits);
    printf("  Cache Misses: %d\n", cacheMisses);
    printf("  Tokens Saved: %d\n", tokensSaved);
    printf("  Tokens Spent: %d\n", tokensSpent);
    printf("  Net Savings:  %d tokens (%.1f%%)\n", 
           tokensSaved - tokensSpent,
           (double)tokensSaved / (tokensSaved + tokensSpent) * 100);
    
    GetPatchCache().PrintStatus();
}

// ============================================================================
// Test 5: Renewal Workflow
// ============================================================================

void testRenewalWorkflow() {
    printf("\n=== Test 5: Renewal Workflow ===\n");
    
    std::string patchId = "renewable_patch";
    void* location = reinterpret_cast<void*>(0x140700000);
    
    // Open bottle with 10 second TTL
    printf("\n-- Opening bottle with 10 second TTL --\n");
    GetBottleTTL().Register(patchId, 10000);
    
    // Check status
    auto lifetime = PatchLifetime();
    if (GetBottleTTL().GetLifetime(patchId, lifetime)) {
        printf("  Time remaining: %llums\n", 
               GetBottleTTL().TimeRemaining(patchId));
    }
    
    // Wait 5 seconds
    printf("-- Waiting 5 seconds... --\n");
    std::this_thread::sleep_for(std::chrono::seconds(5));
    
    // Renew
    printf("-- Renewing patch --\n");
    if (GetBottleTTL().Renew(patchId, 10000)) {
        printf("  ✓ Renewed successfully\n");
        printf("  New time remaining: %llums\n", 
               GetBottleTTL().TimeRemaining(patchId));
    }
    
    // Show final stats
    GetBottleTTL().PrintStatus();
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Intelligent Patching System Demo                         ║\n");
    printf("║     Cross-Bottle Intelligence + TTL Management                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    // Initialize HotPatcher
    GetHotPatcher().initialize();
    
    // Run tests
    testCacheHit();
    testTTLExpiration();
    testCrossBottleSharing();
    testTokenSavings();
    testRenewalWorkflow();
    
    // Final summary
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Final System Status                                        ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    GetPatchCache().PrintStatus();
    GetBottleTTL().PrintStatus();
    GetHotPatcher().printStatus();
    
    // Cleanup
    GetBottleTTL().Shutdown();
    GetPatchCache().Shutdown();
    GetHotPatcher().shutdown();
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Demo Complete                                              ║\n");
    printf("║     Cross-bottle intelligence reduces token waste              ║\n");
    printf("║     TTL management prevents patch accumulation                 ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}

// ============================================================================
// Summary
// ============================================================================
/*

INTELLIGENT PATCHING SYSTEM:

1. PatchCache (Cross-Bottle Intelligence)
   - Stores verified patches with similarity matching
   - Finds "close enough" patches for new threats
   - Shares learned patches between bottles
   - Tracks token savings from cache hits

2. BottleTTL (Time-To-Live Management)
   - Automatic expiration of stale patches
   - Event-driven lifecycle (created, expiring, expired, cleaned)
   - Renewal API for active patches
   - Prevents accumulation of unused hooks

3. Integration
   - OpenSmartBottle() checks cache before generating
   - Cache hits save ~1000 tokens per bottle opening
   - TTL auto-cleanup removes expired patches
   - Cross-bottle sharing propagates knowledge

TOKEN SAVINGS:
- Without cache: 1000 tokens per bottle opening
- With cache hit: ~10 tokens (cache lookup)
- Savings: 99% for repeated patterns

*/
