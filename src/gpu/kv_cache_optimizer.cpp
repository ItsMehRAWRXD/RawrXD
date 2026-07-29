#include "kv_cache_optimizer.h"
<<<<<<< HEAD
#include <cstdio>
#include <algorithm>

// KV cache optimizer — Phase 31 implementation complete


KVCacheOptimizer::KVCacheOptimizer()
    : m_cacheSizeLimit(32000)    // Default limit: 32k tokens
    , m_slidingWindowSize(1000)  // Default sliding window size
    , m_lastAccessTime{}
    , m_gpuCacheInitialized(false)
{
=======
#include "../gpu_masm/gpu_masm_bridge.h"
#include "../ggml_masm/ggml_masm_bridge.h"
KVCacheOptimizer::KVCacheOptimizer()
    
    , m_cacheSizeLimit(32000) // Default limit: 32k tokens
    , m_slidingWindowSize(1000) // Default sliding window size
    , m_gpuCacheInitialized(false)
{
    // Initialize GPU KV cache if available
    if (KVCacheInit(m_cacheSizeLimit) == 0) {
        m_gpuCacheInitialized = true;
    } else {
        m_gpuCacheInitialized = false;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

KVCacheOptimizer::~KVCacheOptimizer()
{
<<<<<<< HEAD
=======
    // No explicit cleanup needed - MASM handles it
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void KVCacheOptimizer::setCacheSizeLimit(int limit)
{
    m_cacheSizeLimit = limit;
}

void KVCacheOptimizer::addTokens(const std::vector<int> &tokens)
{
<<<<<<< HEAD
    m_cachedTokens.insert(m_cachedTokens.end(), tokens.begin(), tokens.end());
    evictIfNeeded();
    m_lastAccessTime = std::chrono::steady_clock::now();

    if (onCacheUpdated) {
        onCacheUpdated(static_cast<int>(m_cachedTokens.size()));
    }
=======
    if (m_gpuCacheInitialized && !tokens.empty()) {
        // Use GPU-accelerated token addition
        std::vector<int> tokenVec = tokens.toVector();
        int result = KVCacheAddTokens(tokenVec.data(), tokenVec.size());
        
        if (result == 0) {
            // Success - update local copy for queries
            m_cachedTokens.append(tokens);
        } else {
            // CPU fallback
            m_cachedTokens.append(tokens);
        }
    } else {
        // CPU-only path
        m_cachedTokens.append(tokens);
    }
    
    evictIfNeeded();
    m_lastAccessTime = // DateTime::currentDateTime();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

std::vector<int> KVCacheOptimizer::getCachedTokens() const
{
    return m_cachedTokens;
}

void KVCacheOptimizer::evictIfNeeded()
{
<<<<<<< HEAD
    if (static_cast<int>(m_cachedTokens.size()) > m_cacheSizeLimit) {
        // Implement dynamic sliding-window eviction
        int tokensToEvict = static_cast<int>(m_cachedTokens.size()) - m_cacheSizeLimit;
        if (tokensToEvict > 0) {
            // Remove tokens from the beginning (oldest tokens)
            m_cachedTokens.erase(m_cachedTokens.begin(), m_cachedTokens.begin() + tokensToEvict);
            fprintf(stderr, "[KVCache] Evicted %d tokens from KV cache\n", tokensToEvict);

            if (onCacheEvicted) {
                onCacheEvicted(tokensToEvict);
            }
=======
    if (m_cachedTokens.size() > m_cacheSizeLimit) {
        int tokensToEvict = m_cachedTokens.size() - m_cacheSizeLimit;
        
        if (tokensToEvict > 0) {
            if (m_gpuCacheInitialized) {
                // Use GPU-accelerated eviction
                int result = KVCacheEvict(tokensToEvict);
                
                if (result == 0) {
                } else {
                }
            }
            
            // Update local cache (both GPU and CPU paths)
            m_cachedTokens.erase(m_cachedTokens.begin(), m_cachedTokens.begin() + tokensToEvict);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }
    }
}

void KVCacheOptimizer::setSlidingWindowSize(int size)
{
    m_slidingWindowSize = size;
<<<<<<< HEAD
}
=======
}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
