// ============================================================================
// KV Cache Implementation
// ============================================================================

#include "kv_cache.hpp"
#include <iostream>

namespace RawrXD {
namespace Runtime {

KVCache::KVCache() = default;
KVCache::~KVCache() = default;

void KVCache::Resize(size_t max_seq_len, size_t num_heads, size_t head_dim) {
    m_max_seq = max_seq_len;
    m_heads = num_heads;
    m_head_dim = head_dim;
    m_current_len = 0;
    m_append_head = 0;
    
    size_t total_size = m_max_seq * m_heads * m_head_dim;
    
    m_keys.resize(total_size, 0.0f);
    m_values.resize(total_size, 0.0f);
    
    std::cout << "[KVCache] Resized to [" << m_max_seq << ", " << m_heads 
              << ", " << m_head_dim << "] = " << (GetMemoryUsage() / (1024.0 * 1024.0)) 
              << " MB" << std::endl;
}

void KVCache::Reset() {
    m_current_len = 0;
    m_append_head = 0;
    
    // Optionally clear memory (comment out for performance)
    // std::fill(m_keys.begin(), m_keys.end(), 0.0f);
    // std::fill(m_values.begin(), m_values.end(), 0.0f);
}

void KVCache::AppendKey(size_t head, const float* data) {
    if (m_current_len >= m_max_seq || head >= m_heads) return;
    
    size_t idx = Index(m_current_len, head);
    std::memcpy(&m_keys[idx], data, m_head_dim * sizeof(float));
    
    // Track which heads have been appended
    m_append_head = head + 1;
    
    // If all heads appended, advance to next position
    if (m_append_head >= m_heads) {
        m_current_len++;
        m_append_head = 0;
    }
}

void KVCache::AppendValue(size_t head, const float* data) {
    if (m_current_len >= m_max_seq || head >= m_heads) return;
    
    size_t idx = Index(m_current_len, head);
    std::memcpy(&m_values[idx], data, m_head_dim * sizeof(float));
}

const float* KVCache::GetKey(size_t pos, size_t head) const {
    if (pos >= m_current_len || head >= m_heads) return nullptr;
    return &m_keys[Index(pos, head)];
}

const float* KVCache::GetValue(size_t pos, size_t head) const {
    if (pos >= m_current_len || head >= m_heads) return nullptr;
    return &m_values[Index(pos, head)];
}

float* KVCache::GetKeyMutable(size_t pos, size_t head) {
    if (pos >= m_max_seq || head >= m_heads) return nullptr;
    return &m_keys[Index(pos, head)];
}

float* KVCache::GetValueMutable(size_t pos, size_t head) {
    if (pos >= m_max_seq || head >= m_heads) return nullptr;
    return &m_values[Index(pos, head)];
}

void KVCache::AppendAllHeads(const float* k_data, const float* v_data) {
    if (m_current_len >= m_max_seq) return;
    
    size_t idx = Index(m_current_len, 0);
    size_t copy_size = m_heads * m_head_dim * sizeof(float);
    
    std::memcpy(&m_keys[idx], k_data, copy_size);
    std::memcpy(&m_values[idx], v_data, copy_size);
    
    m_current_len++;
    m_append_head = 0;
}

} // namespace Runtime
} // namespace RawrXD
