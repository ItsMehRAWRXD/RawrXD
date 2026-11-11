#pragma once
#include <cstdint>
#include <vector>
#include <cstring>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// KVCache - Key-Value cache for transformer attention
// ============================================================================
// Layout: [position, head, head_dim]
// Index: ((pos * num_heads) + head) * head_dim
// ============================================================================
class KVCache {
public:
    KVCache();
    ~KVCache();
    
    // Initialize cache with dimensions
    // max_seq_len: Maximum sequence length (e.g., 4096, 8192, 32768)
    // num_heads: Number of attention heads
    // head_dim: Dimension per head (e.g., 64, 128)
    void Resize(size_t max_seq_len, size_t num_heads, size_t head_dim);
    
    // Reset cache (clear all entries but keep allocation)
    void Reset();
    
    // Get current sequence length
    size_t CurrentLen() const { return m_current_len; }
    
    // Get cache dimensions
    size_t MaxSeqLen() const { return m_max_seq; }
    size_t NumHeads() const { return m_heads; }
    size_t HeadDim() const { return m_head_dim; }
    
    // ------------------------------------------------------------------------
    // Key/Value Access
    // ------------------------------------------------------------------------
    
    // Append key for a specific head at current position
    // Automatically advances current_len after all heads are appended
    void AppendKey(size_t head, const float* data);
    void AppendValue(size_t head, const float* data);
    
    // Get pointer to cached key at position and head
    const float* GetKey(size_t pos, size_t head) const;
    const float* GetValue(size_t pos, size_t head) const;
    
    // Get mutable pointer (for advanced use)
    float* GetKeyMutable(size_t pos, size_t head);
    float* GetValueMutable(size_t pos, size_t head);
    
    // ------------------------------------------------------------------------
    // Batch Operations
    // ------------------------------------------------------------------------
    
    // Append keys/values for all heads at once
    // k_data: [num_heads * head_dim] - contiguous
    // v_data: [num_heads * head_dim] - contiguous
    void AppendAllHeads(const float* k_data, const float* v_data);
    
    // Get contiguous block of all keys up to current_len
    // Useful for attention matrix computation
    const float* GetAllKeys() const { return m_keys.data(); }
    const float* GetAllValues() const { return m_values.data(); }
    
    // ------------------------------------------------------------------------
    // Memory
    // ------------------------------------------------------------------------
    
    // Get total memory usage in bytes
    size_t GetMemoryUsage() const {
        return (m_keys.size() + m_values.size()) * sizeof(float);
    }
    
    // Check if cache is properly configured
    bool IsValid() const {
        return m_max_seq > 0 && m_heads > 0 && m_head_dim > 0 &&
               !m_keys.empty() && !m_values.empty();
    }
    
private:
    size_t m_max_seq = 0;
    size_t m_heads = 0;
    size_t m_head_dim = 0;
    size_t m_current_len = 0;
    
    std::vector<float> m_keys;    // [max_seq][heads][head_dim]
    std::vector<float> m_values;  // [max_seq][heads][head_dim]
    
    // Current append position tracking
    size_t m_append_head = 0;
    
    // Compute flat index: ((pos * heads) + head) * head_dim
    size_t Index(size_t pos, size_t head) const {
        return ((pos * m_heads) + head) * m_head_dim;
    }
};

} // namespace Runtime
} // namespace RawrXD
