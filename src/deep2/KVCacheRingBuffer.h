// ============================================================================
// Blocker #28: KV Cache Circular Ring Buffer
// Implements circular ring-buffers in KVCache_GQA.h for efficient
// KV cache management without large memory moves.
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <atomic>

namespace Deep2 {

// Circular ring buffer for KV cache entries
// Allows O(1) append and O(1) eviction without memmove
template<typename T>
class CircularKVBuffer {
public:
    CircularKVBuffer() : capacity_(0), head_(0), tail_(0), size_(0), buffer_(nullptr) {}
    ~CircularKVBuffer() { delete[] buffer_; }

    bool Initialize(size_t capacity) {
        if (capacity == 0) return false;
        if (buffer_) delete[] buffer_;
        
        capacity_ = capacity;
        buffer_ = new T[capacity_];
        head_ = 0;
        tail_ = 0;
        size_ = 0;
        return true;
    }

    // Append an element - overwrites oldest if full
    void Push(const T& value) {
        if (!buffer_ || capacity_ == 0) return;
        
        buffer_[tail_] = value;
        tail_ = (tail_ + 1) % capacity_;
        
        if (size_ < capacity_) {
            size_++;
        } else {
            // Buffer is full - advance head (overwrite oldest)
            head_ = (head_ + 1) % capacity_;
        }
    }

    // Get element at logical index (0 = oldest)
    T* Get(size_t index) {
        if (!buffer_ || index >= size_) return nullptr;
        size_t physicalIdx = (head_ + index) % capacity_;
        return &buffer_[physicalIdx];
    }

    const T* Get(size_t index) const {
        if (!buffer_ || index >= size_) return nullptr;
        size_t physicalIdx = (head_ + index) % capacity_;
        return &buffer_[physicalIdx];
    }

    // Get most recent element
    T* Back() {
        if (size_ == 0) return nullptr;
        size_t physicalIdx = (tail_ + capacity_ - 1) % capacity_;
        return &buffer_[physicalIdx];
    }

    const T* Back() const {
        if (size_ == 0) return nullptr;
        size_t physicalIdx = (tail_ + capacity_ - 1) % capacity_;
        return &buffer_[physicalIdx];
    }

    // Get oldest element
    T* Front() {
        if (size_ == 0) return nullptr;
        return &buffer_[head_];
    }

    const T* Front() const {
        if (size_ == 0) return nullptr;
        return &buffer_[head_];
    }

    // Remove oldest element
    void Pop() {
        if (size_ == 0) return;
        head_ = (head_ + 1) % capacity_;
        size_--;
    }

    // Clear all entries
    void Clear() {
        head_ = 0;
        tail_ = 0;
        size_ = 0;
    }

    size_t Size() const { return size_; }
    size_t Capacity() const { return capacity_; }
    bool Empty() const { return size_ == 0; }
    bool Full() const { return size_ == capacity_; }

    // Get contiguous span starting from logical index
    // Returns pointer and count (may wrap around)
    size_t GetContiguousSpan(size_t startIndex, T*& outPtr) {
        if (!buffer_ || startIndex >= size_) return 0;
        
        size_t physicalStart = (head_ + startIndex) % capacity_;
        
        // Check if we can get a contiguous block to the end of buffer
        if (physicalStart + (size_ - startIndex) <= capacity_) {
            outPtr = &buffer_[physicalStart];
            return size_ - startIndex;
        } else {
            outPtr = &buffer_[physicalStart];
            return capacity_ - physicalStart;
        }
    }

private:
    T* buffer_;
    size_t capacity_;
    size_t head_;
    size_t tail_;
    size_t size_;
};

// Specialized KV cache entry
struct KVCacheEntry {
    float* kData;
    float* vData;
    int layer;
    int head;
    int seqPos;
    bool valid;
};

// Ring buffer manager for KV cache
typedef CircularKVBuffer<KVCacheEntry> KVCacheRingBuffer;

} // namespace Deep2
