#pragma once
#include <vulkan/vulkan.h>
#include <cstdint>
#include <vector>
#include <string>
#include <mutex>

namespace Deep2Rom::Inference {

    // KV Cache entry for a single layer
    struct KVCacheLayer {
        VkBuffer        keyBuffer{ VK_NULL_HANDLE };
        VkBuffer        valueBuffer{ VK_NULL_HANDLE };
        VkDeviceMemory  keyMemory{ VK_NULL_HANDLE };
        VkDeviceMemory  valueMemory{ VK_NULL_HANDLE };
        uint64_t        keyOffset{ 0 };     // Offset into bound memory
        uint64_t        valueOffset{ 0 };
        uint64_t        capacity{ 0 };      // Max tokens this layer can hold
        uint64_t        size{ 0 };          // Current tokens used
        uint32_t        headDim{ 0 };       // Per-head dimension
        uint32_t        numHeads{ 0 };      // Number of heads
    };

    // KV Cache configuration
    struct KVCacheConfig {
        uint32_t numLayers = 0;
        uint32_t maxSeqLen = 4096;
        uint32_t headDim = 0;
        uint32_t numHeads = 0;
        VkDevice   device{ VK_NULL_HANDLE };
        VkPhysicalDevice physicalDevice{ VK_NULL_HANDLE };
    };

    class KVCache {
    public:
        KVCache() = default;
        ~KVCache();

        // Initialize KV cache for all layers
        bool init(const KVCacheConfig& config);

        // Allocate per-layer buffers
        bool allocateLayer(uint32_t layerIdx);

        // Write key/value for a token at a given position in a layer
        // keyData/valueData are float arrays of size numHeads * headDim
        bool write(uint32_t layerIdx, uint64_t tokenPos,
                   const float* keyData, const float* valueData);

        // Read key/value for all tokens up to position in a layer
        // Returns pointers into device memory (caller must handle synchronization)
        bool readKeys(uint32_t layerIdx, uint64_t numTokens, VkBuffer& outBuffer, uint64_t& outOffset) const;
        bool readValues(uint32_t layerIdx, uint64_t numTokens, VkBuffer& outBuffer, uint64_t& outOffset) const;

        uint64_t size(uint32_t layerIdx) const;
        uint64_t capacity(uint32_t layerIdx) const;
        bool isFull(uint32_t layerIdx) const;

        void clear();
        void clearLayer(uint32_t layerIdx);

        bool isInitialized() const { return m_initialized; }
        VkDevice device() const { return m_config.device; }

    private:
        KVCacheConfig m_config;
        std::vector<KVCacheLayer> m_layers;
        bool m_initialized = false;
        std::mutex m_mutex;

        bool createBuffer(VkDeviceSize size, VkBufferUsageFlags usage,
                          VkBuffer& buffer, VkDeviceMemory& memory);
    };

} // namespace Deep2Rom::Inference
