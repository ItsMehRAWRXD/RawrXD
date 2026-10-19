#include "KVCache.hpp"
#include <iostream>
#include <cstring>
#include <algorithm>

namespace Deep2Rom::Inference {

    KVCache::~KVCache() {
        clear();
    }

    bool KVCache::init(const KVCacheConfig& config) {
        m_config = config;
        m_layers.resize(config.numLayers);
        for (uint32_t i = 0; i < config.numLayers; ++i) {
            m_layers[i].headDim = config.headDim;
            m_layers[i].numHeads = config.numHeads;
            m_layers[i].capacity = static_cast<uint64_t>(config.maxSeqLen);
        }
        m_initialized = true;
        std::cout << "[KVCache] Initialized " << config.numLayers
                  << " layers, maxSeqLen=" << config.maxSeqLen
                  << ", headDim=" << config.headDim
                  << ", numHeads=" << config.numHeads << std::endl;
        return true;
    }

    bool KVCache::allocateLayer(uint32_t layerIdx) {
        if (layerIdx >= m_config.numLayers) return false;

        auto& layer = m_layers[layerIdx];
        if (layer.keyBuffer != VK_NULL_HANDLE) return true; // Already allocated

        // Each token: numHeads * headDim floats for keys and same for values
        VkDeviceSize elementSize = static_cast<VkDeviceSize>(m_config.numHeads * m_config.headDim * sizeof(float));
        VkDeviceSize layerSize = elementSize * m_config.maxSeqLen;

        if (!createBuffer(layerSize,
                          VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                          layer.keyBuffer, layer.keyMemory)) {
            std::cerr << "[KVCache] Failed to allocate key buffer for layer " << layerIdx << std::endl;
            return false;
        }
        if (!createBuffer(layerSize,
                          VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT,
                          layer.valueBuffer, layer.valueMemory)) {
            std::cerr << "[KVCache] Failed to allocate value buffer for layer " << layerIdx << std::endl;
            return false;
        }

        layer.size = 0;
        std::cout << "[KVCache] Allocated layer " << layerIdx
                  << " (" << (layerSize * 2 / 1024 / 1024) << " MB)" << std::endl;
        return true;
    }

bool KVCache::createBuffer(VkDeviceSize size, VkBufferUsageFlags usage,
                           VkBuffer& buffer, VkDeviceMemory& memory) {
        // Null device: no-op allocation for CPU-only testing
        if (m_config.device == VK_NULL_HANDLE) {
            buffer = VK_NULL_HANDLE;
            memory = VK_NULL_HANDLE;
            return true;
        }

        VkBufferCreateInfo bi{ VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
        bi.size = size;
        bi.usage = usage;
        bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;

        if (vkCreateBuffer(m_config.device, &bi, nullptr, &buffer) != VK_SUCCESS) return false;

        VkMemoryRequirements mr;
        vkGetBufferMemoryRequirements(m_config.device, buffer, &mr);

        VkPhysicalDeviceMemoryProperties mp;
        vkGetPhysicalDeviceMemoryProperties(m_config.physicalDevice, &mp);

        uint32_t memType = 0xFFFFFFFF;
        for (uint32_t i = 0; i < mp.memoryTypeCount; ++i) {
            if ((mr.memoryTypeBits & (1u << i)) &&
                (mp.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) == VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                memType = i;
                break;
            }
        }
        if (memType == 0xFFFFFFFF) return false;

        VkMemoryAllocateInfo ai{ VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
        ai.allocationSize = mr.size;
        ai.memoryTypeIndex = memType;

        if (vkAllocateMemory(m_config.device, &ai, nullptr, &memory) != VK_SUCCESS) {
            vkDestroyBuffer(m_config.device, buffer, nullptr);
            buffer = VK_NULL_HANDLE;
            return false;
        }

        if (vkBindBufferMemory(m_config.device, buffer, memory, 0) != VK_SUCCESS) {
            vkDestroyBuffer(m_config.device, buffer, nullptr);
            vkFreeMemory(m_config.device, memory, nullptr);
            buffer = VK_NULL_HANDLE;
            memory = VK_NULL_HANDLE;
            return false;
        }

        return true;
    }

    bool KVCache::write(uint32_t layerIdx, uint64_t tokenPos,
                        const float* keyData, const float* valueData) {
        if (layerIdx >= m_config.numLayers) return false;
        if (!m_initialized) return false;

        std::lock_guard<std::mutex> lock(m_mutex);

        auto& layer = m_layers[layerIdx];
        if (layer.keyBuffer == VK_NULL_HANDLE) {
            if (!allocateLayer(layerIdx)) return false;
        }

        if (tokenPos >= layer.capacity) return false;

        VkDeviceSize elementSize = static_cast<VkDeviceSize>(m_config.numHeads * m_config.headDim * sizeof(float));
        VkDeviceSize offset = tokenPos * elementSize;

        // Null device: no-op write for CPU-only testing
        if (m_config.device == VK_NULL_HANDLE) {
            layer.size = std::max(layer.size, tokenPos + 1);
            return true;
        }

        // Copy key data
        void* dst = nullptr;
        if (vkMapMemory(m_config.device, layer.keyMemory, offset, elementSize, 0, &dst) != VK_SUCCESS) return false;
        memcpy(dst, keyData, elementSize);
        vkUnmapMemory(m_config.device, layer.keyMemory);

        // Copy value data
        if (vkMapMemory(m_config.device, layer.valueMemory, offset, elementSize, 0, &dst) != VK_SUCCESS) return false;
        memcpy(dst, valueData, elementSize);
        vkUnmapMemory(m_config.device, layer.valueMemory);

        layer.size = std::max(layer.size, tokenPos + 1);
        return true;
    }

    bool KVCache::readKeys(uint32_t layerIdx, uint64_t numTokens, VkBuffer& outBuffer, uint64_t& outOffset) const {
        if (layerIdx >= m_config.numLayers) return false;
        const auto& layer = m_layers[layerIdx];
        if (layer.keyBuffer == VK_NULL_HANDLE) return false;
        if (numTokens > layer.size) numTokens = layer.size;

        outBuffer = layer.keyBuffer;
        outOffset = 0; // Data starts at beginning of buffer
        return true;
    }

    bool KVCache::readValues(uint32_t layerIdx, uint64_t numTokens, VkBuffer& outBuffer, uint64_t& outOffset) const {
        if (layerIdx >= m_config.numLayers) return false;
        const auto& layer = m_layers[layerIdx];
        if (layer.valueBuffer == VK_NULL_HANDLE) return false;
        if (numTokens > layer.size) numTokens = layer.size;

        outBuffer = layer.valueBuffer;
        outOffset = 0;
        return true;
    }

    uint64_t KVCache::size(uint32_t layerIdx) const {
        if (layerIdx >= m_config.numLayers) return 0;
        return m_layers[layerIdx].size;
    }

    uint64_t KVCache::capacity(uint32_t layerIdx) const {
        if (layerIdx >= m_config.numLayers) return 0;
        return m_layers[layerIdx].capacity;
    }

    bool KVCache::isFull(uint32_t layerIdx) const {
        if (layerIdx >= m_config.numLayers) return true;
        return m_layers[layerIdx].size >= m_layers[layerIdx].capacity;
    }

    void KVCache::clear() {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& layer : m_layers) {
            if (layer.keyBuffer != VK_NULL_HANDLE) {
                vkDestroyBuffer(m_config.device, layer.keyBuffer, nullptr);
                vkFreeMemory(m_config.device, layer.keyMemory, nullptr);
                layer.keyBuffer = VK_NULL_HANDLE;
                layer.keyMemory = VK_NULL_HANDLE;
            }
            if (layer.valueBuffer != VK_NULL_HANDLE) {
                vkDestroyBuffer(m_config.device, layer.valueBuffer, nullptr);
                vkFreeMemory(m_config.device, layer.valueMemory, nullptr);
                layer.valueBuffer = VK_NULL_HANDLE;
                layer.valueMemory = VK_NULL_HANDLE;
            }
            layer.size = 0;
        }
        m_layers.clear();
        m_initialized = false;
    }

    void KVCache::clearLayer(uint32_t layerIdx) {
        if (layerIdx >= m_config.numLayers) return;
        std::lock_guard<std::mutex> lock(m_mutex);
        auto& layer = m_layers[layerIdx];
        if (layer.keyBuffer != VK_NULL_HANDLE) {
            vkDestroyBuffer(m_config.device, layer.keyBuffer, nullptr);
            vkFreeMemory(m_config.device, layer.keyMemory, nullptr);
            layer.keyBuffer = VK_NULL_HANDLE;
            layer.keyMemory = VK_NULL_HANDLE;
        }
        if (layer.valueBuffer != VK_NULL_HANDLE) {
            vkDestroyBuffer(m_config.device, layer.valueBuffer, nullptr);
            vkFreeMemory(m_config.device, layer.valueMemory, nullptr);
            layer.valueBuffer = VK_NULL_HANDLE;
            layer.valueMemory = VK_NULL_HANDLE;
        }
        layer.size = 0;
    }

} // namespace Deep2Rom::Inference
