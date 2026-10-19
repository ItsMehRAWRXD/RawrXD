#pragma once
#include "Deep2Types.hpp"
#include <vulkan/vulkan.h>
#include <windows.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>

namespace Deep2Rom::Compute {

    struct MultiShardTensorView {
        const uint8_t* ptr;
        size_t         size;
        HANDLE         mapping_handle;
        void*          view_base_ptr;
        uint32_t       shard_id;
    };

    struct StagingBufferSlot {
        VkBuffer       buffer{ VK_NULL_HANDLE };
        VkDeviceMemory memory{ VK_NULL_HANDLE };
        void*          mapped_ptr{ nullptr };
        size_t         allocated_size{ 0 };
        bool           is_free{ true };
    };

    class MultiShardFlickerManager {
    public:
        MultiShardFlickerManager(const std::vector<TensorDescriptorMultiShard>& manifest_tensors, VkDevice device, VkPhysicalDevice gpu);
        ~MultiShardFlickerManager();

        bool register_shard_file(uint32_t shard_id, const std::wstring& path);

        struct MultiShardTensorView acquire_tensor_view(size_t tensor_id);

        void release_tensor_view(const struct MultiShardTensorView& view);

        bool allocate_staging_slot(size_t size, VkBuffer& out_buffer, VkDeviceMemory& out_memory, void*& out_mapped_ptr);

        void free_staging_slot(VkBuffer buffer, VkDeviceMemory memory, void* mapped_ptr);

    private:
        void release_all_shards();

        std::unordered_map<uint32_t, HANDLE> m_shard_files;
        const std::vector<TensorDescriptorMultiShard>& m_tensors;
        VkDevice         m_device;
        VkPhysicalDevice m_gpu;
        SYSTEM_INFO      m_sys_info{};
        std::mutex       m_mutex;
    };
}