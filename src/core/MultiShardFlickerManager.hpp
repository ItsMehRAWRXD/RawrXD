#pragma once
#include "Deep2Types.hpp"
#include <vulkan/vulkan.h>
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
        MultiShardFlickerManager(const std::vector<TensorDescriptorMultiShard>& manifest_tensors, VkDevice device, VkPhysicalDevice gpu)
            : m_tensors(manifest_tensors), m_device(device), m_gpu(gpu) {
            ::GetSystemInfo(&m_sys_info);
        }

        ~MultiShardFlickerManager() {
            release_all_shards();
        }

        bool register_shard_file(uint32_t shard_id, const std::wstring& path) {
            std::lock_guard<std::mutex> lock(m_mutex);
            HANDLE h_file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h_file == INVALID_HANDLE_VALUE) return false;
            m_shard_files[shard_id] = h_file;
            return true;
        }

        MultiShardTensorView acquire_tensor_view(size_t tensor_id) {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto& desc = m_tensors[tensor_id];
            auto it = m_shard_files.find(desc.shard_id);
            if (it == m_shard_files.end() || it->second == INVALID_HANDLE_VALUE) return { nullptr, 0, nullptr, nullptr, 0 };
            HANDLE h_file = it->second;

            uint64_t granularity = m_sys_info.dwAllocationGranularity;
            uint64_t aligned_offset = desc.absolute_offset & ~(granularity - 1);
            uint64_t delta = desc.absolute_offset - aligned_offset;
            uint64_t map_size = delta + desc.tensor_bytes;

            HANDLE h_map = ::CreateFileMappingW(h_file, nullptr, PAGE_READONLY, static_cast<DWORD>(aligned_offset >> 32), static_cast<DWORD>(aligned_offset & 0xFFFFFFFF), nullptr);
            if (!h_map) return { nullptr, 0, nullptr, nullptr, 0 };

            void* base_ptr = ::MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, map_size);
            if (!base_ptr) {
                ::CloseHandle(h_map);
                return { nullptr, 0, nullptr, nullptr, 0 };
            }

            return { static_cast<const uint8_t*>(base_ptr) + delta, desc.tensor_bytes, h_map, base_ptr, desc.shard_id };
        }

        void release_tensor_view(const MultiShardTensorView& view) {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (view.view_base_ptr) ::UnmapViewOfFile(view.view_base_ptr);
            if (view.mapping_handle) ::CloseHandle(view.mapping_handle);
        }

        bool allocate_staging_slot(size_t size, VkBuffer& out_buffer, VkDeviceMemory& out_memory, void*& out_mapped_ptr) {
            VkBufferCreateInfo buffer_info{ VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
            buffer_info.size = size;
            buffer_info.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
            buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
            if (::vkCreateBuffer(m_device, &buffer_info, nullptr, &buffer) != VK_SUCCESS) return false;

            VkMemoryRequirements mem_reqs;
            ::vkGetBufferMemoryRequirements(m_device, buffer, &mem_reqs);
            VkPhysicalDeviceMemoryProperties mem_props;
            ::vkGetPhysicalDeviceMemoryProperties(m_gpu, &mem_props);
            
            uint32_t type_index = 0xFFFFFFFF;
            for (uint32_t i = 0; i < mem_props.memoryTypeCount; i++) {
                if ((mem_reqs.memoryTypeBits & (1 << i)) && (mem_props.memoryTypes[i].propertyFlags & (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) == (VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)) {
                    type_index = i; break;
                }
            }
            if (type_index == 0xFFFFFFFF) return false;

            VkMemoryAllocateInfo alloc_info{ VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
            alloc_info.allocationSize = mem_reqs.size;
            alloc_info.memoryTypeIndex = type_index;
            if (::vkAllocateMemory(m_device, &alloc_info, nullptr, &memory) != VK_SUCCESS) return false;

            ::vkBindBufferMemory(m_device, buffer, memory, 0);
            ::vkMapMemory(m_device, memory, 0, size, 0, &mapped_ptr);
            return true;
        }

        void free_staging_slot(VkBuffer buffer, VkDeviceMemory memory, void* mapped_ptr) {
            if (buffer) {
                ::vkUnmapMemory(m_device, memory);
                ::vkDestroyBuffer(m_device, buffer, nullptr);
                ::vkFreeMemory(m_device, memory, nullptr);
            }
        }

    private:
        void release_all_shards() {
            for (auto& pair : m_shard_files) {
                if (pair.second != INVALID_HANDLE_VALUE) ::CloseHandle(pair.second);
            }
            m_shard_files.clear();
        }

        std::unordered_map<uint32_t, HANDLE> m_shard_files;
        const std::vector<TensorDescriptorMultiShard>& m_tensors;
        VkDevice         m_device;
        VkPhysicalDevice m_gpu;
        SYSTEM_INFO      m_sys_info{};
        std::mutex       m_mutex;
    };
}