#pragma once
#include <windows.h>
#include <stdint.h>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <iostream>
#include <cstring>
#include <unordered_map>
#include "Win32RomEmulator.hpp"
#include "VulkanStagingPipeline.hpp"

namespace Deep2Engine::Emulator {

    using namespace Deep2Rom;

    // Side-channel descriptor info needed to resolve a tensor view at prefetch time.
    // TensorDescriptorMultiShard (in Win32RomEmulator.hpp) does not carry file_size,
    // which acquire_tensor() requires for bounds validation.
    struct TensorPrefetchInfo {
        uint32_t  shard_id = 0;
        uint64_t  absolute_offset = 0;
        uint64_t  tensor_bytes = 0;
        uint64_t  file_size = 0;
    };

    struct ShardedPrefetchTask {
        size_t          tensor_id;          // Index into the ROM manifest tensor table
        VkBuffer        dst_device_buffer;  // Target GPU VRAM buffer (VK_NULL_HANDLE = CPU only)
        VkQueue         dma_queue;          // Hardware transfer queue
        VkCommandBuffer cmd_buffer;         // One-time command buffer
    };

    class PrefetchQueue {
    public:
        // Construct with optional Vulkan staging pipeline. When staging is null,
        // prefetch performs a CPU-side memory-map touch only (no DMA).
        PrefetchQueue(MultiShardFlickerManager& flicker,
                      Compute::VulkanStagingPipeline* staging = nullptr)
            : m_flicker(flicker), m_staging(staging), m_shutdown(false) {
            m_worker_thread = std::thread(&PrefetchQueue::worker_processing_loop, this);
        }

        ~PrefetchQueue() {
            m_shutdown = true;
            m_cv.notify_all();
            if (m_worker_thread.joinable()) {
                m_worker_thread.join();
            }
        }

        // Submit a tensor for background prefetch with Vulkan DMA targets.
        void submit_task(size_t tensor_id,
                         VkBuffer dst = VK_NULL_HANDLE,
                         VkQueue q = VK_NULL_HANDLE,
                         VkCommandBuffer cmd = VK_NULL_HANDLE) {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            m_queue.push({ tensor_id, dst, q, cmd });
            m_cv.notify_all();
        }

        // Backward-compatible single-arg submit (CPU-side prefetch only)
        void submit_prefetch(size_t tensor_id, bool /*urgent*/ = false) {
            submit_task(tensor_id);
        }

        // Register tensor metadata so the worker can resolve shard/offset/bytes/file_size.
        void register_tensor_info(size_t tensor_id, const TensorPrefetchInfo& info) {
            std::lock_guard<std::mutex> lock(m_info_mutex);
            m_infos[tensor_id] = info;
        }

        size_t queue_size() const {
            std::lock_guard<std::mutex> lock(m_queue_mutex);
            return m_queue.size();
        }

    private:
        void worker_processing_loop() {
            while (!m_shutdown) {
                ShardedPrefetchTask task;
                {
                    std::unique_lock<std::mutex> lock(m_queue_mutex);
                    m_cv.wait(lock, [this]() { return !m_queue.empty() || m_shutdown; });

                    if (m_shutdown) break;

                    task = m_queue.front();
                    m_queue.pop();
                }

                // Resolve shard/offset/bytes/file_size from the registered info table.
                TensorPrefetchInfo info;
                {
                    std::lock_guard<std::mutex> lock(m_info_mutex);
                    auto it = m_infos.find(task.tensor_id);
                    if (it == m_infos.end()) {
                        std::cerr << "[-] Prefetch Error: No tensor info registered for "
                                  << task.tensor_id << "\n";
                        continue;
                    }
                    info = it->second;
                }

                // Acquire a bounded, 64KB-aligned view of the tensor from the shard file.
                MultiShardFlickerManager::ScopedView view = m_flicker.acquire_tensor(
                    info.shard_id, task.tensor_id,
                    info.absolute_offset, info.tensor_bytes,
                    info.file_size);

                if (!view.valid()) {
                    std::cerr << "[-] Prefetch Error: Unable to map tensor view for "
                              << task.tensor_id << " (shard " << info.shard_id
                              << ", offset " << info.absolute_offset
                              << ", bytes " << info.tensor_bytes
                              << ", file_size " << info.file_size << ")\n";
                    continue;
                }

                if (task.dst_device_buffer != VK_NULL_HANDLE &&
                    task.dma_queue != VK_NULL_HANDLE &&
                    task.cmd_buffer != VK_NULL_HANDLE &&
                    m_staging != nullptr) {

                    // Stage through host-coherent pinned memory, then DMA to VRAM
                    Compute::StagingSlot staging_slot;
                    if (m_staging->acquire_staging_buffer(view.size(), staging_slot)) {
                        std::memcpy(staging_slot.mapped_ptr, view.data(), view.size());

                        if (m_staging->enqueue_asynchronous_dma(
                                task.dma_queue, task.cmd_buffer,
                                staging_slot, task.dst_device_buffer, view.size())) {
                            ::vkQueueWaitIdle(task.dma_queue);
                        }

                        m_staging->release_staging_buffer(staging_slot);
                    } else {
                        std::cerr << "[-] Prefetch Error: Staging slot allocation failed\n";
                    }
                }
                // else: CPU-side memory-map touch only (pages brought into working set)

                // ScopedView auto-unmaps on destruction (RAII)
            }
        }

        MultiShardFlickerManager& m_flicker;
        Compute::VulkanStagingPipeline* m_staging;
        std::queue<ShardedPrefetchTask> m_queue;
        std::thread                   m_worker_thread;
        mutable std::mutex            m_queue_mutex;
        std::mutex                    m_info_mutex;
        std::condition_variable       m_cv;
        std::atomic<bool>             m_shutdown;
        std::unordered_map<size_t, TensorPrefetchInfo> m_infos;
    };
}
