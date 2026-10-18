#pragma once
#include "MultiShardFlickerManager.hpp"
#include <vulkan/vulkan.h>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace Deep2Rom::Compute {

    struct PrefetchTask {
        size_t tensor_id;
        VkBuffer dst_vram_buffer;
        VkQueue dma_queue;
        VkCommandBuffer cmd_buf;
    };

    class PrefetchQueue {
    public:
        PrefetchQueue(MultiShardFlickerManager& manager);
        ~PrefetchQueue();

        void submit_prefetch(size_t tensor_id, VkBuffer dst, VkQueue q, VkCommandBuffer cmd);

    private:
        void worker_loop();

        MultiShardFlickerManager& m_flicker_manager;
        std::queue<PrefetchTask>  m_queue;
        std::thread               m_worker;
        std::mutex                m_mutex;
        std::condition_variable   m_cv;
        std::atomic<bool>         m_shutdown;
    };
}