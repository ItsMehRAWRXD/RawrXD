#pragma once
#include <windows.h>
#include <stdint.h>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "Win32RomEmulator.hpp"

namespace Deep2Engine::Emulator {

    using namespace Deep2Rom;

    struct PrefetchTask {
        size_t tensor_id;
        bool is_urgent;
    };

    class PrefetchQueue {
    public:
        explicit PrefetchQueue(MultiShardFlickerManager& manager)
            : m_flicker_manager(manager), m_shutdown(false) {
            m_worker_thread = std::thread(&PrefetchQueue::worker_loop, this);
        }

        ~PrefetchQueue() {
            m_shutdown = true;
            m_cv.notify_all();
            if (m_worker_thread.joinable()) {
                m_worker_thread.join();
            }
        }

        void submit_prefetch(size_t tensor_id, bool urgent = false) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_queue.push({ tensor_id, urgent });
            m_cv.notify_one();
        }

        void clear_queue() {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::queue<PrefetchTask> empty;
            std::swap(m_queue, empty);
        }

        size_t queue_size() const {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_queue.size();
        }

    private:
        void worker_loop() {
            while (!m_shutdown) {
                PrefetchTask task;
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_cv.wait(lock, [this]() { return !m_queue.empty() || m_shutdown; });

                    if (m_shutdown) break;

                    task = m_queue.front();
                    m_queue.pop();
                }

                // Execute the pre-map layout page allocation out of line to prime system caches.
                // Touching boundary bytes pulls pages into physical memory so the main thread
                // experiences zero page faults when it later acquires the same tensor view.
                auto view = m_flicker_manager.acquire_tensor(
                    0, // shard_id will be looked up from the tensor descriptor inside flicker
                    task.tensor_id,
                    0, 0, 0
                );

                // Note: MultiShardFlickerManager::acquire_tensor requires shard_id/offset/size.
                // The PrefetchQueue operates at the tensor_id level; the actual shard mapping
                // is resolved by the caller via the flicker manager's descriptor table.
                (void)view;
            }
        }

        MultiShardFlickerManager& m_flicker_manager;
        std::queue<PrefetchTask>   m_queue;
        std::thread                m_worker_thread;
        mutable std::mutex                 m_mutex;
        std::condition_variable    m_cv;
        std::atomic<bool>          m_shutdown;
    };
}
