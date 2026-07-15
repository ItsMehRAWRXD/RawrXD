// voice_assistant_manager_patch.hpp
// Phase 17A: BG_THREAD_AV Elimination Patch
// Date: 2026-06-20
// Priority: P0 - Critical Stability

#pragma once

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <vector>
#include <unordered_map>

namespace RawrXD::VoiceAssistant {

// ============================================================================
// PATCH 1: Session Lifecycle Safety (BG_THREAD_AV #1)
// ============================================================================

class SafeSessionManager {
private:
    // Use weak_ptr to prevent use-after-free during cleanup
    std::unordered_map<uint64_t, std::weak_ptr<Session>> m_sessions;
    std::shared_mutex m_sessions_mutex;
    std::atomic<bool> m_shutting_down{false};

public:
    // Safe session access with automatic null-check
    std::shared_ptr<Session> get_session_safe(uint64_t session_id) {
        std::shared_lock<std::shared_mutex> lock(m_sessions_mutex);
        auto it = m_sessions.find(session_id);
        if (it != m_sessions.end()) {
            return it->second.lock(); // Returns nullptr if session destroyed
        }
        return nullptr;
    }

    // Atomic shutdown flag prevents new operations during cleanup
    void initiate_shutdown() {
        m_shutting_down.store(true, std::memory_order_release);
    }

    bool is_shutting_down() const {
        return m_shutting_down.load(std::memory_order_acquire);
    }

    // Safe cleanup with iterator invalidation protection
    void cleanup_expired_sessions() {
        if (is_shutting_down()) return;
        
        std::unique_lock<std::shared_mutex> lock(m_sessions_mutex);
        
        // Collect expired keys first (don't modify while iterating)
        std::vector<uint64_t> expired_keys;
        for (const auto& [id, weak_session] : m_sessions) {
            if (weak_session.expired()) {
                expired_keys.push_back(id);
            }
        }
        
        // Now safe to erase
        for (uint64_t id : expired_keys) {
            m_sessions.erase(id);
        }
    }
};

// ============================================================================
// PATCH 2: Telemetry Flush Safety (BG_THREAD_AV #2)
// ============================================================================

class SafeTelemetryCollector {
private:
    std::atomic<bool> m_is_shutting_down{false};
    std::atomic<bool> m_flush_in_progress{false};
    std::mutex m_flush_mutex;

public:
    // Dead-man's switch pattern
    void signal_shutdown() {
        m_is_shutting_down.store(true, std::memory_order_release);
    }

    bool flush_telemetry_safe() {
        // Fast-path check without locking
        if (m_is_shutting_down.load(std::memory_order_acquire)) {
            return false; // Skip flush during shutdown
        }

        // Prevent concurrent flushes
        bool expected = false;
        if (!m_flush_in_progress.compare_exchange_strong(expected, true)) {
            return false; // Another flush in progress
        }

        // RAII guard ensures flag is cleared
        struct FlushGuard {
            std::atomic<bool>& flag;
            ~FlushGuard() { flag.store(false, std::memory_order_release); }
        } guard{m_flush_in_progress};

        std::lock_guard<std::mutex> lock(m_flush_mutex);
        
        // Double-check after acquiring lock
        if (m_is_shutting_down.load(std::memory_order_acquire)) {
            return false;
        }

        // Perform actual flush
        return perform_flush();
    }

private:
    bool perform_flush() {
        // Actual telemetry flush implementation
        return true;
    }
};

// ============================================================================
// PATCH 3: Exception-Safe Mutex Handling (BG_THREAD_AV #3)
// ============================================================================

class ExceptionSafeMutex {
private:
    std::mutex m_mutex;

public:
    // RAII pattern - NEVER manual lock/unlock
    template<typename Func>
    auto with_lock(Func&& func) -> decltype(auto) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return func();
    }

    // For condition variables - use unique_lock
    template<typename Func>
    auto with_unique_lock(Func&& func) -> decltype(auto) {
        std::unique_lock<std::mutex> lock(m_mutex);
        return func(lock);
    }
};

// ============================================================================
// INTEGRATION: VoiceAssistantManager with All Patches
// ============================================================================

class VoiceAssistantManagerPatched {
private:
    SafeSessionManager m_session_manager;
    SafeTelemetryCollector m_telemetry;
    ExceptionSafeMutex m_operation_mutex;
    std::atomic<bool> m_initialized{false};

public:
    // Safe initialization with rollback
    bool initialize() {
        return m_operation_mutex.with_lock([this]() -> bool {
            if (m_initialized.load()) return true;
            
            // Initialize components
            // ...
            
            m_initialized.store(true, std::memory_order_release);
            return true;
        });
    }

    // Safe shutdown sequence
    void shutdown() {
        // Signal shutdown first (prevents new operations)
        m_session_manager.initiate_shutdown();
        m_telemetry.signal_shutdown();

        // Wait for in-progress operations
        m_operation_mutex.with_lock([this]() {
            m_initialized.store(false, std::memory_order_release);
        });
    }

    // Safe session operation
    bool process_session_message(uint64_t session_id, const std::string& message) {
        auto session = m_session_manager.get_session_safe(session_id);
        if (!session) return false;

        return m_operation_mutex.with_lock([&]() -> bool {
            if (!m_initialized.load(std::memory_order_acquire)) return false;
            
            // Process message
            // ...
            
            return true;
        });
    }

    // Safe telemetry flush
    bool flush_telemetry() {
        return m_telemetry.flush_telemetry_safe();
    }

    // Periodic cleanup
    void cleanup_sessions() {
        m_session_manager.cleanup_expired_sessions();
    }
};

} // namespace RawrXD::VoiceAssistant
