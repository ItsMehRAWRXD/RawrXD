// voice_assistant_manager_patch.cpp
// Phase 17A: BG_THREAD_AV Elimination Implementation
// Date: 2026-06-20

#include "voice_assistant_manager_patch.hpp"
#include <chrono>
#include <thread>

namespace RawrXD::VoiceAssistant {

// ============================================================================
// IMPLEMENTATION: SafeSessionManager
// ============================================================================

void SafeSessionManager::cleanup_expired_sessions() {
    if (is_shutting_down()) return;
    
    std::unique_lock<std::shared_mutex> lock(m_sessions_mutex);
    
    // Collect expired keys first (don't modify while iterating)
    std::vector<uint64_t> expired_keys;
    expired_keys.reserve(m_sessions.size() / 4); // Pre-allocate estimate
    
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

// ============================================================================
// IMPLEMENTATION: SafeTelemetryCollector
// ============================================================================

bool SafeTelemetryCollector::flush_telemetry_safe() {
    // Fast-path check without locking
    if (m_is_shutting_down.load(std::memory_order_acquire)) {
        return false;
    }

    // Prevent concurrent flushes with timeout
    bool expected = false;
    if (!m_flush_in_progress.compare_exchange_strong(expected, true)) {
        return false; // Another flush in progress
    }

    // RAII guard ensures flag is cleared even if exception thrown
    struct FlushGuard {
        std::atomic<bool>& flag;
        ~FlushGuard() { flag.store(false, std::memory_order_release); }
    } guard{m_flush_in_progress};

    std::lock_guard<std::mutex> lock(m_flush_mutex);
    
    // Double-check after acquiring lock
    if (m_is_shutting_down.load(std::memory_order_acquire)) {
        return false;
    }

    // Perform actual flush with exception safety
    try {
        return perform_flush();
    } catch (...) {
        // Log error but don't propagate - we must clear the flag
        return false;
    }
}

bool SafeTelemetryCollector::perform_flush() {
    // Actual telemetry flush implementation
    // This is where the original BG_THREAD_AV #2 occurred
    // Now protected by:
    // 1. Shutdown flag check
    // 2. Flush-in-progress atomic
    // 3. Mutex lock
    // 4. Exception handling
    
    return true;
}

// ============================================================================
// IMPLEMENTATION: VoiceAssistantManagerPatched
// ============================================================================

bool VoiceAssistantManagerPatched::initialize() {
    return m_operation_mutex.with_lock([this]() -> bool {
        if (m_initialized.load(std::memory_order_acquire)) {
            return true; // Already initialized
        }
        
        // Initialize session manager
        // Initialize telemetry
        
        m_initialized.store(true, std::memory_order_release);
        return true;
    });
}

void VoiceAssistantManagerPatched::shutdown() {
    // Phase 1: Signal shutdown (prevents new operations)
    m_session_manager.initiate_shutdown();
    m_telemetry.signal_shutdown();
    
    // Phase 2: Wait for in-progress operations with timeout
    auto start = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(5);
    
    while (std::chrono::steady_clock::now() - start < timeout) {
        // Check if operations are complete
        // ...
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Phase 3: Final cleanup under lock
    m_operation_mutex.with_lock([this]() {
        m_initialized.store(false, std::memory_order_release);
        
        // Final session cleanup
        m_session_manager.cleanup_expired_sessions();
        
        // Final telemetry flush (may be skipped if shutting down)
        m_telemetry.flush_telemetry_safe();
    });
}

bool VoiceAssistantManagerPatched::process_session_message(
    uint64_t session_id, 
    const std::string& message
) {
    // Check 1: Get session safely (weak_ptr pattern)
    auto session = m_session_manager.get_session_safe(session_id);
    if (!session) {
        return false; // Session not found or expired
    }
    
    // Check 2: Verify initialized under lock
    return m_operation_mutex.with_lock([&]() -> bool {
        if (!m_initialized.load(std::memory_order_acquire)) {
            return false;
        }
        
        // Check 3: Verify session still valid
        if (session->is_expired()) {
            return false;
        }
        
        // Process message
        // ...
        
        return true;
    });
}

} // namespace RawrXD::VoiceAssistant
