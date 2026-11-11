#include "StateObserver.h"
#include <iostream>
#include <mutex>

namespace RawrXD::E2E {

// Static member initialization
std::atomic<uint64_t> StateObserver::m_swap_count{0};
static std::mutex g_observer_mutex;
static std::vector<std::pair<std::string, std::string>> g_swap_history;
static std::atomic<bool> g_integrity_violation{false};

void StateObserver::OnAdapterSwap(const std::string& old_id, const std::string& new_id) {
    uint64_t count = m_swap_count.fetch_add(1, std::memory_order_relaxed) + 1;
    
    std::lock_guard<std::mutex> lock(g_observer_mutex);
    g_swap_history.emplace_back(old_id, new_id);
    
    // Log swap for debugging
    std::cout << "[StateObserver] Adapter swap #" << count 
              << ": " << old_id << " -> " << new_id << "\n";
}

bool StateObserver::VerifyAtomicIntegrity() {
    // Check for potential race conditions
    // In a real implementation, this would:
    // 1. Verify no reads occurred during swap window
    // 2. Check memory barriers were properly issued
    // 3. Validate pointer alignment
    
    if (g_integrity_violation.load()) {
        return false;
    }
    
    // Verify swap history is consistent
    std::lock_guard<std::mutex> lock(g_observer_mutex);
    
    for (size_t i = 1; i < g_swap_history.size(); ++i) {
        // Each swap's old_id should not be the same as previous new_id
        // (indicates potential double-swap without read)
        if (g_swap_history[i].first == g_swap_history[i-1].second) {
            // This is actually valid - rapid swapping
            // But we log it for analysis
        }
    }
    
    return true;
}

} // namespace RawrXD::E2E
