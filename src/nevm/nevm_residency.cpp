//============================================================================
// nevm_residency.cpp
// RawrXD N-EVM Residency State Machine - Implementation
//============================================================================

#include "nevm_residency.hpp"
#include <algorithm>

namespace RawrXD {
namespace NEVM {

//============================================================================
// State Machine Transitions
//============================================================================

const char* ResidencyStateToString(ResidencyState state) {
    switch (state) {
        case ResidencyState::INVALID: return "INVALID";
        case ResidencyState::COLD: return "COLD";
        case ResidencyState::MAPPED: return "MAPPED";
        case ResidencyState::COMPRESSED: return "COMPRESSED";
        case ResidencyState::CONVERTING: return "CONVERTING";
        case ResidencyState::PREFETCHING: return "PREFETCHING";
        case ResidencyState::RESIDENT_FAST: return "RESIDENT_FAST";
        case ResidencyState::UPGRADING: return "UPGRADING";
        case ResidencyState::DOWNGRADING: return "DOWNGRADING";
        case ResidencyState::EVICTING: return "EVICTING";
        case ResidencyState::PINNED: return "PINNED";
        default: return "UNKNOWN";
    }
}

bool ResidencyStateMachine::CanTransition(ResidencyState from, ResidencyState to) {
    // Define valid transitions
    switch (from) {
        case ResidencyState::INVALID:
            return to == ResidencyState::COLD || 
                   to == ResidencyState::MAPPED;
            
        case ResidencyState::COLD:
            return to == ResidencyState::MAPPED ||
                   to == ResidencyState::PREFETCHING;
            
        case ResidencyState::MAPPED:
            return to == ResidencyState::COMPRESSED ||
                   to == ResidencyState::RESIDENT_FAST ||
                   to == ResidencyState::PREFETCHING;
            
        case ResidencyState::COMPRESSED:
            return to == ResidencyState::CONVERTING ||
                   to == ResidencyState::UPGRADING ||
                   to == ResidencyState::EVICTING ||
                   to == ResidencyState::PINNED;
            
        case ResidencyState::CONVERTING:
            return to == ResidencyState::RESIDENT_FAST ||
                   to == ResidencyState::COMPRESSED;  // Failed conversion
            
        case ResidencyState::PREFETCHING:
            return to == ResidencyState::COMPRESSED ||
                   to == ResidencyState::RESIDENT_FAST ||
                   to == ResidencyState::INVALID;  // Failed prefetch
            
        case ResidencyState::RESIDENT_FAST:
            return to == ResidencyState::DOWNGRADING ||
                   to == ResidencyState::EVICTING ||
                   to == ResidencyState::PINNED;
            
        case ResidencyState::UPGRADING:
            return to == ResidencyState::RESIDENT_FAST ||
                   to == ResidencyState::COMPRESSED;  // Failed upgrade
            
        case ResidencyState::DOWNGRADING:
            return to == ResidencyState::COMPRESSED ||
                   to == ResidencyState::RESIDENT_FAST;  // Failed downgrade
            
        case ResidencyState::EVICTING:
            return to == ResidencyState::COLD ||
                   to == ResidencyState::MAPPED;
            
        case ResidencyState::PINNED:
            return to == ResidencyState::RESIDENT_FAST ||
                   to == ResidencyState::COMPRESSED;  // After unpin
            
        default:
            return false;
    }
}

std::vector<ResidencyState> ResidencyStateMachine::GetValidTransitions(ResidencyState from) {
    std::vector<ResidencyState> valid;
    
    for (int i = 0; i <= static_cast<int>(ResidencyState::PINNED); ++i) {
        ResidencyState to = static_cast<ResidencyState>(i);
        if (CanTransition(from, to)) {
            valid.push_back(to);
        }
    }
    
    return valid;
}

bool ResidencyStateMachine::IsReadable(ResidencyState state) {
    return state == ResidencyState::COMPRESSED ||
           state == ResidencyState::RESIDENT_FAST ||
           state == ResidencyState::PINNED;
}

bool ResidencyStateMachine::IsWritable(ResidencyState state) {
    return state == ResidencyState::RESIDENT_FAST ||
           state == ResidencyState::PINNED;
}

bool ResidencyStateMachine::IsTransitional(ResidencyState state) {
    return state == ResidencyState::CONVERTING ||
           state == ResidencyState::PREFETCHING ||
           state == ResidencyState::UPGRADING ||
           state == ResidencyState::DOWNGRADING ||
           state == ResidencyState::EVICTING;
}

bool ResidencyStateMachine::IsStable(ResidencyState state) {
    return IsReadable(state) || state == ResidencyState::COLD ||
           state == ResidencyState::MAPPED;
}

//============================================================================
// TensorBlockResidency Implementation
//============================================================================

bool TensorBlockResidency::WaitForTransition(uint64_t timeout_ms) {
    std::unique_lock<std::mutex> lock(transition_mutex);
    
    bool result = transition_cv.wait_for(lock, 
                                          std::chrono::milliseconds(timeout_ms),
                                          [this] { 
                                              return transition_complete || 
                                                     IsStable(state.load()); 
                                          });
    
    return result;
}

void TensorBlockResidency::NotifyTransitionComplete() {
    {
        std::lock_guard<std::mutex> lock(transition_mutex);
        transition_complete = true;
    }
    transition_cv.notify_all();
}

//============================================================================
// ResidencyManager Implementation
//============================================================================

ResidencyManager::ResidencyManager() {}

ResidencyManager::~ResidencyManager() {
    // All blocks should be cleaned up
}

bool ResidencyManager::RegisterBlock(VirtualTensorAddress vta) {
    uint64_t key = vta.BlockKey();
    
    std::unique_lock<std::shared_mutex> lock(blocks_mutex_);
    
    if (blocks_.find(key) != blocks_.end()) {
        return false;  // Already registered
    }
    
    auto block = std::make_unique<TensorBlockResidency>();
    block->vta = vta;
    block->state = ResidencyState::COLD;
    
    blocks_[key] = std::move(block);
    return true;
}

bool ResidencyManager::UnregisterBlock(VirtualTensorAddress vta) {
    uint64_t key = vta.BlockKey();
    
    std::unique_lock<std::shared_mutex> lock(blocks_mutex_);
    
    auto it = blocks_.find(key);
    if (it == blocks_.end()) {
        return false;
    }
    
    // Check if block can be removed
    auto state = it->second->state.load();
    if (state == ResidencyState::PINNED ||
        ResidencyStateMachine::IsTransitional(state)) {
        return false;
    }
    
    blocks_.erase(it);
    return true;
}

bool ResidencyManager::RequestTransition(VirtualTensorAddress vta,
                                          ResidencyState target_state,
                                          PrecisionMode target_format) {
    uint64_t key = vta.BlockKey();
    
    TensorBlockResidency* block = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(blocks_mutex_);
        auto it = blocks_.find(key);
        if (it == blocks_.end()) {
            return false;
        }
        block = it->second.get();
    }
    
    ResidencyState current = block->state.load();
    
    // Check if already in target state
    if (current == target_state) {
        return true;
    }
    
    // Check if transition is valid
    if (!ResidencyStateMachine::CanTransition(current, target_state)) {
        return false;
    }
    
    // Attempt atomic transition
    ResidencyState expected = current;
    if (!block->state.compare_exchange_strong(expected, target_state)) {
        // Another thread changed state
        return false;
    }
    
    // Set target format for conversion states
    if (target_state == ResidencyState::UPGRADING ||
        target_state == ResidencyState::DOWNGRADING ||
        target_state == ResidencyState::CONVERTING) {
        block->target_format = target_format;
        block->transition_complete = false;
    }
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.transitions_requested++;
    }
    
    return true;
}

ResidencyState ResidencyManager::GetState(VirtualTensorAddress vta) const {
    uint64_t key = vta.BlockKey();
    
    std::shared_lock<std::shared_mutex> lock(blocks_mutex_);
    auto it = blocks_.find(key);
    if (it == blocks_.end()) {
        return ResidencyState::INVALID;
    }
    
    return it->second->state.load();
}

void* ResidencyManager::WaitForReadable(VirtualTensorAddress vta, uint64_t timeout_ms) {
    uint64_t key = vta.BlockKey();
    
    TensorBlockResidency* block = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(blocks_mutex_);
        auto it = blocks_.find(key);
        if (it == blocks_.end()) {
            return nullptr;
        }
        block = it->second.get();
    }
    
    auto start = GetTick();
    
    while (GetTick() - start < timeout_ms) {
        ResidencyState state = block->state.load();
        
        if (ResidencyStateMachine::IsReadable(state)) {
            block->access_count.fetch_add(1);
            block->last_access_tick.store(GetTick());
            return block->physical_ptr;
        }
        
        if (ResidencyStateMachine::IsTransitional(state)) {
            // Wait for transition
            if (!block->WaitForTransition(timeout_ms - (GetTick() - start))) {
                return nullptr;  // Timeout
            }
        } else {
            // Not readable and not transitioning - need to initiate transition
            // This would typically be handled by a higher-level manager
            std::this_thread::sleep_for(std::chrono::microseconds(10));
        }
    }
    
    return nullptr;  // Timeout
}

bool ResidencyManager::IsReadable(VirtualTensorAddress vta) const {
    return ResidencyStateMachine::IsReadable(GetState(vta));
}

bool ResidencyManager::PinBlock(VirtualTensorAddress vta) {
    return RequestTransition(vta, ResidencyState::PINNED);
}

bool ResidencyManager::UnpinBlock(VirtualTensorAddress vta) {
    // Return to previous state (simplified: always go to RESIDENT_FAST)
    return RequestTransition(vta, ResidencyState::RESIDENT_FAST);
}

void ResidencyManager::RecordAccess(VirtualTensorAddress vta, bool is_write) {
    uint64_t key = vta.BlockKey();
    
    std::shared_lock<std::shared_mutex> lock(blocks_mutex_);
    auto it = blocks_.find(key);
    if (it != blocks_.end()) {
        it->second->access_count.fetch_add(1);
        it->second->last_access_tick.store(GetTick());
        
        if (is_write) {
            it->second->pending_writes.fetch_add(1);
        } else {
            it->second->pending_reads.fetch_add(1);
        }
    }
}

const TensorBlockResidency* ResidencyManager::GetBlockInfo(VirtualTensorAddress vta) const {
    uint64_t key = vta.BlockKey();
    
    std::shared_lock<std::shared_mutex> lock(blocks_mutex_);
    auto it = blocks_.find(key);
    if (it != blocks_.end()) {
        return it->second.get();
    }
    return nullptr;
}

ResidencyManager::Stats ResidencyManager::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

uint64_t ResidencyManager::GetTick() const {
    return GetTickCount64();
}

//============================================================================
// DependencyGraphPrefetcher Implementation
//============================================================================

bool DependencyGraphPrefetcher::BuildGraph(const std::vector<TensorDependency>& dependencies) {
    std::lock_guard<std::mutex> lock(graph_mutex_);
    
    graph_.clear();
    
    for (const auto& dep : dependencies) {
        graph_[dep.vta.BlockKey()] = dep;
    }
    
    // Build reverse dependencies (required_by)
    for (auto& [key, dep] : graph_) {
        for (const auto& required : dep.depends_on) {
            auto it = graph_.find(required.BlockKey());
            if (it != graph_.end()) {
                it->second.required_by.push_back(dep.vta);
            }
        }
    }
    
    return true;
}

std::vector<VirtualTensorAddress> DependencyGraphPrefetcher::GetPrefetchCandidates(
    const std::vector<VirtualTensorAddress>& currently_executing,
    uint32_t horizon_distance) {
    
    std::lock_guard<std::mutex> lock(graph_mutex_);
    
    std::vector<VirtualTensorAddress> candidates;
    std::set<uint64_t> visited;
    
    // BFS from currently executing tensors
    std::queue<std::pair<VirtualTensorAddress, uint32_t>> queue;
    
    for (const auto& vta : currently_executing) {
        queue.push({vta, 0});
        visited.insert(vta.BlockKey());
    }
    
    while (!queue.empty()) {
        auto [current, distance] = queue.front();
        queue.pop();
        
        if (distance >= horizon_distance) {
            continue;
        }
        
        auto it = graph_.find(current.BlockKey());
        if (it == graph_.end()) {
            continue;
        }
        
        // Add tensors that depend on current
        for (const auto& required : it->second.required_by) {
            uint64_t key = required.BlockKey();
            if (visited.find(key) == visited.end()) {
                visited.insert(key);
                candidates.push_back(required);
                queue.push({required, distance + 1});
            }
        }
        
        // Also add tensors at next compute stage
        for (const auto& [key, dep] : graph_) {
            if (dep.compute_stage == it->second.compute_stage + 1) {
                if (visited.find(key) == visited.end()) {
                    visited.insert(key);
                    candidates.push_back(dep.vta);
                }
            }
        }
    }
    
    // Sort by criticality (higher first)
    std::sort(candidates.begin(), candidates.end(),
              [this](VirtualTensorAddress a, VirtualTensorAddress b) {
                  auto it_a = graph_.find(a.BlockKey());
                  auto it_b = graph_.find(b.BlockKey());
                  if (it_a != graph_.end() && it_b != graph_.end()) {
                      return it_a->second.criticality > it_b->second.criticality;
                  }
                  return false;
              });
    
    return candidates;
}

std::vector<VirtualTensorAddress> DependencyGraphPrefetcher::GetCriticalPath(
    VirtualTensorAddress target) {
    
    std::lock_guard<std::mutex> lock(graph_mutex_);
    
    std::vector<VirtualTensorAddress> path;
    std::set<uint64_t> visited;
    
    std::function<void(VirtualTensorAddress)> dfs = [&](VirtualTensorAddress vta) {
        uint64_t key = vta.BlockKey();
        if (visited.find(key) != visited.end()) {
            return;
        }
        visited.insert(key);
        
        auto it = graph_.find(key);
        if (it == graph_.end()) {
            return;
        }
        
        // Visit dependencies first
        for (const auto& dep : it->second.depends_on) {
            dfs(dep);
        }
        
        path.push_back(vta);
    };
    
    dfs(target);
    return path;
}

void DependencyGraphPrefetcher::UpdateCriticality(VirtualTensorAddress vta, 
                                                     float measured_impact) {
    std::lock_guard<std::mutex> lock(graph_mutex_);
    
    auto it = graph_.find(vta.BlockKey());
    if (it != graph_.end()) {
        // Exponential moving average
        float alpha = 0.1f;
        it->second.criticality = alpha * measured_impact + (1.0f - alpha) * it->second.criticality;
    }
}

} // namespace NEVM
} // namespace RawrXD
