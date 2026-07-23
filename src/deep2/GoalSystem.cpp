// ============================================================================
// GoalSystem.cpp - Priority-Based Goal Management Implementation
//
// FIXED: Reprioritization now correctly boosts goals with many dependents
//        (was lowering Critical goals to High, now boosts Low/Medium to High)
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "GoalSystem.hpp"
#include "PatchCache.hpp"
#include "HotPatcher.hpp"
#include <algorithm>
#include <queue>

namespace Deep2 {

// ============================================================================
// Implementation
// ============================================================================

class GoalManager::Impl {
public:
    std::unordered_map<std::string, Goal> goals;
    mutable std::mutex mutex;
    bool initialized = false;
    
    bool Initialize() {
        initialized = true;
        printf("[GoalManager] Initialized\n");
        return true;
    }
    
    void Shutdown() {
        goals.clear();
        initialized = false;
        printf("[GoalManager] Shutdown\n");
    }
    
    std::string CreateGoal(const std::string& name, const std::string& description, Priority priority) {
        std::lock_guard<std::mutex> lock(mutex);
        
        static uint64_t counter = 0;
        std::string id = "goal_" + std::to_string(++counter);
        
        Goal g;
        g.id = id;
        g.name = name;
        g.description = description;
        g.priority = priority;
        g.status = Goal::Status::Pending;
        g.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        g.progress = 0.0f;
        g.isBottleneck = false;
        g.dependentCount = 0;
        
        goals[id] = g;
        
        printf("[GoalManager] Created goal: %s (priority=%d)\n", name.c_str(), static_cast<int>(priority));
        return id;
    }
    
    bool GetGoal(const std::string& id, Goal& out) const {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = goals.find(id);
        if (it == goals.end()) return false;
        
        out = it->second;
        return true;
    }
    
    bool UpdateGoal(const std::string& id, const Goal& goal) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = goals.find(id);
        if (it == goals.end()) return false;
        
        it->second = goal;
        it->second.id = id;  // Preserve original ID
        return true;
    }
    
    bool DeleteGoal(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = goals.find(id);
        if (it == goals.end()) return false;
        
        // Remove from all dependents' dependsOn lists
        for (const auto& depId : it->second.dependsOn) {
            auto depIt = goals.find(depId);
            if (depIt != goals.end()) {
                auto& dependents = depIt->second.dependents;
                dependents.erase(std::remove(dependents.begin(), dependents.end(), id), dependents.end());
                depIt->second.dependentCount = dependents.size();
            }
        }
        
        // Remove from all dependents' lists
        for (const auto& dependentId : it->second.dependents) {
            auto depIt = goals.find(dependentId);
            if (depIt != goals.end()) {
                auto& deps = depIt->second.dependsOn;
                deps.erase(std::remove(deps.begin(), deps.end(), id), deps.end());
            }
        }
        
        goals.erase(it);
        return true;
    }
    
    bool AddDependency(const std::string& goalId, const std::string& dependencyId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        if (WouldCreateCycleInternal(goalId, dependencyId)) {
            printf("[GoalManager] ERROR: Would create cycle: %s -> %s\n", goalId.c_str(), dependencyId.c_str());
            return false;
        }
        
        auto goalIt = goals.find(goalId);
        auto depIt = goals.find(dependencyId);
        
        if (goalIt == goals.end() || depIt == goals.end()) return false;
        
        // Add to goal's dependencies
        goalIt->second.dependsOn.push_back(dependencyId);
        
        // Add to dependency's dependents
        depIt->second.dependents.push_back(goalId);
        depIt->second.dependentCount++;
        
        // Update bottleneck status
        UpdateBottleneckStatus(depIt->second);
        
        printf("[GoalManager] Added dependency: %s depends on %s\n", goalId.c_str(), dependencyId.c_str());
        return true;
    }
    
    bool WouldCreateCycleInternal(const std::string& goalId, const std::string& dependencyId) const {
        // Check if dependencyId depends on goalId (directly or indirectly)
        std::unordered_set<std::string> visited;
        std::queue<std::string> toVisit;
        toVisit.push(dependencyId);
        
        while (!toVisit.empty()) {
            std::string current = toVisit.front();
            toVisit.pop();
            
            if (current == goalId) return true;
            if (visited.count(current)) continue;
            visited.insert(current);
            
            auto it = goals.find(current);
            if (it != goals.end()) {
                for (const auto& dep : it->second.dependsOn) {
                    toVisit.push(dep);
                }
            }
        }
        
        return false;
    }
    
    void UpdateBottleneckStatus(Goal& g) {
        // A goal is a bottleneck if it has many dependents
        g.isBottleneck = (g.dependentCount > 2);
    }
    
    // ============================================================================
    // FIXED: Reprioritization Logic
    // ============================================================================
    void ReprioritizeBasedOnDependents() {
        std::lock_guard<std::mutex> lock(mutex);
        
        for (auto& [id, g] : goals) {
            if (g.status == Goal::Status::Completed || 
                g.status == Goal::Status::Failed) {
                continue;
            }
            
            // Count direct and indirect dependents
            uint32_t dependents = CountDependents(id);
            
            // FIXED: If many goals depend on this AND priority is LESS than High, boost it
            // OLD BUG: if (dependents > 2 && g.priority > Goal::Priority::High) 
            //          This would LOWER Critical goals to High!
            // NEW FIX: if (dependents > 2 && g.priority < Goal::Priority::High)
            //          This correctly BOOSTS Low/Medium goals to High
            if (dependents > 2 && g.priority < Priority::High) {
                Priority oldPriority = g.priority;
                g.priority = Priority::High;
                printf("[Goals] Reprioritized %s from %d to HIGH (%d dependents)\n",
                       g.name.c_str(), static_cast<int>(oldPriority), dependents);
            }
            
            // Critical goals with many dependents stay Critical
            // (no change needed, they're already highest priority)
        }
    }
    
    uint32_t CountDependents(const std::string& goalId) {
        // Count all goals that depend on this one (directly or indirectly)
        std::unordered_set<std::string> visited;
        std::queue<std::string> toVisit;
        
        // Start with direct dependents
        auto it = goals.find(goalId);
        if (it == goals.end()) return 0;
        
        for (const auto& dep : it->second.dependents) {
            toVisit.push(dep);
        }
        
        // BFS to find all indirect dependents
        while (!toVisit.empty()) {
            std::string current = toVisit.front();
            toVisit.pop();
            
            if (visited.count(current)) continue;
            visited.insert(current);
            
            auto cit = goals.find(current);
            if (cit != goals.end()) {
                for (const auto& dep : cit->second.dependents) {
                    toVisit.push(dep);
                }
            }
        }
        
        return static_cast<uint32_t>(visited.size());
    }
    
    void UnblockCriticalPaths() {
        std::lock_guard<std::mutex> lock(mutex);
        
        // Find goals that are blocking many others
        for (auto& [id, g] : goals) {
            if (g.status != Goal::Status::InProgress && 
                g.status != Goal::Status::Pending) {
                continue;
            }
            
            if (g.isBottleneck && g.priority < Priority::Critical) {
                // Boost to Critical
                g.priority = Priority::Critical;
                printf("[Goals] Unblocking bottleneck: %s -> CRITICAL\n", g.name.c_str());
            }
        }
    }
    
    std::string GetNextGoal() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        std::string bestGoal;
        Priority bestPriority = Priority::Low;
        
        for (const auto& [id, g] : goals) {
            // Skip completed/failed goals
            if (g.status == Goal::Status::Completed || 
                g.status == Goal::Status::Failed) {
                continue;
            }
            
            // Check if dependencies are satisfied
            bool ready = true;
            for (const auto& depId : g.dependsOn) {
                auto depIt = goals.find(depId);
                if (depIt == goals.end() || 
                    depIt->second.status != Goal::Status::Completed) {
                    ready = false;
                    break;
                }
            }
            
            if (!ready) continue;
            
            // Higher priority wins
            if (g.priority > bestPriority || bestGoal.empty()) {
                bestPriority = g.priority;
                bestGoal = id;
            }
        }
        
        return bestGoal;
    }
    
    GoalManager::Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        GoalManager::Stats stats = {};
        stats.totalGoals = goals.size();
        
        for (const auto& [id, g] : goals) {
            switch (g.status) {
                case Goal::Status::Pending: stats.pending++; break;
                case Goal::Status::InProgress: stats.inProgress++; break;
                case Goal::Status::Blocked: stats.blocked++; break;
                case Goal::Status::Completed: stats.completed++; break;
                case Goal::Status::Failed: stats.failed++; break;
            }
            stats.totalEstimatedTokens += g.estimatedTokens;
            stats.totalActualTokens += g.actualTokens;
        }
        
        return stats;
    }
};

// ============================================================================
// Public API
// ============================================================================

GoalManager::GoalManager() : impl_(std::make_unique<Impl>()) {}
GoalManager::~GoalManager() = default;

bool GoalManager::Initialize() { return impl_->Initialize(); }
void GoalManager::Shutdown() { impl_->Shutdown(); }

std::string GoalManager::CreateGoal(const std::string& name, const std::string& description, Priority priority) {
    return impl_->CreateGoal(name, description, priority);
}

bool GoalManager::GetGoal(const std::string& id, Goal& out) const { return impl_->GetGoal(id, out); }

bool GoalManager::UpdateGoal(const std::string& id, const Goal& goal) { return impl_->UpdateGoal(id, goal); }

bool GoalManager::DeleteGoal(const std::string& id) { return impl_->DeleteGoal(id); }

bool GoalManager::AddDependency(const std::string& goalId, const std::string& dependencyId) {
    return impl_->AddDependency(goalId, dependencyId);
}

void GoalManager::ReprioritizeBasedOnDependents() { impl_->ReprioritizeBasedOnDependents(); }
void GoalManager::UnblockCriticalPaths() { impl_->UnblockCriticalPaths(); }

std::string GoalManager::GetNextGoal() const { return impl_->GetNextGoal(); }

GoalManager::Stats GoalManager::GetStats() const { return impl_->GetStats(); }

void GoalManager::PrintStatus() const {
    auto stats = GetStats();
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              Goal Manager Status                               ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Total Goals:      %4zu                                          ║\n", stats.totalGoals);
    printf("║ Pending:          %4zu                                          ║\n", stats.pending);
    printf("║ In Progress:      %4zu                                          ║\n", stats.inProgress);
    printf("║ Blocked:          %4zu                                          ║\n", stats.blocked);
    printf("║ Completed:        %4zu                                          ║\n", stats.completed);
    printf("║ Failed:           %4zu                                          ║\n", stats.failed);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

// ============================================================================
// Global Instance
// ============================================================================

GoalManager& GetGoalManager() {
    static GoalManager instance;
    return instance;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::string CreateGoal(const std::string& name, Priority priority) {
    return GetGoalManager().CreateGoal(name, "", priority);
}

bool CompleteGoal(const std::string& goalId, uint64_t actualTokens) {
    Goal g;
    if (!GetGoalManager().GetGoal(goalId, g)) return false;
    
    g.status = Goal::Status::Completed;
    g.completedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    g.actualTokens = actualTokens;
    g.progress = 1.0f;
    
    return GetGoalManager().UpdateGoal(goalId, g);
}

std::string GetNextWorkItem() {
    return GetGoalManager().GetNextGoal();
}

} // namespace Deep2
