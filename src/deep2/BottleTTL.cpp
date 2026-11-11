// ============================================================================
// BottleTTL.cpp - Time-To-Live Management Implementation
//
// Automatically expires and removes patches after a specified duration.
// Prevents accumulation of stale hooks that slow down execution.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "BottleTTL.hpp"
#include "HotPatcher.hpp"
#include <algorithm>
#include <thread>

namespace Deep2 {

// ============================================================================
// BottleTTL Implementation
// ============================================================================

class BottleTTL::Impl {
public:
    std::unordered_map<std::string, PatchLifetime> lifetimes;
    std::vector<TTLEvent> eventHistory;
    TTLConfig config;
    EventCallback eventCallback;
    
    mutable std::mutex mutex;
    std::thread cleanupThread;
    std::atomic<bool> running{false};
    std::atomic<bool> shouldStop{false};
    
    std::atomic<size_t> totalRegistered{0};
    std::atomic<size_t> totalRenewals{0};
    std::atomic<size_t> totalCleanups{0};
    
    bool Initialize(const TTLConfig& cfg) {
        config = cfg;
        running = true;
        shouldStop = false;
        
        // Start cleanup thread
        cleanupThread = std::thread([this]() {
            while (running.load() && !shouldStop.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(config.cleanupIntervalMs));
                if (config.autoCleanup) {
                    CleanupExpired();
                }
                CheckExpiringSoon();
            }
        });
        
        printf("[BottleTTL] Initialized (default TTL=%llums, cleanup interval=%llums)\n",
               config.defaultTTLMs, config.cleanupIntervalMs);
        return true;
    }
    
    void Shutdown() {
        running = false;
        shouldStop = true;
        
        if (cleanupThread.joinable()) {
            cleanupThread.join();
        }
        
        std::lock_guard<std::mutex> lock(mutex);
        lifetimes.clear();
        printf("[BottleTTL] Shutdown\n");
    }
    
    bool Register(const std::string& patchId, uint64_t ttlMs, bool isCritical, bool isEmergency) {
        std::lock_guard<std::mutex> lock(mutex);
        
        // Determine TTL
        uint64_t actualTTL = ttlMs;
        if (actualTTL == 0) {
            if (isEmergency) actualTTL = config.emergencyTTLMs;
            else if (isCritical) actualTTL = config.criticalTTLMs;
            else actualTTL = config.defaultTTLMs;
        }
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        PatchLifetime lifetime;
        lifetime.patchId = patchId;
        lifetime.createdAt = now;
        lifetime.expiresAt = now + actualTTL;
        lifetime.lastRenewedAt = now;
        lifetime.renewalCount = 0;
        lifetime.isCritical = isCritical;
        lifetime.isEmergency = isEmergency;
        lifetime.status = PatchLifetime::Status::ACTIVE;
        
        lifetimes[patchId] = lifetime;
        totalRegistered++;
        
        // Log event
        TTLEvent event;
        event.type = TTLEventType::CREATED;
        event.patchId = patchId;
        event.timestamp = now;
        event.newExpiry = lifetime.expiresAt;
        eventHistory.push_back(event);
        
        if (eventCallback) eventCallback(event);
        
        printf("[BottleTTL] Registered: %s (expires in %llums)\n", patchId.c_str(), actualTTL);
        return true;
    }
    
    bool Unregister(const std::string& patchId) {
        std::lock_guard<std::mutex> lock(mutex);
        return lifetimes.erase(patchId) > 0;
    }
    
    bool Renew(const std::string& patchId, uint64_t extensionMs) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = lifetimes.find(patchId);
        if (it == lifetimes.end()) return false;
        
        if (!config.allowRenewal) {
            printf("[BottleTTL] Renewal not allowed for: %s\n", patchId.c_str());
            return false;
        }
        
        if (it->second.renewalCount >= config.maxRenewals) {
            printf("[BottleTTL] Max renewals reached for: %s\n", patchId.c_str());
            return false;
        }
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        uint64_t oldExpiry = it->second.expiresAt;
        uint64_t actualExtension = extensionMs == 0 ? config.defaultTTLMs : extensionMs;
        
        it->second.expiresAt = now + actualExtension;
        it->second.lastRenewedAt = now;
        it->second.renewalCount++;
        it->second.status = PatchLifetime::Status::RENEWED;
        
        totalRenewals++;
        
        // Log event
        TTLEvent event;
        event.type = TTLEventType::RENEWED;
        event.patchId = patchId;
        event.timestamp = now;
        event.oldExpiry = oldExpiry;
        event.newExpiry = it->second.expiresAt;
        eventHistory.push_back(event);
        
        if (eventCallback) eventCallback(event);
        
        printf("[BottleTTL] Renewed: %s (new expiry in %llums, renewal #%llu)\n",
               patchId.c_str(), actualExtension, it->second.renewalCount);
        return true;
    }
    
    size_t CleanupExpired() {
        std::lock_guard<std::mutex> lock(mutex);
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        std::vector<std::string> toRemove;
        for (auto& [id, lifetime] : lifetimes) {
            if (lifetime.IsExpired(now) && lifetime.status != PatchLifetime::Status::REMOVED) {
                toRemove.push_back(id);
                lifetime.status = PatchLifetime::Status::EXPIRED;
                
                // Log event
                TTLEvent event;
                event.type = TTLEventType::EXPIRED;
                event.patchId = id;
                event.timestamp = now;
                event.oldExpiry = lifetime.expiresAt;
                eventHistory.push_back(event);
                
                if (eventCallback) eventCallback(event);
                
                // Auto-rollback via HotPatcher
                GetHotPatcher().rollback(id);
            }
        }
        
        for (const auto& id : toRemove) {
            lifetimes.erase(id);
            totalCleanups++;
            
            // Log cleanup
            TTLEvent event;
            event.type = TTLEventType::CLEANED_UP;
            event.patchId = id;
            event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            eventHistory.push_back(event);
        }
        
        if (!toRemove.empty()) {
            printf("[BottleTTL] Cleaned up %zu expired patches\n", toRemove.size());
        }
        
        return toRemove.size();
    }
    
    void CheckExpiringSoon() {
        if (!config.warnBeforeExpire) return;
        
        std::lock_guard<std::mutex> lock(mutex);
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        for (auto& [id, lifetime] : lifetimes) {
            if (lifetime.IsExpiringSoon(now, config.warnThresholdMs) &&
                lifetime.status == PatchLifetime::Status::ACTIVE) {
                lifetime.status = PatchLifetime::Status::EXPIRING;
                
                // Log event
                TTLEvent event;
                event.type = TTLEventType::EXPIRING;
                event.patchId = id;
                event.timestamp = now;
                event.oldExpiry = lifetime.expiresAt;
                eventHistory.push_back(event);
                
                if (eventCallback) eventCallback(event);
                
                printf("[BottleTTL] Warning: %s expiring in %llums\n",
                       id.c_str(), lifetime.TimeRemaining(now));
            }
        }
    }
    
    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        Stats stats;
        stats.activePatches = 0;
        stats.expiredPatches = 0;
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        uint64_t totalLifetime = 0;
        for (const auto& [id, lifetime] : lifetimes) {
            if (lifetime.IsExpired(now)) {
                stats.expiredPatches++;
            } else {
                stats.activePatches++;
            }
            totalLifetime += (lifetime.expiresAt - lifetime.createdAt);
        }
        
        stats.totalRegistered = totalRegistered.load();
        stats.totalRenewals = totalRenewals.load();
        stats.totalCleanups = totalCleanups.load();
        stats.avgLifetimeMs = lifetimes.empty() ? 0 : totalLifetime / lifetimes.size();
        stats.renewalRate = stats.totalRegistered > 0 ? 
            static_cast<double>(stats.totalRenewals) / stats.totalRegistered : 0.0;
        
        return stats;
    }
};

// ============================================================================
// Public API Implementation
// ============================================================================

BottleTTL::BottleTTL() : impl_(std::make_unique<Impl>()) {}
BottleTTL::~BottleTTL() = default;

bool BottleTTL::Initialize(const TTLConfig& config) { return impl_->Initialize(config); }
void BottleTTL::Shutdown() { impl_->Shutdown(); }

bool BottleTTL::Register(const std::string& patchId, uint64_t ttlMs, bool isCritical, bool isEmergency) {
    return impl_->Register(patchId, ttlMs, isCritical, isEmergency);
}

bool BottleTTL::Unregister(const std::string& patchId) { return impl_->Unregister(patchId); }
bool BottleTTL::Renew(const std::string& patchId, uint64_t extensionMs) { return impl_->Renew(patchId, extensionMs); }

size_t BottleTTL::CleanupExpired() { return impl_->CleanupExpired(); }

void BottleTTL::SetEventCallback(EventCallback cb) { impl_->eventCallback = cb; }

BottleTTL::Stats BottleTTL::GetStats() const { return impl_->GetStats(); }

void BottleTTL::PrintStatus() const {
    auto stats = GetStats();
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              BottleTTL Status - Patch Expiration               ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Active Patches:    %4zu                                          ║\n", stats.activePatches);
    printf("║ Expired Patches:   %4zu                                          ║\n", stats.expiredPatches);
    printf("║ Total Registered:  %4zu                                          ║\n", stats.totalRegistered);
    printf("║ Total Renewals:    %4zu                                          ║\n", stats.totalRenewals);
    printf("║ Total Cleanups:    %4zu                                          ║\n", stats.totalCleanups);
    printf("║ Avg Lifetime:      %4llums                                       ║\n", stats.avgLifetimeMs);
    printf("║ Renewal Rate:      %6.2f%%                                        ║\n", stats.renewalRate * 100);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

// ============================================================================
// Global Instance
// ============================================================================

BottleTTL& GetBottleTTL() {
    static BottleTTL instance;
    return instance;
}

// ============================================================================
// Convenience Functions
// ============================================================================

bool RegisterPatchWithTTL(const std::string& patchId, uint64_t ttlMinutes) {
    return GetBottleTTL().Register(patchId, ttlMinutes * 60 * 1000);
}

bool RenewPatch(const std::string& patchId, uint64_t extensionMinutes) {
    return GetBottleTTL().Renew(patchId, extensionMinutes * 60 * 1000);
}

size_t CleanupExpiredPatches() {
    return GetBottleTTL().CleanupExpired();
}

} // namespace Deep2
