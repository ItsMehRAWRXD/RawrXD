// =============================================================================
// RawRamXD.cpp - Software-Defined AI Memory Fabric Implementation
// =============================================================================

#include "RawRamXD.hpp"
#include <algorithm>
#include <string>
#include <iostream>
#include <future>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace rawramxd {

// =============================================================================
// Default Residency Engine - AI-Driven Placement Decisions
// =============================================================================

class DefaultResidencyEngine : public ResidencyEngine {
public:
    DefaultResidencyEngine() : targetTPS_(0.0), aggressiveness_(0.5) {}
    
    Tier decidePlacement(const RawRamXDHandle* handle) override {
        // AI-driven placement based on access pattern and pressure
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        uint64_t lastAccess = handle->lastAccessTime.load();
        uint64_t accessCount = handle->accessCount.load();
        
        // Calculate recency score (0-1, higher = more recent)
        double recency = 1.0;
        if (lastAccess > 0) {
            double age = (now - lastAccess) / 1e9; // seconds
            recency = std::exp(-age / 10.0); // 10s half-life
        }
        
        // Calculate frequency score
        double frequency = std::min(1.0, accessCount / 100.0);
        
        // Pattern-based base tier
        Tier baseTier = Tier::NVMe;
        switch (handle->pattern) {
            case AccessPattern::WEIGHTS:
                baseTier = Tier::RAM; // Weights start in RAM
                break;
            case AccessPattern::KV_CACHE:
                baseTier = Tier::VRAM; // KV cache wants VRAM
                break;
            case AccessPattern::ACTIVATIONS:
                baseTier = Tier::VRAM; // Activations need VRAM
                break;
            case AccessPattern::SCRATCH:
                baseTier = Tier::VRAM; // Scratch in VRAM
                break;
            default:
                baseTier = Tier::RAM;
        }
        
        // Adjust based on access heat
        double heat = recency * 0.6 + frequency * 0.4;
        
        if (heat > 0.8 * aggressiveness_) {
            // Hot data - promote to VRAM
            return Tier::VRAM;
        } else if (heat > 0.4 * aggressiveness_ && baseTier == Tier::NVMe) {
            // Warm data - keep in RAM
            return Tier::RAM;
        }
        
        return baseTier;
    }
    
    MigrationPriority decideUrgency(const RawRamXDHandle* handle) override {
        // Critical for KV cache and activations
        if (handle->pattern == AccessPattern::ACTIVATIONS) {
            return MigrationPriority::CRITICAL;
        }
        if (handle->pattern == AccessPattern::KV_CACHE) {
            return MigrationPriority::HIGH;
        }
        if (handle->accessCount > 10) {
            return MigrationPriority::NORMAL;
        }
        return MigrationPriority::LOW;
    }
    
    bool shouldPrefetch(const RawRamXDHandle* handle) override {
        // Prefetch weights and frequently accessed data
        if (handle->pattern == AccessPattern::WEIGHTS) {
            return handle->accessCount.load() > 0;
        }
        return false;
    }
    
    bool shouldEvict(const RawRamXDHandle* handle) override {
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        uint64_t lastAccess = handle->lastAccessTime.load();
        
        if (lastAccess == 0) return false;
        
        double age = (now - lastAccess) / 1e9; // seconds
        
        // Evict cold data from VRAM
        if (handle->currentTier == Tier::VRAM && age > 30.0) {
            return true;
        }
        
        // Evict very cold data from RAM
        if (handle->currentTier == Tier::RAM && age > 300.0) {
            return true;
        }
        
        return false;
    }
    
    void onMigrationComplete(Handle handle, Tier from, Tier to, double latencyMs) override {
        // Update running average
        double oldAvg = avgMigrationTimeMs_.load();
        double newAvg = oldAvg * 0.9 + latencyMs * 0.1;
        avgMigrationTimeMs_.store(newAvg);
    }
    
    void onFault(Handle handle, Tier needed) override {
        faultCount_++;
    }
    
    void onAccess(Handle handle, size_t bytes) override {
        (void)handle;
        (void)bytes;
    }
    
    void updatePressure(Tier tier, float pressure) override {
        pressure_[static_cast<size_t>(tier)] = pressure;
    }
    
    void setTargetTPS(double tps) override {
        targetTPS_ = tps;
    }
    
    void setAggressiveness(float level) override {
        aggressiveness_ = std::clamp(level, 0.0f, 1.0f);
    }
    
private:
    std::atomic<double> avgMigrationTimeMs_{0.0};
    std::atomic<uint64_t> faultCount_{0};
    std::atomic<double> targetTPS_{0.0};
    std::atomic<float> aggressiveness_{0.5f};
    std::atomic<float> pressure_[4];
};

// =============================================================================
// RawRamXD Implementation
// =============================================================================

class RawRamXDFabric::Impl {
public:
    Impl() : nextHandle_(1), running_(false) {}
    
    ~Impl() {
        shutdown();
    }
    
    bool initialize(size_t vramSize, size_t ramSize, size_t nvmeSize) {
        std::lock_guard<std::mutex> lock(initMutex_);
        
        if (running_) {
            return true;
        }
        
        // Initialize tier capacities
        tierCapacity_[static_cast<size_t>(Tier::VRAM)] = vramSize;
        tierCapacity_[static_cast<size_t>(Tier::RAM)] = ramSize;
        tierCapacity_[static_cast<size_t>(Tier::NVMe)] = nvmeSize;
        
        tierUsed_[static_cast<size_t>(Tier::VRAM)] = 0;
        tierUsed_[static_cast<size_t>(Tier::RAM)] = 0;
        tierUsed_[static_cast<size_t>(Tier::NVMe)] = 0;
        
        // Set default residency engine
        if (!engine_) {
            engine_ = std::make_unique<DefaultResidencyEngine>();
        }
        
        // Start scheduler thread
        running_ = true;
        schedulerThread_ = std::thread(&Impl::schedulerLoop, this);
        
        std::cout << "[RawRamXD] Initialized with:" << std::endl;
        std::cout << "  VRAM: " << (vramSize / (1024*1024*1024)) << " GB" << std::endl;
        std::cout << "  RAM: " << (ramSize / (1024*1024*1024)) << " GB" << std::endl;
        std::cout << "  NVMe: " << (nvmeSize / (1024*1024*1024)) << " GB" << std::endl;
        
        return true;
    }
    
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(initMutex_);
            if (!running_) return;
            running_ = false;
        }
        
        cv_.notify_all();
        
        if (schedulerThread_.joinable()) {
            schedulerThread_.join();
        }
        
        // Clean up all handles
        std::lock_guard<std::mutex> lock(handlesMutex_);
        handles_.clear();
    }
    
    Handle allocate(size_t size, const char* name, AccessPattern pattern) {
        Handle id = nextHandle_++;
        
        auto handle = std::make_unique<RawRamXDHandle>();
        handle->id = id;
        handle->vaddr = id << 12; // Page-aligned virtual address
        handle->size = size;
        handle->currentTier = Tier::NVMe; // Start in NVMe
        handle->preferredTier = Tier::RAM;
        handle->state = ResidencyState::UNMAPPED;
        handle->pattern = pattern;
        handle->priority = MigrationPriority::NORMAL;
        handle->name = name ? name : "unnamed";
        handle->physicalPtr = nullptr;
        handle->vramPtr = nullptr;
        handle->ramPtr = nullptr;
        handle->nvmeHandle = nullptr;
        
        // Allocate in NVMe (backing store)
        handle->nvmeHandle = allocateInNVMe(size);
        handle->state = ResidencyState::RESIDENT;
        handle->currentTier = Tier::NVMe;
        
        {
            std::lock_guard<std::mutex> lock(handlesMutex_);
            handles_[id] = std::move(handle);
        }
        
        // Update stats
        stats_.tiers[static_cast<size_t>(Tier::NVMe)].totalBytes += size;
        stats_.tiers[static_cast<size_t>(Tier::NVMe)].usedBytes += size;
        
        return id;
    }
    
    void deallocate(Handle id) {
        std::unique_lock<std::mutex> lock(handlesMutex_);
        auto it = handles_.find(id);
        if (it == handles_.end()) return;
        
        auto* handle = it->second.get();
        
        // Free from current tier
        freeFromTier(handle->currentTier, handle);
        
        // Update stats
        stats_.tiers[static_cast<size_t>(handle->currentTier)].usedBytes -= handle->size;
        
        handles_.erase(it);
    }
    
    bool ensureInVRAM(Handle id) {
        auto* handle = resolve(id);
        if (!handle) return false;
        
        // Already in VRAM
        if (handle->currentTier == Tier::VRAM) {
            touch(id);
            return true;
        }
        
        // Trigger migration
        migrate(id, Tier::VRAM);
        
        // Wait for completion (simplified - in production use async)
        int retries = 1000;
        while (handle->state == ResidencyState::MIGRATING && retries-- > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        
        return handle->currentTier == Tier::VRAM;
    }
    
    bool ensureInRAM(Handle id) {
        auto* handle = resolve(id);
        if (!handle) return false;
        
        if (static_cast<int>(handle->currentTier) <= static_cast<int>(Tier::RAM)) {
            touch(id);
            return true;
        }
        
        migrate(id, Tier::RAM);
        return true;
    }
    
    void touch(Handle id) {
        auto* handle = resolve(id);
        if (!handle) return;
        
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        handle->lastAccessTime.store(now);
        handle->accessCount++;
        
        // Notify engine
        if (engine_) {
            engine->onAccess(id, handle->size);
        }
    }
    
    void migrate(Handle id, Tier target) {
        auto* handle = resolve(id);
        if (!handle || handle->currentTier == target) return;
        
        // Queue migration
        MigrationRequest req;
        req.handle = id;
        req.from = handle->currentTier;
        req.to = target;
        req.priority = engine_ ? engine->decideUrgency(handle) : MigrationPriority::NORMAL;
        
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            migrationQueue_.push(req);
        }
        
        cv_.notify_one();
    }
    
    void prefetch(Handle id) {
        auto* handle = resolve(id);
        if (!handle || handle->state != ResidencyState::EVICTED) return;
        
        // Queue prefetch
        MigrationRequest req;
        req.handle = id;
        req.from = handle->currentTier;
        req.to = handle->preferredTier;
        req.priority = MigrationPriority::PREFETCH;
        
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            migrationQueue_.push(req);
        }
        
        cv_.notify_one();
    }
    
    RawRamXDHandle* resolve(Handle id) {
        std::lock_guard<std::mutex> lock(handlesMutex_);
        auto it = handles_.find(id);
        return (it != handles_.end()) ? it->second.get() : nullptr;
    }
    
    Tier currentTier(Handle id) {
        auto* handle = resolve(id);
        return handle ? handle->currentTier : Tier::COUNT;
    }
    
    ResidencyState residency(Handle id) {
        auto* handle = resolve(id);
        return handle ? handle->state : ResidencyState::UNMAPPED;
    }
    
    bool isResident(Handle id, Tier tier) {
        auto* handle = resolve(id);
        return handle && handle->currentTier == tier && 
               handle->state == ResidencyState::RESIDENT;
    }
    
    RawRamXDStats stats() {
        return stats_;
    }
    
    void dumpState() {
        std::lock_guard<std::mutex> lock(handlesMutex_);
        
        std::cout << "\n=== RawRamXD State ===" << std::endl;
        std::cout << "Active handles: " << handles_.size() << std::endl;
        
        for (const auto& [id, handle] : handles_) {
            std::cout << "  [" << id << "] " << handle->name
                      << " | Tier: " << static_cast<int>(handle->currentTier)
                      << " | State: " << static_cast<int>(handle->state)
                      << " | Access: " << handle->accessCount.load()
                      << std::endl;
        }
        
        std::cout << "\nTier Usage:" << std::endl;
        for (size_t i = 0; i < static_cast<size_t>(Tier::COUNT); i++) {
            auto used = tierUsed_[i].load();
            auto cap = tierCapacity_[i];
            std::cout << "  Tier " << i << ": " 
                      << (used / (1024*1024)) << " MB / "
                      << (cap / (1024*1024)) << " MB"
                      << std::endl;
        }
    }
    
    void setResidencyEngine(std::unique_ptr<ResidencyEngine> engine) {
        engine_ = std::move(engine);
    }
    
    void setPolicy(const std::string& policy) {
        if (!engine_) return;
        
        if (policy == "aggressive") {
            engine->setAggressiveness(0.9f);
        } else if (policy == "balanced") {
            engine->setAggressiveness(0.5f);
        } else if (policy == "conservative") {
            engine->setAggressiveness(0.1f);
        }
    }
    
    void* vramPtr(Handle id) {
        auto* handle = resolve(id);
        return (handle && handle->currentTier == Tier::VRAM) ? handle->vramPtr : nullptr;
    }
    
    void* ramPtr(Handle id) {
        auto* handle = resolve(id);
        return (handle && static_cast<int>(handle->currentTier) <= static_cast<int>(Tier::RAM)) 
               ? handle->ramPtr : nullptr;
    }

private:
    struct MigrationRequest {
        Handle handle;
        Tier from;
        Tier to;
        MigrationPriority priority;
        
        bool operator<(const MigrationRequest& other) const {
            return static_cast<int>(priority) > static_cast<int>(other.priority);
        }
    };
    
    void schedulerLoop() {
        while (running_) {
            std::unique_lock<std::mutex> lock(queueMutex_);
            cv_.wait(lock, [this] { return !migrationQueue_.empty() || !running_; });
            
            while (!migrationQueue_.empty()) {
                auto req = migrationQueue_.top();
                migrationQueue_.pop();
                lock.unlock();
                
                executeMigration(req);
                
                lock.lock();
            }
        }
    }
    
    void executeMigration(const MigrationRequest& req) {
        auto* handle = resolve(req.handle);
        if (!handle) return;
        
        handle->state = ResidencyState::MIGRATING;
        
        auto start = std::chrono::steady_clock::now();
        
        // Perform actual migration
        bool success = doMigration(handle, req.from, req.to);
        
        auto end = std::chrono::steady_clock::now();
        double latencyMs = std::chrono::duration<double, std::milli>(end - start).count();
        
        if (success) {
            handle->currentTier = req.to;
            handle->state = ResidencyState::RESIDENT;
            
            // Update stats
            stats_.migrationsCompleted++;
            stats_.tiers[static_cast<size_t>(req.from)].migrationOutBytes += handle->size;
            stats_.tiers[static_cast<size_t>(req.to)].migrationInBytes += handle->size;
            
            if (engine_) {
                engine->onMigrationComplete(req.handle, req.from, req.to, latencyMs);
            }
        } else {
            handle->state = ResidencyState::RESIDENT;
        }
    }
    
    bool doMigration(RawRamXDHandle* handle, Tier from, Tier to) {
        // Allocate in target tier
        void* newPtr = nullptr;
        switch (to) {
            case Tier::VRAM:
                newPtr = allocateInVRAM(handle->size);
                handle->vramPtr = newPtr;
                break;
            case Tier::RAM:
                newPtr = allocateInRAM(handle->size);
                handle->ramPtr = newPtr;
                break;
            case Tier::NVMe:
                newPtr = allocateInNVMe(handle->size);
                handle->nvmeHandle = newPtr;
                break;
            default:
                return false;
        }
        
        if (!newPtr) {
            return false;
        }
        
        // Copy data (simplified - real implementation uses DMA)
        void* oldPtr = nullptr;
        switch (from) {
            case Tier::VRAM: oldPtr = handle->vramPtr; break;
            case Tier::RAM: oldPtr = handle->ramPtr; break;
            case Tier::NVMe: oldPtr = handle->nvmeHandle; break;
            default: break;
        }
        
        if (oldPtr && newPtr) {
            std::memcpy(newPtr, oldPtr, handle->size);
        }
        
        // Free from old tier
        freeFromTier(from, handle);
        
        // Update tier usage
        tierUsed_[static_cast<size_t>(from)] -= handle->size;
        tierUsed_[static_cast<size_t>(to)] += handle->size;
        
        return true;
    }
    
    void* allocateInVRAM(size_t size) {
        // Platform-specific VRAM allocation
        #ifdef _WIN32
        // Use DirectX 12 or CUDA
        return std::malloc(size); // Placeholder
        #else
        return std::malloc(size); // Placeholder
        #endif
    }
    
    void* allocateInRAM(size_t size) {
        #ifdef _WIN32
        return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        #else
        return std::aligned_alloc(4096, size);
        #endif
    }
    
    void* allocateInNVMe(size_t size) {
        // Memory-mapped file or SSD-backed allocation
        return std::malloc(size); // Placeholder
    }
    
    void freeFromTier(Tier tier, RawRamXDHandle* handle) {
        switch (tier) {
            case Tier::VRAM:
                if (handle->vramPtr) {
                    std::free(handle->vramPtr);
                    handle->vramPtr = nullptr;
                }
                break;
            case Tier::RAM:
                if (handle->ramPtr) {
                    #ifdef _WIN32
                    VirtualFree(handle->ramPtr, 0, MEM_RELEASE);
                    #else
                    std::free(handle->ramPtr);
                    #endif
                    handle->ramPtr = nullptr;
                }
                break;
            case Tier::NVMe:
                if (handle->nvmeHandle) {
                    std::free(handle->nvmeHandle);
                    handle->nvmeHandle = nullptr;
                }
                break;
            default:
                break;
        }
    }
    
    // Members
    std::atomic<Handle> nextHandle_;
    std::unordered_map<Handle, std::unique_ptr<RawRamXDHandle>> handles_;
    std::mutex handlesMutex_;
    
    std::priority_queue<MigrationRequest> migrationQueue_;
    std::mutex queueMutex_;
    std::condition_variable cv_;
    
    std::thread schedulerThread_;
    std::atomic<bool> running_;
    std::mutex initMutex_;
    
    std::unique_ptr<ResidencyEngine> engine_;
    RawRamXDStats stats_;
    
    std::atomic<size_t> tierCapacity_[4];
    std::atomic<size_t> tierUsed_[4];
};

// =============================================================================
// Singleton Instance
// =============================================================================

RawRamXDFabric& RawRamXDFabric::instance() {
    static RawRamXDFabric instance;
    return instance;
}

bool RawRamXDFabric::initialize(size_t vramSize, size_t ramSize, size_t nvmeSize) {
    if (!impl_) {
        impl_ = std::make_unique<Impl>();
    }
    return impl_>initialize(vramSize, ramSize, nvmeSize);
}

void RawRamXDFabric::shutdown() {
    if (impl_) {
        impl_>shutdown();
    }
}

Handle RawRamXDFabric::allocate(size_t size, const char* name, AccessPattern pattern) {
    return impl_ ? impl_>allocate(size, name, pattern) : 0;
}

void RawRamXDFabric::deallocate(Handle handle) {
    if (impl_) impl_>deallocate(handle);
}

bool RawRamXDFabric::ensureInVRAM(Handle handle) {
    return impl_ ? impl_>ensureInVRAM(handle) : false;
}

bool RawRamXDFabric::ensureInRAM(Handle handle) {
    return impl_ ? impl_>ensureInRAM(handle) : false;
}

void RawRamXDFabric::touch(Handle handle) {
    if (impl_) impl_>touch(handle);
}

void RawRamXDFabric::migrate(Handle handle, Tier target) {
    if (impl_) impl_>migrate(handle, target);
}

void RawRamXDFabric::prefetch(Handle handle) {
    if (impl_) impl_>prefetch(handle);
}

RawRamXDHandle* RawRamXDFabric::resolve(Handle handle) {
    return impl_ ? impl_>resolve(handle) : nullptr;
}

Tier RawRamXDFabric::currentTier(Handle handle) {
    return impl_ ? impl_>currentTier(handle) : Tier::COUNT;
}

ResidencyState RawRamXDFabric::residency(Handle handle) {
    return impl_ ? impl_>residency(handle) : ResidencyState::UNMAPPED;
}

bool RawRamXDFabric::isResident(Handle handle, Tier tier) {
    return impl_ ? impl_>isResident(handle, tier) : false;
}

RawRamXDStats RawRamXDFabric::stats() {
    return impl_ ? impl_>stats() : RawRamXDStats{};
}

void RawRamXDFabric::dumpState() {
    if (impl_) impl_>dumpState();
}

void RawRamXDFabric::setResidencyEngine(std::unique_ptr<ResidencyEngine> engine) {
    if (impl_) impl_>setResidencyEngine(std::move(engine));
}

void RawRamXDFabric::setPolicy(const std::string& policy) {
    if (impl_) impl_>setPolicy(policy);
}

void* RawRamXDFabric::vramPtr(Handle handle) {
    return impl_ ? impl_>vramPtr(handle) : nullptr;
}

void* RawRamXDFabric::ramPtr(Handle handle) {
    return impl_ ? impl_>ramPtr(handle) : nullptr;
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

bool rawramxd_init(uint64_t vram_bytes, uint64_t ram_bytes, uint64_t nvme_bytes) {
    return RawRamXDFabric::instance().initialize(vram_bytes, ram_bytes, nvme_bytes);
}

void rawramxd_shutdown() {
    RawRamXDFabric::instance().shutdown();
}

uint64_t rawramxd_alloc(size_t size, const char* name, uint8_t pattern) {
    return RawRamXDFabric::instance().allocate(size, name, 
        static_cast<AccessPattern>(pattern));
}

void rawramxd_free(uint64_t handle) {
    RawRamXDFabric::instance().deallocate(handle);
}

bool rawramxd_ensure_vram(uint64_t handle) {
    return RawRamXDFabric::instance().ensureInVRAM(handle);
}

bool rawramxd_ensure_ram(uint64_t handle) {
    return RawRamXDFabric::instance().ensureInRAM(handle);
}

void rawramxd_touch(uint64_t handle) {
    RawRamXDFabric::instance().touch(handle);
}

void rawramxd_migrate(uint64_t handle, uint8_t tier) {
    RawRamXDFabric::instance().migrate(handle, static_cast<Tier>(tier));
}

void rawramxd_prefetch(uint64_t handle) {
    RawRamXDFabric::instance().prefetch(handle);
}

uint8_t rawramxd_current_tier(uint64_t handle) {
    return static_cast<uint8_t>(RawRamXDFabric::instance().currentTier(handle));
}

uint8_t rawramxd_residency(uint64_t handle) {
    return static_cast<uint8_t>(RawRamXDFabric::instance().residency(handle));
}

void* rawramxd_vram_ptr(uint64_t handle) {
    return RawRamXDFabric::instance().vramPtr(handle);
}

void* rawramxd_ram_ptr(uint64_t handle) {
    return RawRamXDFabric::instance().ramPtr(handle);
}

void rawramxd_stats(void* stats_out) {
    if (stats_out) {
        *static_cast<RawRamXDStats*>(stats_out) = RawRamXDFabric::instance().stats();
    }
}

void rawramxd_dump() {
    RawRamXDFabric::instance().dumpState();
}

} // extern "C"

// =============================================================================
// RAII Wrapper Implementation
// =============================================================================

RawRamXDTensor::RawRamXDTensor(size_t size, const char* name, AccessPattern pattern)
    : handle_(RawRamXDFabric::instance().allocate(size, name, pattern)) {}

RawRamXDTensor::~RawRamXDTensor() {
    if (handle_) {
        RawRamXDFabric::instance().deallocate(handle_);
    }
}

RawRamXDTensor::RawRamXDTensor(RawRamXDTensor&& other) noexcept
    : handle_(other.handle_) {
    other.handle_ = 0;
}

RawRamXDTensor& RawRamXDTensor::operator=(RawRamXDTensor&& other) noexcept {
    if (this != &other) {
        if (handle_) {
            RawRamXDFabric::instance().deallocate(handle_);
        }
        handle_ = other.handle_;
        other.handle_ = 0;
    }
    return *this;
}

VRAMResidencyGuard::VRAMResidencyGuard(Handle handle) : handle_(handle) {
    acquired_ = RawRamXDFabric::instance().ensureInVRAM(handle_);
}

VRAMResidencyGuard::~VRAMResidencyGuard() {
    // Residency persists after guard - we don't demote automatically
}

} // namespace rawramxd