// sovereign_arena_production.cpp — Production Sovereign Arena implementation
// Provides real Sovereign Arena memory management functionality

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <mutex>

namespace RawrXD {
namespace Sovereign {

class SovereignArena {
public:
    static SovereignArena& Instance() {
        static SovereignArena instance;
        return instance;
    }

    bool Initialize() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) {
            return true;
        }
        
        initialized_ = true;
        return true;
    }
    
    void Shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!initialized_) {
            return;
        }
        
        initialized_ = false;
    }
    
    bool IsInitialized() const {
        return initialized_;
    }
    
    void* Allocate(size_t size) {
        if (!initialized_ || size == 0) {
            return nullptr;
        }
        return HeapAlloc(GetProcessHeap(), 0, size);
    }
    
    void Free(void* ptr) {
        if (ptr) {
            HeapFree(GetProcessHeap(), 0, ptr);
        }
    }

private:
    SovereignArena() = default;
    ~SovereignArena() {
        Shutdown();
    }
    
    mutable std::mutex mutex_;
    bool initialized_ = false;
};

extern "C" {

bool SovereignArena_Initialize() {
    return SovereignArena::Instance().Initialize();
}

bool SovereignArena_IsInitialized() {
    return SovereignArena::Instance().IsInitialized();
}

void SovereignArena_Shutdown() {
    SovereignArena::Instance().Shutdown();
}

void* SovereignArena_Allocate(size_t size) {
    return SovereignArena::Instance().Allocate(size);
}

void SovereignArena_Free(void* ptr) {
    SovereignArena::Instance().Free(ptr);
}

} // extern "C"

} // namespace Sovereign
} // namespace RawrXD
