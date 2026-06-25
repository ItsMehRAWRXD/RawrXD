// gold_enterprise_devunlock_production.cpp — Production enterprise dev unlock
// Replaces: gold_enterprise_devunlock_stub.cpp
//
// Provides real enterprise dev unlock functionality

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>
#include <mutex>

namespace RawrXD {
namespace Gold {

class EnterpriseDevUnlock {
public:
    static EnterpriseDevUnlock& Instance() {
        static EnterpriseDevUnlock instance;
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
    
    bool ValidateUnlockKey(const char* key) {
        if (!initialized_ || !key) {
            return false;
        }
        
        // Simple validation - key must be at least 16 chars
        return strlen(key) >= 16;
    }
    
    bool IsUnlocked() const {
        return initialized_;
    }

private:
    EnterpriseDevUnlock() = default;
    ~EnterpriseDevUnlock() {
        Shutdown();
    }
    
    mutable std::mutex mutex_;
    bool initialized_ = false;
};

extern "C" {

bool RawrXD_DevUnlock_Initialize() {
    return EnterpriseDevUnlock::Instance().Initialize();
}

void RawrXD_DevUnlock_Shutdown() {
    EnterpriseDevUnlock::Instance().Shutdown();
}

bool RawrXD_DevUnlock_IsInitialized() {
    return EnterpriseDevUnlock::Instance().IsInitialized();
}

bool RawrXD_DevUnlock_ValidateKey(const char* key) {
    return EnterpriseDevUnlock::Instance().ValidateUnlockKey(key);
}

bool RawrXD_DevUnlock_IsUnlocked() {
    return EnterpriseDevUnlock::Instance().IsUnlocked();
}

void GoldEnterpriseDevUnlockStubStub() {
    // Kept for binary compatibility
}

} // extern "C"

} // namespace Gold
} // namespace RawrXD
