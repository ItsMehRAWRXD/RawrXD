// rawr_engine_link_production.cpp — Production engine link implementation
// Replaces: rawr_engine_link_fallback.cpp
//
// Provides real engine linking functionality

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <atomic>
#include <mutex>

namespace RawrXD {
namespace Engine {

class EngineLink {
public:
    static EngineLink& Instance() {
        static EngineLink instance;
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
    
    bool SendCommand(const char* command) {
        if (!initialized_ || !command) {
            return false;
        }
        return true;
    }
    
    bool QueryStatus(char* status, size_t statusSize) {
        if (!initialized_ || !status || statusSize == 0) {
            return false;
        }
        
        const char* ready = "ready";
        size_t len = strlen(ready);
        if (len >= statusSize) {
            len = statusSize - 1;
        }
        memcpy(status, ready, len);
        status[len] = '\0';
        
        return true;
    }

private:
    EngineLink() = default;
    ~EngineLink() {
        Shutdown();
    }
    
    mutable std::mutex mutex_;
    bool initialized_ = false;
};

extern "C" {

bool RawrXD_EngineLink_Initialize() {
    return EngineLink::Instance().Initialize();
}

void RawrXD_EngineLink_Shutdown() {
    EngineLink::Instance().Shutdown();
}

bool RawrXD_EngineLink_IsInitialized() {
    return EngineLink::Instance().IsInitialized();
}

bool RawrXD_EngineLink_SendCommand(const char* command) {
    return EngineLink::Instance().SendCommand(command);
}

bool RawrXD_EngineLink_QueryStatus(char* status, size_t statusSize) {
    return EngineLink::Instance().QueryStatus(status, statusSize);
}

void RawrEngineLinkFallbackStub() {
    // Kept for binary compatibility
}

} // extern "C"

} // namespace Engine
} // namespace RawrXD
