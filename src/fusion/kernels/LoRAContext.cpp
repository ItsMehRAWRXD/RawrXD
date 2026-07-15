#include "LoRAContext.h"

namespace RawrXD::MASM {

// Global beacon definition
alignas(64) volatile LoRAContext* g_loraContextBeacon = nullptr;

// Beacon manager implementation
LoRABeaconManager& LoRABeaconManager::instance() {
    static LoRABeaconManager inst;
    return inst;
}

bool LoRABeaconManager::updateBeacon(LoRAContext* context) {
    if (!context) {
        return false;
    }
    
    // Validate context
    if (!(context->flags & LoRAContext::FLAG_VALID)) {
        return false;
    }
    
    if (context->rank <= 0 || context->rank > 64) {
        return false; // Sanity check
    }
    
    if (context->input_dim <= 0 || context->input_dim > 4096) {
        return false; // Sanity check
    }
    
    if (!context->matrix_A || !context->matrix_B) {
        return false;
    }
    
    // Clear active flag first (during update)
    context->active = 0;
    
    // Memory barrier to ensure ordering
    _mm_sfence();
    
    // Update beacon pointer
    g_loraContextBeacon = context;
    
    // Memory barrier
    _mm_sfence();
    
    // Set active flag
    context->active = 1;
    
    return true;
}

void LoRABeaconManager::clearBeacon() {
    // Clear active flag first
    if (g_loraContextBeacon) {
        g_loraContextBeacon->active = 0;
    }
    
    _mm_sfence();
    
    // Clear beacon
    g_loraContextBeacon = nullptr;
}

bool LoRABeaconManager::isActive() const {
    return g_loraContextBeacon != nullptr && 
           g_loraContextBeacon->active != 0;
}

const LoRAContext* LoRABeaconManager::getContext() const {
    return g_loraContextBeacon;
}

} // namespace RawrXD::MASM
