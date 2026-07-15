#include "sovereign/Beaconism.hpp"
#include "sovereign/SovereignEventBus.hpp"
#include <intrin.h>

namespace Sovereign {

BeaconismEmitter& BeaconismEmitter::Instance() {
    static BeaconismEmitter instance;
    return instance;
}

bool BeaconismEmitter::Initialize(const wchar_t* mmfName) {
    if (m_initialized) return true;
    
    m_hMMF = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        sizeof(BeaconismShared),
        mmfName
    );
    
    if (!m_hMMF) {
        m_hMMF = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mmfName);
        if (!m_hMMF) return false;
    }
    
    m_pShared = (BeaconismShared*)MapViewOfFile(
        m_hMMF,
        FILE_MAP_ALL_ACCESS,
        0, 0,
        sizeof(BeaconismShared)
    );
    
    if (!m_pShared) {
        CloseHandle(m_hMMF);
        m_hMMF = nullptr;
        return false;
    }
    
    // Initialize if first
    if (GetLastError() != ERROR_ALREADY_EXISTS) {
        m_pShared->writeIndex = 0;
        m_pShared->readIndex = 0;
    }
    
    m_initialized = true;
    return true;
}

void BeaconismEmitter::Shutdown() {
    if (m_pShared) {
        UnmapViewOfFile(m_pShared);
        m_pShared = nullptr;
    }
    if (m_hMMF) {
        CloseHandle(m_hMMF);
        m_hMMF = nullptr;
    }
    m_initialized = false;
}

void BeaconismEmitter::Emit(BeaconID id, uint32_t payload) {
    if (!m_initialized || !m_pShared) return;
    
    // Get current index
    uint32_t idx = _InterlockedIncrement((volatile LONG*)&m_pShared->writeIndex) - 1;
    idx &= (BeaconismShared::MAX_BEACONS - 1); // Wrap around
    
    // Fill beacon
    Beacon& beacon = m_pShared->beacons[idx];
    beacon.id = static_cast<uint32_t>(id);
    beacon.payload = payload;
    
    // RDTSC for timestamp
    beacon.timestamp = __rdtsc();
    
    // Memory barrier
    _mm_sfence();
}

bool BeaconismEmitter::ReadNext(Beacon& out) {
    if (!m_initialized || !m_pShared) return false;
    
    uint32_t writeIdx = m_pShared->writeIndex;
    
    if (m_lastReadIndex == writeIdx) {
        return false; // Empty
    }
    
    out = m_pShared->beacons[m_lastReadIndex & (BeaconismShared::MAX_BEACONS - 1)];
    m_lastReadIndex++;
    
    return true;
}

uint32_t BeaconismEmitter::GetPendingCount() const {
    if (!m_pShared) return 0;
    return m_pShared->writeIndex - m_pShared->readIndex;
}

void BeaconismEmitter::Poll() {
    if (!m_initialized || !m_pShared) return;
    
    Beacon beacon;
    while (ReadNext(beacon)) {
        // Publish to event bus
        SovereignEventBus::PublishBeacon(beacon);
    }
}

void BeaconismEmitter::Reset() {
    if (!m_pShared) return;
    m_pShared->writeIndex = 0;
    m_pShared->readIndex = 0;
    m_lastReadIndex = 0;
}

void BeaconismEmitter::Reset() {
    if (!m_pShared) return;
    m_pShared->readIndex = 0;
    m_pShared->writeIndex = 0;
}

} // namespace Sovereign
