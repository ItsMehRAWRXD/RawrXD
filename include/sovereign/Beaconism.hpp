#pragma once
#include <cstdint>
#include <windows.h>

namespace Sovereign {

#pragma pack(push, 1)

struct Beacon {
    uint32_t id;
    uint64_t timestamp;
    uint32_t payload;
};

struct BeaconismShared {
    static constexpr uint32_t MAX_BEACONS = 1024;
    
    volatile uint32_t writeIndex;
    volatile uint32_t readIndex;
    Beacon beacons[MAX_BEACONS];
};

enum class BeaconID : uint32_t {
    // Runtime lifecycle
    RuntimeStart = 0x10,
    RuntimeInitialized = 0x11,
    RuntimeShutdown = 0x12,
    
    // IDE lifecycle
    IDE_Start = 0x20,
    IDE_Initialized = 0x21,
    IDE_Shutdown = 0x22,
    
    // Smoketest
    SmoketestStart = 0x30,
    SmoketestDone = 0x31,
    
    // Subsystem operations
    KV_START = 0x100,
    KV_DONE = 0x101,
    EXPERT_START = 0x200,
    EXPERT_DONE = 0x201,
    ATTENTION_START = 0x300,
    ATTENTION_DONE = 0x301,
    MOE_START = 0x400,
    MOE_DONE = 0x401,
    NVME_START = 0x500,
    NVME_DONE = 0x501,
    VULKAN_START = 0x600,
    VULKAN_DONE = 0x601,
    QUANT_START = 0x700,
    QUANT_DONE = 0x701,
    MODEL_START = 0x800,
    MODEL_DONE = 0x801,
    REPLAY_START = 0x900,
    REPLAY_DONE = 0x901,
    TELEMETRY_START = 0xA00,
    TELEMETRY_DONE = 0xA01,
    BEACONISM_TEST = 0xFF00,
    REPAIR_KV = 0x10000,
    REPAIR_EXPERT = 0x10001,
    REPAIR_VULKAN = 0x10002,
    AutoRepairAttempt = 0x10003,
    AutoRepairComplete = 0x10004,
    SmoketestFailed = 0x10005,
    SmoketestPassed = 0x10006,
    SmoketestRepaired = 0x10007,
    
    // Maintenance cycle
    MaintenanceCycle = 0x10008,
    MaintenanceDegraded = 0x10009,
    MaintenanceRepaired = 0x1000A,
    
    // Watchdog alerts
    WatchdogStall = 0x1000B,
    WatchdogThermal = 0x1000C,
    WatchdogLatency = 0x1000D,
    
    // Stress testing
    StressTestStart = 0x1000E,
    StressTestDone = 0x1000F,
    
    // Integrity checking
    IntegrityCheckStart = 0x10010,
    IntegrityCheckDone = 0x10011,
    IntegrityCheckFailed = 0x10012,
    
    // Crash recovery
    CrashSaveStart = 0x10013,
    CrashSaveDone = 0x10014,
    CrashLoadStart = 0x10015,
    CrashLoadDone = 0x10016,
    
    // Profiler
    ProfilerFrameTime = 0x10017,
    ProfilerTokPerSec = 0x10018,
    ProfilerNVMeMBps = 0x10019,
    ProfilerThermal = 0x1001A
};

class BeaconismEmitter {
public:
    static BeaconismEmitter& Instance();
    
    bool Initialize(const wchar_t* mmfName = L"RawrXD_Beaconism_v1");
    void Shutdown();
    
    void Emit(BeaconID id, uint32_t payload = 0);
    bool ReadNext(Beacon& out);
    
    uint32_t GetPendingCount() const;
    void Reset();
    
    // Poll for new beacons and publish to event bus
    void Poll();
    
private:
    BeaconismEmitter() = default;
    ~BeaconismEmitter() { Shutdown(); }
    
    HANDLE m_hMMF = nullptr;
    BeaconismShared* m_pShared = nullptr;
    bool m_initialized = false;
    uint32_t m_lastReadIndex = 0;
};

#pragma pack(pop)

} // namespace Sovereign
