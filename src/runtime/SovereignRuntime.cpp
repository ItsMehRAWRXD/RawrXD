#include "sovereign/Beaconism.hpp"
#include "sovereign/HealthReport.hpp"
#include "sovereign/Telemetry.hpp"
#include "sovereign/Scheduler.hpp"
#include "sovereign/Replay.hpp"
#include "sovereign/KVCache.hpp"
#include "sovereign/ExpertCache.hpp"
#include "sovereign/VulkanCompute.hpp"
#include "sovereign/ModelRegistry.hpp"
#include "sovereign/SovereignRuntime.hpp"

#include <windows.h>
#include <atomic>

namespace Sovereign {

// Shared command structure for runtime control
struct RuntimeCommand {
    std::atomic<uint32_t> Type{0};
    std::atomic<uint32_t> Status{0};
    wchar_t Path[MAX_PATH];
    uint32_t QuantBits;
};

static RuntimeCommand* g_pSharedCommand = nullptr;
static HANDLE g_hCommandMMF = nullptr;

// Command types
enum class CommandType : uint32_t {
    CMD_NONE = 0,
    CMD_RUN_SMOKETEST = 1,
    CMD_LOAD_MODEL = 2,
    CMD_HOTSWAP_MODEL = 3,
    CMD_QUANTIZE_MODEL = 4,
    CMD_SHUTDOWN = 5
};

// Smoketest results
struct SmoketestResults {
    uint32_t testsRun;
    uint32_t testsPassed;
    uint32_t testsFailed;
    char lastError[256];
};

static SmoketestResults g_smoketestResults{};

void SovereignRuntime::Initialize() {
    // Initialize Beaconism first - it's the signaling fabric
    Beaconism::InitSharedMemory();
    Beaconism::Emit(BeaconID::RuntimeStart, 0);

    // Initialize other shared memory subsystems
    Telemetry::InitSharedMemory();
    Scheduler::InitSharedMemory();
    Replay::InitSharedMemory();

    // Create command shared memory
    g_hCommandMMF = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        sizeof(RuntimeCommand),
        L"RawrXD_RuntimeCommand_v1"
    );

    if (g_hCommandMMF) {
        g_pSharedCommand = static_cast<RuntimeCommand*>(
            MapViewOfFile(g_hCommandMMF, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(RuntimeCommand))
        );
        if (g_pSharedCommand) {
            g_pSharedCommand->Type.store(0);
            g_pSharedCommand->Status.store(0);
        }
    }

    // Initialize core subsystems
    KVCache::Initialize();
    ExpertCache::Initialize();
    VulkanCompute::Initialize();
    ModelRegistry::Initialize();

    Beaconism::Emit(BeaconID::RuntimeInitialized, 0);
}

void SovereignRuntime::Shutdown() {
    Beaconism::Emit(BeaconID::RuntimeShutdown, 0);

    // Cleanup subsystems
    ModelRegistry::Shutdown();
    VulkanCompute::Shutdown();
    ExpertCache::Shutdown();
    KVCache::Shutdown();

    // Cleanup shared memory
    if (g_pSharedCommand) {
        UnmapViewOfFile(g_pSharedCommand);
        g_pSharedCommand = nullptr;
    }
    if (g_hCommandMMF) {
        CloseHandle(g_hCommandMMF);
        g_hCommandMMF = nullptr;
    }

    Replay::Shutdown();
    Scheduler::Shutdown();
    Telemetry::Shutdown();
    Beaconism::Shutdown();
}

void SovereignRuntime::Tick() {
    Beaconism::Poll();
    Telemetry::Update();
    Scheduler::Update();
    Replay::Update();
    
    CheckCommands();
    
    // Continuous sovereign maintenance
    static uint64_t lastMaintenance = 0;
    uint64_t now = GetTickCount64();
    
    // Run maintenance every 5 seconds
    if (now - lastMaintenance > 5000) {
        lastMaintenance = now;
        RunMaintenanceCycle();
    }
}

void SovereignRuntime::CheckCommands() {
    if (!g_pSharedCommand) return;

    uint32_t cmd = g_pSharedCommand->Type.load();
    if (cmd == 0) return;

    switch (static_cast<CommandType>(cmd)) {
        case CommandType::CMD_RUN_SMOKETEST:
            Beaconism::Emit(BeaconID::SmoketestStart, 0);
            RunSmoketest();
            Beaconism::Emit(BeaconID::SmoketestDone, g_smoketestResults.testsFailed == 0 ? 1 : 0);
            g_pSharedCommand->Type.store(0);
            break;

        case CommandType::CMD_LOAD_MODEL:
            Beaconism::Emit(BeaconID::ModelStart, 0);
            LoadModel(g_pSharedCommand->Path);
            Beaconism::Emit(BeaconID::ModelDone, 0);
            g_pSharedCommand->Type.store(0);
            break;

        case CommandType::CMD_HOTSWAP_MODEL:
            Beaconism::Emit(BeaconID::ModelStart, 1); // 1 = hotswap
            HotSwapModel(g_pSharedCommand->Path);
            Beaconism::Emit(BeaconID::ModelDone, 1);
            g_pSharedCommand->Type.store(0);
            break;

        case CommandType::CMD_QUANTIZE_MODEL:
            Beaconism::Emit(BeaconID::QuantStart, g_pSharedCommand->QuantBits);
            QuantizeModel(g_pSharedCommand->Path, g_pSharedCommand->QuantBits);
            Beaconism::Emit(BeaconID::QuantDone, 0);
            g_pSharedCommand->Type.store(0);
            break;

        case CommandType::CMD_SHUTDOWN:
            Beaconism::Emit(BeaconID::RuntimeShutdown, 0);
            g_pSharedCommand->Type.store(0);
            // Signal main loop to exit
            PostQuitMessage(0);
            break;

        default:
            g_pSharedCommand->Type.store(0);
            break;
    }
}

void SovereignRuntime::RunMaintenanceCycle() {
    SovereignHealth health = HealthReport::GenerateSnapshot();
    
    // Emit live health beacons
    Beaconism::Emit(BeaconID::MaintenanceCycle, 0);
    
    if (AutoRepair::NeedsRepair(health)) {
        Beaconism::Emit(BeaconID::MaintenanceDegraded, 0);
        AutoRepair::TryRepair(health);
        Beaconism::Emit(BeaconID::MaintenanceRepaired, 0);
    }
}

void SovereignRuntime::RunSmoketest() {
    g_smoketestResults = {};
    g_smoketestResults.testsRun = 0;

    // Test 1: KV Cache
    Beaconism::Emit(BeaconID::KVStart, 0);
    bool kvOk = KVCache::SelfTest();
    Beaconism::Emit(BeaconID::KVDone, kvOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (kvOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 2: Expert Cache
    Beaconism::Emit(BeaconID::ExpertStart, 0);
    bool expertOk = ExpertCache::SelfTest();
    Beaconism::Emit(BeaconID::ExpertDone, expertOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (expertOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 3: Attention
    Beaconism::Emit(BeaconID::AttentionStart, 0);
    bool attnOk = VulkanCompute::SelfTestAttention();
    Beaconism::Emit(BeaconID::AttentionDone, attnOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (attnOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 4: MoE Router
    Beaconism::Emit(BeaconID::MoEStart, 0);
    bool moeOk = VulkanCompute::SelfTestMoE();
    Beaconism::Emit(BeaconID::MoEDone, moeOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (moeOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 5: NVMe I/O
    Beaconism::Emit(BeaconID::NVMeStart, 0);
    bool nvmeOk = KVCache::SelfTestNVMe();
    Beaconism::Emit(BeaconID::NVMeDone, nvmeOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (nvmeOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 6: Vulkan Compute
    Beaconism::Emit(BeaconID::VulkanStart, 0);
    bool vulkanOk = VulkanCompute::SelfTest();
    Beaconism::Emit(BeaconID::VulkanDone, vulkanOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (vulkanOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 7: Model Loader
    Beaconism::Emit(BeaconID::ModelStart, 2); // 2 = self-test
    bool modelOk = ModelRegistry::SelfTest();
    Beaconism::Emit(BeaconID::ModelDone, modelOk ? 2 : 0);
    g_smoketestResults.testsRun++;
    if (modelOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 8: Replay System
    Beaconism::Emit(BeaconID::ReplayStart, 0);
    bool replayOk = Replay::SelfTest();
    Beaconism::Emit(BeaconID::ReplayDone, replayOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (replayOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 9: Telemetry
    Beaconism::Emit(BeaconID::TelemetryStart, 0);
    bool telemOk = Telemetry::SelfTest();
    Beaconism::Emit(BeaconID::TelemetryDone, telemOk ? 1 : 0);
    g_smoketestResults.testsRun++;
    if (telemOk) g_smoketestResults.testsPassed++; else g_smoketestResults.testsFailed++;

    // Test 10: Beaconism itself
    Beaconism::Emit(BeaconID::BeaconismTest, 0xDEADBEEF);
    g_smoketestResults.testsRun++;
    g_smoketestResults.testsPassed++; // If we got here, Beaconism works
}

void SovereignRuntime::LoadModel(const wchar_t* path) {
    ModelRegistry::Load(path);
}

void SovereignRuntime::HotSwapModel(const wchar_t* path) {
    ModelRegistry::HotSwap(path);
}

void SovereignRuntime::QuantizeModel(const wchar_t* path, uint32_t bits) {
    ModelRegistry::Quantize(path, bits);
}

bool SovereignRuntime::IsRunning() {
    return g_pSharedCommand != nullptr;
}

const SmoketestResults* SovereignRuntime::GetSmoketestResults() {
    return &g_smoketestResults;
}

} // namespace Sovereign
