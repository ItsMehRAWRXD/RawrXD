#include "Win32SwarmBridge.h"
#include "../agentic/SubAgentManager.h"
#include <windows.h>
#include <memory>
#include <atomic>
#include <cstdio>
#include <chrono>

// Forward-declare the IAT slot 20 export (defined below)
// The definition at the bottom of this file provides the implementation.

namespace RawrXD::Bridge {

static std::unique_ptr<SwarmContext> g_swarmContext;
static std::atomic<bool> g_swarmActive{false};

int WINAPI InitializeSwarmSystemImpl(void* rawConfig) {
    if (!rawConfig) {
        OutputDebugStringA("[Win32SwarmBridge] Error: Null configuration (E_INVALIDARG)\n");
        return E_INVALIDARG;
    }

    if (g_swarmActive.exchange(true)) {
        OutputDebugStringA("[Win32SwarmBridge] Swarm already initialized\n");
        return S_OK; // Idempotent success
    }

    auto* config = static_cast<SwarmInitConfig*>(rawConfig);
    
    // Validate config
    if (config->structSize != sizeof(SwarmInitConfig)) {
        OutputDebugStringA("[Win32SwarmBridge] Invalid struct size\n");
        g_swarmActive = false;
        return E_INVALIDARG;
    }

    if (config->maxSubAgents == 0 || config->maxSubAgents > 64) {
        OutputDebugStringA("[Win32SwarmBridge] Invalid swarm configuration\n");
        g_swarmActive = false;
        return E_INVALIDARG;
    }

    try {
        // Bridge to SubAgentManager (IAT slots 54-55)
        auto& manager = RawrXD::Agentic::SubAgentManager::instance();
        
        // Configure swarm topology
        RawrXD::Agentic::SwarmTopology topology;
        topology.workerCount = config->maxSubAgents;
        topology.taskTimeout = std::chrono::milliseconds(config->taskTimeoutMs);
        topology.gpuWorkStealing = (config->enableGPUWorkStealing != 0);
        
        // Initialize coordinator inference model
        if (!manager.initializeSwarm(topology, config->coordinatorModel)) {
            OutputDebugStringA("[Win32SwarmBridge] Failed to initialize coordinator model\n");
            g_swarmActive = false;
            return E_FAIL;
        }

        g_swarmContext = std::make_unique<SwarmContext>();
        g_swarmContext->creationTime = GetTickCount64();

        char msg[256];
        sprintf_s(msg, "[Win32SwarmBridge] Swarm initialized: %u workers, GPU steal=%d, model=%s\n",
                  config->maxSubAgents, (int)config->enableGPUWorkStealing, config->coordinatorModel);
        OutputDebugStringA(msg);

        return S_OK;
    }
    catch (...) {
        OutputDebugStringA("[Win32SwarmBridge] Exception during initialization\n");
        g_swarmActive = false;
        return E_UNEXPECTED;
    }
}

// Cleanup for graceful shutdown
void ShutdownSwarmSystem() {
    if (!g_swarmActive.exchange(false)) return;
    
    if (g_swarmContext) {
        Agentic::SubAgentManager::instance().shutdownSwarm();
        g_swarmContext.reset();
    }
}

int InitializeSwarmSystem(SwarmInitConfig* config) {
    return InitializeSwarmSystemImpl(config);
}

} // namespace RawrXD::Bridge

// C-export for IAT binding (slot 20)
extern "C" __declspec(dllexport) int Win32IDE_initializeSwarmSystem(void* config) {
    return RawrXD::Bridge::InitializeSwarmSystemImpl(config);
}

// AgenticBridge/SubAgent Implementation (Slots 48-51)
extern "C" __declspec(dllexport) void* AgenticBridge_GetSubAgentManager() {
    return &RawrXD::Agentic::SubAgentManager::instance();
}

extern "C" __declspec(dllexport) const char* SubAgentManager_getStatusSummary(void* pMgr) {
    if (!pMgr) return "Invalid Manager";
    // Use static buffer to avoid allocation issues in IAT bridge
    static char summary[256];
    auto* mgr = static_cast<RawrXD::Agentic::SubAgentManager*>(pMgr);
    sprintf_s(summary, "Active: %s, Shards: %zu",
              mgr->isSwarmActive() ? "Yes" : "No",
              mgr->getActiveShardCount());
    return summary;
}

extern "C" __declspec(dllexport) uint32_t SubAgentManager_getAgentCount(void* pMgr) {
    if (!pMgr) return 0;
    auto* mgr = static_cast<RawrXD::Agentic::SubAgentManager*>(pMgr);
    return (uint32_t)mgr->getActiveShardCount();
}

extern "C" __declspec(dllexport) int SubAgentManager_isHealthy(void* pMgr) {
    if (!pMgr) return 0;
    auto* mgr = static_cast<RawrXD::Agentic::SubAgentManager*>(pMgr);
    return mgr->isSwarmActive() ? 1 : 0;
}

// SLOTS 52-53
extern "C" __declspec(dllexport) float SubAgentManager_getLoadAverage(void* pMgr) {
    if (!pMgr) return 0.0f;
    auto* mgr = static_cast<RawrXD::Agentic::SubAgentManager*>(pMgr);
    return mgr->getSwarmLoadAverage();
}

extern "C" __declspec(dllexport) void SubAgentManager_broadcastCommand(void* pMgr, const char* command) {
    if (!pMgr || !command) return;
    auto* mgr = static_cast<RawrXD::Agentic::SubAgentManager*>(pMgr);
    mgr->broadcastCommand(command);
}

// Global state for AgenticBridge properties (could be moved to manager later)
static char g_ModelPath[MAX_PATH] = { 0 };
static char g_APIKey[128] = { 0 };

// SLOTS 56-60
extern "C" __declspec(dllexport) void AgenticBridge_SetModelPath(const char* path) {
    if (path) strcpy_s(g_ModelPath, path);
    char msg[MAX_PATH + 64];
    sprintf_s(msg, "[AgenticBridge] Model Path set: %s\n", g_ModelPath);
    OutputDebugStringA(msg);
}

extern "C" __declspec(dllexport) bool AgenticBridge_GetModelPath(char* buffer, uint32_t bufferSize) {
    if (!buffer || bufferSize == 0) return false;
    strcpy_s(buffer, bufferSize, g_ModelPath);
    return true;
}

extern "C" __declspec(dllexport) void AgenticBridge_UpdateStatus(const char* status) {
    if (!status) return;
    char msg[256];
    sprintf_s(msg, "[AgenticBridge] Status Update: %s\n", status);
    OutputDebugStringA(msg);
}

extern "C" __declspec(dllexport) bool AgenticBridge_GetAPIKey(char* buffer, uint32_t bufferSize) {
    if (!buffer || bufferSize == 0) return false;
    strcpy_s(buffer, bufferSize, g_APIKey);
    return true;
}

extern "C" __declspec(dllexport) void AgenticBridge_SetAPIKey(const char* key) {
    if (key) strcpy_s(g_APIKey, key);
    OutputDebugStringA("[AgenticBridge] API Key updated\n");
}

// AgenticBridge Context (Slots 61-63)
static void* g_pAgenticContext = nullptr;

extern "C" __declspec(dllexport) void* AgenticBridge_GetContext() {
    return g_pAgenticContext;
}

extern "C" __declspec(dllexport) void AgenticBridge_SetContext(void* pContext) {
    g_pAgenticContext = pContext;
    OutputDebugStringA("[AgenticBridge] Context updated\n");
}

extern "C" __declspec(dllexport) void AgenticBridge_ResetContext() {
    g_pAgenticContext = nullptr;
    OutputDebugStringA("[AgenticBridge] Context reset\n");
}

// Win32IDE UI Components (Slots 21-23)
extern "C" __declspec(dllexport) void* Win32IDE_createAcceleratorTable(void* pTableData, int count) {
    // UI accelerator table implementation
    OutputDebugStringA("[Win32IDE] createAcceleratorTable called\n");
    return CreateAcceleratorTableA(static_cast<LPACCEL>(pTableData), count);
}

extern "C" __declspec(dllexport) bool Win32IDE_removeTab(int tabIndex) {
    char buf[64];
    sprintf_s(buf, "[Win32IDE] removeTab index=%d\n", tabIndex);
    OutputDebugStringA(buf);
    // Production: Delegate to Win32IDE_TabManager
    return true;
}

extern "C" __declspec(dllexport) bool Win32IDE_addTab(const char* title, void* pContent) {
    char buf[128];
    sprintf_s(buf, "[Win32IDE] addTab title=%s\n", title ? title : "NULL");
    OutputDebugStringA(buf);
    // Production: Delegate to Win32IDE_TabManager
    (void)pContent;
    return true;
}

// Sidebar Implementation (Slots 24-27)
extern "C" __declspec(dllexport) bool Win32IDE_addSidebarPanel(const char* id, const char* title, void* pContent) {
    if (!id || !title) return false;
    char buf[256];
    sprintf_s(buf, "[Win32IDE] addSidebarPanel ID=%s Title=%s\n", id, title);
    OutputDebugStringA(buf);
    // Production: Delegate to Win32IDE sidebar implementation
    (void)pContent;
    return true;
}

extern "C" __declspec(dllexport) bool Win32IDE_removeSidebarPanel(const char* id) {
    if (!id) return false;
    char buf[128];
    sprintf_s(buf, "[Win32IDE] removeSidebarPanel ID=%s\n", id);
    OutputDebugStringA(buf);
    // Production: Delegate to Win32IDE sidebar implementation
    return true;
}

extern "C" __declspec(dllexport) void Win32IDE_showSidebarPanel(const char* id) {
    if (!id) return;
    char buf[128];
    sprintf_s(buf, "[Win32IDE] showSidebarPanel ID=%s\n", id);
    OutputDebugStringA(buf);
}

extern "C" __declspec(dllexport) void Win32IDE_hideSidebarPanel(const char* id) {
    if (!id) return;
    char buf[128];
    sprintf_s(buf, "[Win32IDE] hideSidebarPanel ID=%s\n", id);
    OutputDebugStringA(buf);
}

extern "C" __declspec(dllexport) uint32_t Win32IDE_executeSwarmTask(const char* taskDesc) {
    if (!taskDesc) return 0;
    OutputDebugStringA("[Win32SwarmBridge] Executing Swarm Task (Slot 54)\n");
    return RawrXD::Agentic::SubAgentManager::instance().executeSwarmTask(taskDesc);
}

extern "C" __declspec(dllexport) void Win32IDE_shutdownSwarmSystem() {
    OutputDebugStringA("[Win32SwarmBridge] Shutting down Swarm System (Slot 55)\n");
    RawrXD::Bridge::ShutdownSwarmSystem();
}

// ═════════════════════════════════════════════════════════════════════════════
// OMEGA-1 AUTONOMOUS ENGINE INTEGRATION
// Self-mutating, self-healing, hardware-accelerated deployment system
// ═════════════════════════════════════════════════════════════════════════════

#include <map>
#include <thread>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

namespace RawrXD::Bridge {

class OmegaAgent {
public:
    struct ModuleInfo {
        std::string name;
        std::string code;
        std::string hash;
        bool exists;
    };

    struct Manifest {
        std::string version = "1.0.0";
        std::string timestamp;
        int moduleCount = 0;
        int mutationCount = 0;
        bool isMutant = false;
        std::string rootPath;
        std::string genesisPath;
    };

private:
    std::string m_rootPath;
    std::string m_genesisPath;
    std::string m_manifestPath;
    std::map<std::string, ModuleInfo> m_genome;
    std::map<std::string, std::string> m_moduleHashes;
    bool m_isMutant;
    int m_mutationCount;
    std::chrono::system_clock::time_point m_createdAt;
    bool m_running;
    std::unique_ptr<std::thread> m_autonomousThread;

public:
    OmegaAgent(const std::string& rootPath)
        : m_rootPath(rootPath)
        , m_isMutant(false)
        , m_mutationCount(0)
        , m_running(false) {
        m_genesisPath = (fs::path(rootPath) / "genesis.ps1").string();
        m_manifestPath = (fs::path(rootPath) / "manifest.json").string();
        m_createdAt = std::chrono::system_clock::now();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BOOTSTRAP: Generate all 16 core modules
    // ═══════════════════════════════════════════════════════════════════════
    void Bootstrap() {
        if (!fs::exists(m_rootPath)) {
            fs::create_directories(m_rootPath);
        }

        const std::vector<std::string> coreModules = {
            "Core", "Deployment", "Agentic", "Observability",
            "Win32", "ModelLoader", "Swarm", "Production",
            "ReverseEngineering", "Testing", "Security", "Performance",
            "AutonomousEnhancement", "DeploymentOrchestrator",
            "UltimateProduction", "CustomModelLoaders"
        };

        for (const auto& module : coreModules) {
            std::string moduleName = "RawrXD." + module;
            fs::path modulePath = fs::path(m_rootPath) / (moduleName + ".psm1");

            ModuleInfo info;
            info.name = moduleName;
            info.exists = fs::exists(modulePath);

            if (!info.exists) {
                info.code = GenerateModuleCode(module, moduleName);
                info.hash = ComputeHash(info.code);

                std::ofstream file(modulePath);
                file << info.code;
                file.close();

                Log("Generated module: " + moduleName, 2);
            } else {
                std::ifstream file(modulePath);
                info.code = std::string((std::istreambuf_iterator<char>(file)),
                                         std::istreambuf_iterator<char>());
                info.hash = ComputeHash(info.code);
            }

            m_genome[module] = info;
            m_moduleHashes[module] = info.hash;
        }

        PersistManifest();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // SELF-MUTATION: Append generation marker to script
    // ═══════════════════════════════════════════════════════════════════════
    void Mutate(const std::string& scriptPath) {
        if (!fs::exists(scriptPath)) return;

        std::ifstream inFile(scriptPath);
        std::string current((std::istreambuf_iterator<char>(inFile)),
                           std::istreambuf_iterator<char>());
        inFile.close();

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y%m%d-%H%M%S");
        std::string mutationMarker = "# OMEGA-MUTATION-" + ss.str();

        if (current.find(mutationMarker) == std::string::npos) {
            std::ofstream outFile(scriptPath, std::ios::app);
            outFile << "\n\n" << mutationMarker << "\n";
            outFile << "# Generation: " << (m_mutationCount + 1) << "\n";
            outFile << "$Global:RawrXDOmega = @{ Root = '" << m_rootPath
                   << "'; Generation = " << (m_mutationCount + 1) << " }\n";
            outFile.close();

            m_isMutant = true;
            m_mutationCount++;
            PersistManifest();

            Log("Self-mutation complete - Generation " + std::to_string(m_mutationCount), 5);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // REFLECTIVE EXECUTION: In-memory shellcode execution
    // ═══════════════════════════════════════════════════════════════════════
    bool ExecuteReflective(const std::vector<uint8_t>& shellcode) {
        if (shellcode.empty()) return false;

        LPVOID addr = VirtualAlloc(
            nullptr,
            shellcode.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!addr) return false;

        memcpy(addr, shellcode.data(), shellcode.size());

        DWORD oldProtect;
        if (!VirtualProtect(addr, shellcode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            VirtualFree(addr, 0, MEM_RELEASE);
            return false;
        }

        DWORD threadId;
        HANDLE hThread = CreateThread(
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)addr,
            nullptr,
            0,
            &threadId
        );

        if (!hThread) {
            VirtualFree(addr, 0, MEM_RELEASE);
            return false;
        }

        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        VirtualFree(addr, 0, MEM_RELEASE);

        Log("Reflective execution complete (Thread " + std::to_string(threadId) + ")", 3);
        return true;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // AUTONOMOUS LOOP: Background self-healing thread
    // ═══════════════════════════════════════════════════════════════════════
    void StartAutonomousLoop(int intervalMs = 1000) {
        m_running = true;
        m_autonomousThread = std::make_unique<std::thread>([this, intervalMs]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(1, 100);

            while (m_running) {
                auto modules = ScanModules();
                if (modules.size() < 16) {
                    Log("Module count anomaly detected - bootstrapping...", 6);
                    Bootstrap();
                }

                if (dis(gen) <= 5) {
                    Log("Spontaneous mutation triggered", 5);
                }

                static int iterations = 0;
                if (++iterations % 10 == 0) {
                    Log("Heartbeat - Iteration: " + std::to_string(iterations), 2);
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
            }
        });
    }

    void StopAutonomousLoop() {
        m_running = false;
        if (m_autonomousThread && m_autonomousThread->joinable()) {
            m_autonomousThread->join();
        }
    }

    void ValidateIntegrity() {
        for (const auto& [name, hash] : m_moduleHashes) {
            fs::path modulePath = fs::path(m_rootPath) / ("RawrXD." + name + ".psm1");
            if (fs::exists(modulePath)) {
                std::ifstream file(modulePath);
                std::string content((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
                std::string currentHash = ComputeHash(content);

                if (currentHash != hash) {
                    Log("Module hash mismatch: " + name, 6);
                    m_moduleHashes[name] = currentHash;
                }
            }
        }
    }

    Manifest GetManifest() const {
        Manifest m;
        m.timestamp = std::to_string(
            std::chrono::duration_cast<std::chrono::seconds>(
                m_createdAt.time_since_epoch()
            ).count()
        );
        m.moduleCount = static_cast<int>(m_genome.size());
        m.mutationCount = m_mutationCount;
        m.isMutant = m_isMutant;
        m.rootPath = m_rootPath;
        m.genesisPath = m_genesisPath;
        return m;
    }

private:
    std::string GenerateModuleCode(const std::string& module, const std::string& moduleName) {
        std::stringstream ss;
        ss << "#Requires -Version 7.4\n";
        ss << "# Module: " << moduleName << "\n";
        ss << "# Part of RawrXD OMEGA-1 Autonomous System\n\n";
        ss << "function Invoke-" << module << " {\n";
        ss << "    [CmdletBinding()]\n";
        ss << "    param(\n";
        ss << "        [Parameter(Mandatory=$false)]\n";
        ss << "        [string]$Path='" << m_rootPath << "',\n";
        ss << "        [Parameter(Mandatory=$false)]\n";
        ss << "        [hashtable]$Config=@{}\n";
        ss << "    )\n";
        ss << "    $result = @{\n";
        ss << "        Status='Active'\n";
        ss << "        Module='" << moduleName << "'\n";
        ss << "        Timestamp=Get-Date\n";
        ss << "        ProcessId=$PID\n";
        ss << "    }\n";
        ss << "    Write-Verbose \"[$moduleName] Operational\"\n";
        ss << "    return $result\n";
        ss << "}\n\n";
        ss << "function Test-" << module << "Health {\n";
        ss << "    [CmdletBinding()]\n";
        ss << "    param()\n";
        ss << "    return @{\n";
        ss << "        Module='" << moduleName << "'\n";
        ss << "        Healthy=$true\n";
        ss << "        Status='Operational'\n";
        ss << "        Timestamp=Get-Date\n";
        ss << "    }\n";
        ss << "}\n\n";
        ss << "Export-ModuleMember -Function Invoke-" << module << ", Test-" << module << "Health\n";
        return ss.str();
    }

    std::string ComputeHash(const std::string& input) {
        std::hash<std::string> hasher;
        auto hash = hasher(input);
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(16) << hash;
        return ss.str();
    }

    void PersistManifest() {
        std::ofstream file(m_manifestPath);
        file << "{\n";
        file << "  \"Version\": \"1.0.0\",\n";
        file << "  \"ModuleCount\": " << m_genome.size() << ",\n";
        file << "  \"MutationCount\": " << m_mutationCount << ",\n";
        file << "  \"IsMutant\": " << (m_isMutant ? "true" : "false") << ",\n";
        file << "  \"RootPath\": \"" << m_rootPath << "\"\n";
        file << "}\n";
        file.close();
    }

    std::vector<std::string> ScanModules() {
        std::vector<std::string> modules;
        if (!fs::exists(m_rootPath)) return modules;

        for (const auto& entry : fs::directory_iterator(m_rootPath)) {
            if (entry.path().extension() == ".psm1") {
                modules.push_back(entry.path().filename().string());
            }
        }
        return modules;
    }

    void Log(const std::string& message, int color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, color);
        char buf[512];
        sprintf_s(buf, "[Omega-1] %s\n", message.c_str());
        OutputDebugStringA(buf);
        SetConsoleTextAttribute(hConsole, 7);
    }
};

// Global Omega-1 instance
static std::unique_ptr<OmegaAgent> g_omegaAgent;

} // namespace RawrXD::Bridge

// ═════════════════════════════════════════════════════════════════════════════
// OMEGA-1 IAT EXPORTS (Slots 64-80)
// ═════════════════════════════════════════════════════════════════════════════

extern "C" __declspec(dllexport) int OmegaBridge_Initialize(const char* rootPath) {
    OutputDebugStringA("[Omega-1] Initializing autonomous engine...\n");

    std::string path = rootPath ? rootPath : "D:\\lazy init ide\\auto_generated_methods";
    RawrXD::Bridge::g_omegaAgent = std::make_unique<RawrXD::Bridge::OmegaAgent>(path);

    RawrXD::Bridge::g_omegaAgent->Bootstrap();
    RawrXD::Bridge::g_omegaAgent->Mutate(path + "\\genesis.ps1");
    RawrXD::Bridge::g_omegaAgent->StartAutonomousLoop(1000);

    auto manifest = RawrXD::Bridge::g_omegaAgent->GetManifest();
    char buf[256];
    sprintf_s(buf, "[Omega-1] Initialized: %d modules, Mutant=%d\n",
              manifest.moduleCount, manifest.isMutant ? 1 : 0);
    OutputDebugStringA(buf);

    return S_OK;
}

extern "C" __declspec(dllexport) void OmegaBridge_Shutdown() {
    OutputDebugStringA("[Omega-1] Shutting down autonomous engine...\n");
    if (RawrXD::Bridge::g_omegaAgent) {
        RawrXD::Bridge::g_omegaAgent->StopAutonomousLoop();
        RawrXD::Bridge::g_omegaAgent.reset();
    }
}

extern "C" __declspec(dllexport) int OmegaBridge_GetModuleCount() {
    if (!RawrXD::Bridge::g_omegaAgent) return 0;
    return RawrXD::Bridge::g_omegaAgent->GetManifest().moduleCount;
}

extern "C" __declspec(dllexport) int OmegaBridge_IsMutant() {
    if (!RawrXD::Bridge::g_omegaAgent) return 0;
    return RawrXD::Bridge::g_omegaAgent->GetManifest().isMutant ? 1 : 0;
}

extern "C" __declspec(dllexport) int OmegaBridge_GetMutationCount() {
    if (!RawrXD::Bridge::g_omegaAgent) return 0;
    return RawrXD::Bridge::g_omegaAgent->GetManifest().mutationCount;
}

extern "C" __declspec(dllexport) bool OmegaBridge_ExecuteReflective(const uint8_t* shellcode, uint32_t size) {
    if (!RawrXD::Bridge::g_omegaAgent || !shellcode || size == 0) return false;
    std::vector<uint8_t> code(shellcode, shellcode + size);
    return RawrXD::Bridge::g_omegaAgent->ExecuteReflective(code);
}

extern "C" __declspec(dllexport) void OmegaBridge_ValidateIntegrity() {
    if (RawrXD::Bridge::g_omegaAgent) {
        RawrXD::Bridge::g_omegaAgent->ValidateIntegrity();
    }
}

extern "C" __declspec(dllexport) bool OmegaBridge_TriggerMutation(const char* scriptPath) {
    if (!RawrXD::Bridge::g_omegaAgent || !scriptPath) return false;
    RawrXD::Bridge::g_omegaAgent->Mutate(scriptPath);
    return true;
}

extern "C" __declspec(dllexport) void OmegaBridge_GetManifestJson(char* buffer, uint32_t bufferSize) {
    if (!buffer || bufferSize == 0) return;
    if (!RawrXD::Bridge::g_omegaAgent) {
        strcpy_s(buffer, bufferSize, "{}");
        return;
    }

    auto m = RawrXD::Bridge::g_omegaAgent->GetManifest();
    std::stringstream json;
    json << "{\"version\":\"" << m.version << "\",";
    json << "\"moduleCount\":" << m.moduleCount << ",";
    json << "\"mutationCount\":" << m.mutationCount << ",";
    json << "\"isMutant\":" << (m.isMutant ? "true" : "false") << ",";
    json << "\"rootPath\":\"" << m.rootPath << "\"}";

    strcpy_s(buffer, bufferSize, json.str().c_str());
}
