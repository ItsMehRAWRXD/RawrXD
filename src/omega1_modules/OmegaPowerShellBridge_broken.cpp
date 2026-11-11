// ═════════════════════════════════════════════════════════════════════════════
// RawrXD OMEGA-1 PowerShell Bridge
// Native C++ to PowerShell execution harness
// ═════════════════════════════════════════════════════════════════════════════

#include "OmegaPowerShellBridge.h"

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <memory>

namespace fs = std::filesystem;

namespace RawrXD::Bridge {

// PowerShellExecutor method implementations
PowerShellExecutor::PowerShellExecutor(const std::string& modulePath) : m_modulePath(modulePath) {
    ZeroMemory(&m_sa, sizeof(m_sa));
    m_sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    m_sa.bInheritHandle = TRUE;
    m_sa.lpSecurityDescriptor = nullptr;
}

PowerShellExecutor::~PowerShellExecutor() {
    CleanupPipes();
}

bool PowerShellExecutor::Initialize() {
    // Create pipes for stdout capture
    if (!CreatePipe(&m_hReadPipe, &m_hWritePipe, &m_sa, 0)) {
        return false;
    }

    // Ensure read handle is not inherited
    SetHandleInformation(m_hReadPipe, HANDLE_FLAG_INHERIT, 0);
    return true;
}

bool PowerShellExecutor::ExecuteCommand(const char* command, char* output, uint32_t outputSize) {
        if (!command || !output || outputSize == 0) return false;

        std::string psCommand = BuildPowerShellCommand(command);
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        si.hStdOutput = m_hWritePipe;
        si.hStdError = m_hWritePipe;
        si.dwFlags |= STARTF_USESTDHANDLES;

        // PowerShell execution with bypass policy
        std::string cmdLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"" + psCommand + "\"";
        
        char* cmdBuffer = new char[cmdLine.length() + 1];
        strcpy_s(cmdBuffer, cmdLine.length() + 1, cmdLine.c_str());

        BOOL success = CreateProcessA(
            nullptr,
            cmdBuffer,
            nullptr,
            nullptr,
            TRUE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi
        );

        delete[] cmdBuffer;

        if (!success) {
            return false;
        }

        // Close write end of pipe so ReadFile will return
        CloseHandle(m_hWritePipe);
        m_hWritePipe = nullptr;

        // Read output
        DWORD bytesRead = 0;
        std::string result;
        char buffer[4096];
        
        while (ReadFile(m_hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            result += buffer;
        }

        // Wait for process to complete
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        // Copy result to output buffer
        strncpy_s(output, outputSize, result.c_str(), _TRUNCATE);
        
        // Recreate pipes for next execution
        CleanupPipes();
        Initialize();
        
        return true;
    }

    bool LoadModule(const char* moduleName) {
        if (!moduleName) return false;
        
        fs::path modulePath = fs::path(m_modulePath) / (std::string("RawrXD.") + moduleName + ".psm1");
        if (!fs::exists(modulePath)) {
            return false;
        }

        std::stringstream ss;
        ss << "Import-Module '" << modulePath.string() << "' -Force -Global";
        
        char output[1024];
        return ExecuteCommand(ss.str().c_str(), output, sizeof(output));
    }

    bool InvokeModuleFunction(const char* moduleName, const char* function, char* output, uint32_t outputSize) {
        if (!moduleName || !function) return false;
        
        std::stringstream ss;
        ss << "Import-Module '" << m_modulePath << "\RawrXD." << moduleName << ".psm1' -Force; ";
        ss << "&" << function << " | ConvertTo-Json -Depth 5";
        
        return ExecuteCommand(ss.str().c_str(), output, outputSize);
    }

    bool ExecuteOmegaBootstrap() {
        std::stringstream ss;
        ss << "$env:RAWRXD_OMEGA_ROOT='" << m_modulePath << "'; ";
        ss << "Get-ChildItem '" << m_modulePath << "' -Filter 'RawrXD.*.psm1' | ForEach-Object { ";
        ss << "    Import-Module $_.FullName -Force -Global; ";
        ss << "    Write-Host ('Loaded: ' + $_.BaseName) -ForegroundColor Green ";
        ss << "}; ";
        ss << "Write-Host '[Ω] OMEGA-1 Bootstrap Complete' -ForegroundColor Cyan";
        
        char output[8192];
        return ExecuteCommand(ss.str().c_str(), output, sizeof(output));
    }

private:
    std::string BuildPowerShellCommand(const char* userCommand) {
        std::stringstream ss;
        // Set environment and execute
        ss << "$env:RAWRXD_OMEGA_ROOT='" << m_modulePath << "'; ";
        ss << userCommand;
        return ss.str();
    }

    void CleanupPipes() {
        if (m_hReadPipe) {
            CloseHandle(m_hReadPipe);
            m_hReadPipe = nullptr;
        }
        if (m_hWritePipe) {
            CloseHandle(m_hWritePipe);
            m_hWritePipe = nullptr;
        }
    }
};

// Global executor instance
static std::unique_ptr<PowerShellExecutor> g_psExecutor;

bool InitializePowerShellBridge(const char* modulePath) {
    if (!modulePath) return false;
    
    g_psExecutor = std::make_unique<PowerShellExecutor>(modulePath);
    if (!g_psExecutor->Initialize()) {
        g_psExecutor.reset();
        return false;
    }
    
    // Bootstrap all modules
    return g_psExecutor->ExecuteOmegaBootstrap();
}

void ShutdownPowerShellBridge() {
    g_psExecutor.reset();
}

// ═════════════════════════════════════════════════════════════════════════
// PowerShellExecutor Method Implementations (declared in header)
// ═════════════════════════════════════════════════════════════════════════

void PowerShellExecutor::CleanupPipes() {
    if (m_hReadPipe) {
        CloseHandle(m_hReadPipe);
        m_hReadPipe = nullptr;
    }
    if (m_hWritePipe) {
        CloseHandle(m_hWritePipe);
        m_hWritePipe = nullptr;
    }
}

std::string PowerShellExecutor::BuildPowerShellCommand(const char* userCommand) {
    std::stringstream ss;
    ss << "$env:RAWRXD_OMEGA_ROOT='" << m_modulePath << "'; ";
    ss << userCommand;
    return ss.str();
}

bool PowerShellExecutor::ExecuteGenesis() {
    fs::path genesisPath = fs::path(m_modulePath) / "genesis.ps1";
    if (!fs::exists(genesisPath)) {
        return false;
    }
    
    std::stringstream ss;
    ss << "& '" << genesisPath.string() << "'";
    
    char output[8192];
    return ExecuteCommand(ss.str().c_str(), output, sizeof(output));
}

bool PowerShellExecutor::GetModuleManifest(const char* moduleName, char* output, uint32_t outputSize) {
    if (!moduleName || !output || outputSize == 0) return false;
    
    std::stringstream ss;
    ss << "Get-Module 'RawrXD." << moduleName << "' | Select-Object Name, Version, ExportedCommands | ConvertTo-Json -Depth 3";
    
    return ExecuteCommand(ss.str().c_str(), output, outputSize);
}

// ═════════════════════════════════════════════════════════════════════════
// Omega1Engine Implementation
// ═════════════════════════════════════════════════════════════════════════

Omega1Engine::Omega1Engine() : m_pContext(nullptr), m_pExecutor(nullptr) {}

Omega1Engine::~Omega1Engine() {
    Shutdown();
}

bool Omega1Engine::Initialize(uint32_t flags) {
    if (m_pContext) return false; // Already initialized
    
    void* pCtx = nullptr;
    if (!Omega1_Initialize(&pCtx, flags)) {
        return false;
    }
    
    m_pContext = static_cast<Omega1Context*>(pCtx);
    
    // Initialize PowerShell bridge
    std::string modulePath = Omega1Utils::GetModulePath();
    if (!InitializePowerShellBridge(modulePath.c_str())) {
        Omega1_Shutdown(m_pContext);
        m_pContext = nullptr;
        return false;
    }
    
    m_pExecutor = g_psExecutor.get();
    return true;
}

void Omega1Engine::Shutdown() {
    if (m_pContext) {
        ShutdownPowerShellBridge();
        Omega1_Shutdown(m_pContext);
        m_pContext = nullptr;
        m_pExecutor = nullptr;
    }
}

uint32_t Omega1Engine::GetModuleCount() const {
    return Omega1_GetModuleCount(m_pContext);
}

std::vector<Omega1ModuleInfo> Omega1Engine::GetLoadedModules() const {
    std::vector<Omega1ModuleInfo> result;
    auto modules = Omega1Utils::DiscoverModules();
    
    for (const auto& mod : modules) {
        Omega1ModuleInfo info;
        strncpy_s(info.name, mod.c_str(), sizeof(info.name) - 1);
        strncpy_s(info.version, "1.0.0", sizeof(info.version) - 1);
        info.slotIndex = 0;
        info.loaded = true;
        result.push_back(info);
    }
    
    return result;
}

HPSMODULE Omega1Engine::LoadModule(const char* moduleName) {
    return Omega1_LoadModule(m_pContext, moduleName);
}

bool Omega1Engine::InvokeModule(HPSMODULE hModule, const char* function, char* output, uint32_t outputSize) {
    return Omega1_InvokeModule(m_pContext, hModule, function, output, outputSize);
}

bool Omega1Engine::IsMutant() const {
    return Omega1_IsMutant(m_pContext) == TRUE;
}

uint32_t Omega1Engine::GetMutationCount() const {
    return Omega1_GetMutationCount(m_pContext);
}

bool Omega1Engine::TriggerMutation(uint32_t mutationType) {
    return Omega1_TriggerMutation(m_pContext, mutationType) == TRUE;
}

bool Omega1Engine::ExecuteReflective(const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize) {
    return Omega1_ExecuteReflective(m_pContext, payload, payloadSize, output, outputSize) == TRUE;
}

bool Omega1Engine::ExecutePowerShell(const char* command, char* output, uint32_t outputSize) {
    return Omega1_ExecutePowerShell(m_pContext, command, output, outputSize) == TRUE;
}

bool Omega1Engine::ValidateIntegrity(uint32_t* pChecksum) {
    return Omega1_ValidateIntegrity(m_pContext, pChecksum) == TRUE;
}

std::string Omega1Engine::GetManifestJson() const {
    char buffer[8192];
    if (Omega1_GetManifestJson(m_pContext, buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    return "{}";
}

bool Omega1Engine::BootstrapFromGenesis() {
    if (!m_pExecutor) return false;
    return m_pExecutor->ExecuteGenesis();
}

// ═════════════════════════════════════════════════════════════════════════
// Utility Functions
// ═════════════════════════════════════════════════════════════════════════

namespace Omega1Utils {

std::string GetModulePath() {
    char buffer[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        fs::path exePath(buffer);
        return (exePath.parent_path() / "omega1_modules").string();
    }
    return ".\\omega1_modules";
}

bool ValidateModuleExists(const char* moduleName) {
    if (!moduleName) return false;
    
    fs::path modulePath = fs::path(GetModulePath()) / (std::string("RawrXD.") + moduleName + ".psm1");
    return fs::exists(modulePath);
}

std::vector<std::string> DiscoverModules() {
    std::vector<std::string> modules;
    fs::path moduleDir = GetModulePath();
    
    if (fs::exists(moduleDir) && fs::is_directory(moduleDir)) {
        for (const auto& entry : fs::directory_iterator(moduleDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".psm1") {
                std::string filename = entry.path().stem().string();
                // Strip "RawrXD." prefix if present
                const std::string prefix = "RawrXD.";
                if (filename.find(prefix) == 0) {
                    filename = filename.substr(prefix.length());
                }
                modules.push_back(filename);
            }
        }
    }
    
    return modules;
}

std::string GetOmegaRoot() {
    const char* envRoot = getenv("RAWRXD_OMEGA_ROOT");
    if (envRoot) return std::string(envRoot);
    return GetModulePath();
}

} // namespace Omega1Utils

} // namespace RawrXD::Bridge

// ═════════════════════════════════════════════════════════════════════════════
// C EXPORTS FOR IAT BINDING
// ═════════════════════════════════════════════════════════════════════════════

extern "C" __declspec(dllexport) bool OmegaBridge_ExecutePowerShell(const char* command, char* output, uint32_t outputSize) {
    if (!RawrXD::Bridge::g_psExecutor || !command || !output || outputSize == 0) {
        return false;
    }
    return RawrXD::Bridge::g_psExecutor->ExecuteCommand(command, output, outputSize);
}

extern "C" __declspec(dllexport) bool OmegaBridge_LoadModule(const char* moduleName) {
    if (!RawrXD::Bridge::g_psExecutor || !moduleName) return false;
    return RawrXD::Bridge::g_psExecutor->LoadModule(moduleName);
}

extern "C" __declspec(dllexport) bool OmegaBridge_InvokeModule(const char* moduleName, const char* function, char* output, uint32_t outputSize) {
    if (!RawrXD::Bridge::g_psExecutor || !moduleName || !function || !output || outputSize == 0) {
        return false;
    }
    return RawrXD::Bridge::g_psExecutor->InvokeModuleFunction(moduleName, function, output, outputSize);
}

extern "C" __declspec(dllexport) bool OmegaBridge_InitializePowerShell(const char* modulePath) {
    return RawrXD::Bridge::InitializePowerShellBridge(modulePath);
}

extern "C" __declspec(dllexport) void OmegaBridge_ShutdownPowerShell() {
    RawrXD::Bridge::ShutdownPowerShellBridge();
}

// ═════════════════════════════════════════════════════════════════════════════
// IAT EXPORT FUNCTIONS (Slots 64-75)
// ═════════════════════════════════════════════════════════════════════════════

// Slot 64: Initialize
extern "C" __declspec(dllexport) BOOL Omega1_Initialize(void** ppContext, uint32_t flags) {
    if (!ppContext) return FALSE;
    
    auto* pContext = new RawrXD::Bridge::Omega1Context();
    ZeroMemory(pContext, sizeof(RawrXD::Bridge::Omega1Context));
    pContext->flags = flags;
    pContext->isMutant = (flags & OMEGA1_FLAG_MUTANT) ? TRUE : FALSE;
    pContext->mutationCount = 0;
    
    *ppContext = pContext;
    return TRUE;
}

// Slot 65: Shutdown
extern "C" __declspec(dllexport) void Omega1_Shutdown(void* pContext) {
    if (pContext) {
        auto* pCtx = static_cast<RawrXD::Bridge::Omega1Context*>(pContext);
        delete pCtx;
    }
}

// Slot 66: GetModuleCount
extern "C" __declspec(dllexport) uint32_t Omega1_GetModuleCount(void* pContext) {
    if (!pContext) return 0;
    // Return count of discovered PowerShell modules
    auto modules = RawrXD::Bridge::Omega1Utils::DiscoverModules();
    return static_cast<uint32_t>(modules.size());
}

// Slot 67: IsMutant
extern "C" __declspec(dllexport) BOOL Omega1_IsMutant(void* pContext) {
    if (!pContext) return FALSE;
    auto* pCtx = static_cast<RawrXD::Bridge::Omega1Context*>(pContext);
    return pCtx->isMutant;
}

// Slot 68: GetMutationCount
extern "C" __declspec(dllexport) uint32_t Omega1_GetMutationCount(void* pContext) {
    if (!pContext) return 0;
    auto* pCtx = static_cast<RawrXD::Bridge::Omega1Context*>(pContext);
    return pCtx->mutationCount;
}

// Slot 69: ExecuteReflective
extern "C" __declspec(dllexport) BOOL Omega1_ExecuteReflective(void* pContext, const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize) {
    if (!pContext || !payload || !output || outputSize == 0) return FALSE;
    
    auto* pCtx = static_cast<RawrXD::Bridge::Omega1Context*>(pContext);
    pCtx->mutationCount++;
    
    // Execute as PowerShell command
    if (RawrXD::Bridge::g_psExecutor) {
        return RawrXD::Bridge::g_psExecutor->ExecuteCommand(payload, output, outputSize);
    }
    return FALSE;
}

// Slot 70: ValidateIntegrity
extern "C" __declspec(dllexport) BOOL Omega1_ValidateIntegrity(void* pContext, uint32_t* pChecksum) {
    if (!pContext || !pChecksum) return FALSE;
    
    // Simple checksum of module directory
    auto modules = RawrXD::Bridge::Omega1Utils::DiscoverModules();
    uint32_t checksum = 0;
    for (const auto& mod : modules) {
        for (char c : mod) {
            checksum = checksum * 31 + c;
        }
    }
    *pChecksum = checksum;
    return TRUE;
}

// Slot 71: TriggerMutation
extern "C" __declspec(dllexport) BOOL Omega1_TriggerMutation(void* pContext, uint32_t mutationType) {
    if (!pContext) return FALSE;
    
    auto* pCtx = static_cast<RawrXD::Bridge::Omega1Context*>(pContext);
    pCtx->mutationCount++;
    pCtx->isMutant = TRUE;
    
    // Execute genesis.ps1 for mutation type 3
    if (mutationType == OMEGA1_MUTATION_GENESIS) {
        char output[8192];
        std::string cmd = "& '" + RawrXD::Bridge::Omega1Utils::GetOmegaRoot() + "/genesis.ps1'";
        if (RawrXD::Bridge::g_psExecutor) {
            return RawrXD::Bridge::g_psExecutor->ExecuteCommand(cmd.c_str(), output, sizeof(output));
        }
    }
    
    return TRUE;
}

// Slot 72: GetManifestJson
extern "C" __declspec(dllexport) BOOL Omega1_GetManifestJson(void* pContext, char* buffer, uint32_t bufferSize) {
    if (!pContext || !buffer || bufferSize == 0) return FALSE;
    
    auto modules = RawrXD::Bridge::Omega1Utils::DiscoverModules();
    std::stringstream json;
    json << "{\n";
    json << "  \"version\": \"" << OMEGA1_VERSION_STRING << "\",\n";
    json << "  \"modules\": [\n";
    
    for (size_t i = 0; i < modules.size(); ++i) {
        json << "    \"" << modules[i] << "\"";
        if (i < modules.size() - 1) json << ",";
        json << "\n";
    }
    
    json << "  ],\n";
    json << "  \"moduleCount\": " << modules.size() << "\n";
    json << "}";
    
    strncpy_s(buffer, bufferSize, json.str().c_str(), _TRUNCATE);
    return TRUE;
}

// Slot 73: ExecutePowerShell
extern "C" __declspec(dllexport) BOOL Omega1_ExecutePowerShell(void* pContext, const char* command, char* output, uint32_t outputSize) {
    if (!pContext || !command || !output || outputSize == 0) return FALSE;
    
    if (RawrXD::Bridge::g_psExecutor) {
        return RawrXD::Bridge::g_psExecutor->ExecuteCommand(command, output, outputSize);
    }
    return FALSE;
}

// Slot 74: LoadModule
extern "C" __declspec(dllexport) HPSMODULE Omega1_LoadModule(void* pContext, const char* moduleName) {
    if (!pContext || !moduleName) return nullptr;
    
    if (RawrXD::Bridge::g_psExecutor) {
        if (RawrXD::Bridge::g_psExecutor->LoadModule(moduleName)) {
            // Return a non-null handle to indicate success
            return reinterpret_cast<HPSMODULE>(1);
        }
    }
    return nullptr;
}

// Slot 75: InvokeModule
extern "C" __declspec(dllexport) BOOL Omega1_InvokeModule(void* pContext, HPSMODULE hModule, const char* function, char* output, uint32_t outputSize) {
    if (!pContext || !hModule || !function || !output || outputSize == 0) return FALSE;
    
    // Module handle is just a sentinel - function name contains module::function
    if (RawrXD::Bridge::g_psExecutor) {
        // Parse module name from function string (format: "ModuleName::FunctionName")
        std::string funcStr(function);
        size_t pos = funcStr.find("::");
        if (pos != std::string::npos) {
            std::string moduleName = funcStr.substr(0, pos);
            std::string funcName = funcStr.substr(pos + 2);
            return RawrXD::Bridge::g_psExecutor->InvokeModuleFunction(moduleName.c_str(), funcName.c_str(), output, outputSize);
        }
    }
    return FALSE;
}

// ═════════════════════════════════════════════════════════════════════════════
// C API for External Binding
// ═════════════════════════════════════════════════════════════════════════════

extern "C" __declspec(dllexport) void* Omega1_CreateContext() {
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    return pContext;
}

extern "C" __declspec(dllexport) void Omega1_DestroyContext(void* pContext) {
    Omega1_Shutdown(pContext);
}

extern "C" __declspec(dllexport) uint32_t Omega1_EnumModules(void* pContext, char* buffer, uint32_t bufferSize) {
    if (!buffer || bufferSize == 0) return 0;
    
    auto modules = RawrXD::Bridge::Omega1Utils::DiscoverModules();
    std::stringstream ss;
    for (const auto& mod : modules) {
        ss << mod << "\n";
    }
    
    strncpy_s(buffer, bufferSize, ss.str().c_str(), _TRUNCATE);
    return static_cast<uint32_t>(modules.size());
}

extern "C" __declspec(dllexport) uint32_t Omega1_GetVersion(char* buffer, uint32_t bufferSize) {
    if (!buffer || bufferSize == 0) return 0;
    strncpy_s(buffer, bufferSize, OMEGA1_VERSION_STRING, _TRUNCATE);
    return static_cast<uint32_t>(strlen(OMEGA1_VERSION_STRING));
}

extern "C" __declspec(dllexport) uint32_t Omega1_GetStatus(void* pContext) {
    if (!pContext) return OMEGA1_STATUS_NOT_INIT;
    return OMEGA1_STATUS_OK;
}
