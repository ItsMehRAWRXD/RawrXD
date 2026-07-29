// ═════════════════════════════════════════════════════════════════════════════
// RawrXD OMEGA-1 PowerShell Bridge - FIXED
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

// ═════════════════════════════════════════════════════════════════════════
// PowerShellExecutor Implementation
// ═════════════════════════════════════════════════════════════════════════

PowerShellExecutor::PowerShellExecutor(const std::string& modulePath) 
    : m_modulePath(modulePath) {
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

bool PowerShellExecutor::LoadModule(const char* moduleName) {
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

bool PowerShellExecutor::InvokeModuleFunction(const char* moduleName, const char* function, char* output, uint32_t outputSize) {
    if (!moduleName || !function) return false;
    
    std::stringstream ss;
    ss << "Import-Module '" << m_modulePath << "\\RawrXD." << moduleName << ".psm1' -Force; ";
    ss << "&" << function << " | ConvertTo-Json -Depth 5";
    
    return ExecuteCommand(ss.str().c_str(), output, outputSize);
}

bool PowerShellExecutor::ExecuteOmegaBootstrap() {
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

bool PowerShellExecutor::ExecuteGenesis() {
    std::stringstream ss;
    ss << "Write-Host '[Ω] OMEGA-1 Genesis Protocol Initiated' -ForegroundColor Magenta; ";
    ss << "$env:RAWRXD_GENESIS='TRUE'; ";
    ss << "Write-Host '[Ω] Genesis Complete' -ForegroundColor Green";
    
    char output[4096];
    return ExecuteCommand(ss.str().c_str(), output, sizeof(output));
}

bool PowerShellExecutor::GetModuleManifest(const char* moduleName, char* output, uint32_t outputSize) {
    if (!moduleName) return false;
    
    std::stringstream ss;
    ss << "$mod = Get-Module -ListAvailable '" << m_modulePath << "\\RawrXD." << moduleName << "'; ";
    ss << "if ($mod) { $mod | Select-Object Name, Version, Description | ConvertTo-Json } else { '{\"error\":\"Module not found\"}' }";
    
    return ExecuteCommand(ss.str().c_str(), output, outputSize);
}

std::string PowerShellExecutor::BuildPowerShellCommand(const char* userCommand) {
    std::stringstream ss;
    // Set environment and execute
    ss << "$env:RAWRXD_OMEGA_ROOT='" << m_modulePath << "'; ";
    ss << userCommand;
    return ss.str();
}

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

// ═════════════════════════════════════════════════════════════════════════
// Omega1Engine Implementation
// ═════════════════════════════════════════════════════════════════════════

Omega1Engine::Omega1Engine() : m_pContext(nullptr), m_pExecutor(nullptr) {}

Omega1Engine::~Omega1Engine() {
    Shutdown();
}

bool Omega1Engine::Initialize(uint32_t flags) {
    if (m_pContext) return true;  // Already initialized
    
    m_pContext = new Omega1Context();
    ZeroMemory(m_pContext, sizeof(Omega1Context));
    m_pContext->flags = flags;
    m_pContext->mutationCount = 0;
    m_pContext->isMutant = FALSE;
    
    // Initialize PowerShell executor
    std::string modulePath = Omega1Utils::GetModulePath();
    m_pExecutor = new PowerShellExecutor(modulePath);
    
    if (!m_pExecutor->Initialize()) {
        delete m_pExecutor;
        m_pExecutor = nullptr;
        delete m_pContext;
        m_pContext = nullptr;
        return false;
    }
    
    // Bootstrap
    if (!m_pExecutor->ExecuteOmegaBootstrap()) {
        Shutdown();
        return false;
    }
    
    return true;
}

void Omega1Engine::Shutdown() {
    if (m_pExecutor) {
        delete m_pExecutor;
        m_pExecutor = nullptr;
    }
    
    if (m_pContext) {
        delete m_pContext;
        m_pContext = nullptr;
    }
}

uint32_t Omega1Engine::GetModuleCount() const {
    if (!m_pContext) return 0;
    return m_pContext->mutationCount;  // Placeholder
}

std::vector<Omega1ModuleInfo> Omega1Engine::GetLoadedModules() const {
    std::vector<Omega1ModuleInfo> modules;
    // Implementation would enumerate loaded modules
    return modules;
}

HPSMODULE Omega1Engine::LoadModule(const char* moduleName) {
    if (!m_pExecutor || !moduleName) return nullptr;
    
    if (m_pExecutor->LoadModule(moduleName)) {
        return reinterpret_cast<HPSMODULE>(1);  // Placeholder handle
    }
    
    return nullptr;
}

bool Omega1Engine::InvokeModule(HPSMODULE hModule, const char* function, char* output, uint32_t outputSize) {
    if (!m_pExecutor || !hModule || !function) return false;
    
    // Extract module name from handle (placeholder)
    return m_pExecutor->InvokeModuleFunction("Core", function, output, outputSize);
}

bool Omega1Engine::IsMutant() const {
    if (!m_pContext) return false;
    return m_pContext->isMutant != FALSE;
}

uint32_t Omega1Engine::GetMutationCount() const {
    if (!m_pContext) return 0;
    return m_pContext->mutationCount;
}

bool Omega1Engine::TriggerMutation(uint32_t mutationType) {
    if (!m_pContext) return false;
    
    m_pContext->mutationCount++;
    if (mutationType & 0x80000000) {
        m_pContext->isMutant = TRUE;
    }
    
    return true;
}

bool Omega1Engine::ExecuteReflective(const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize) {
    if (!m_pExecutor || !payload || payloadSize == 0) return false;
    
    // Execute payload as PowerShell command
    std::string command(payload, payloadSize);
    return m_pExecutor->ExecuteCommand(command.c_str(), output, outputSize);
}

bool Omega1Engine::ExecutePowerShell(const char* command, char* output, uint32_t outputSize) {
    if (!m_pExecutor || !command) return false;
    return m_pExecutor->ExecuteCommand(command, output, outputSize);
}

bool Omega1Engine::ValidateIntegrity(uint32_t* pChecksum) {
    if (!m_pContext) return false;
    
    if (pChecksum) {
        *pChecksum = 0xDEADBEEF;  // Placeholder checksum
    }
    
    return true;
}

std::string Omega1Engine::GetManifestJson() const {
    if (!m_pContext) return "{}";
    return std::string(m_pContext->manifestJson);
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
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    fs::path exePath(buffer);
    return exePath.parent_path().string();
}

bool ValidateModuleExists(const char* moduleName) {
    std::string modulePath = GetModulePath();
    fs::path fullPath = fs::path(modulePath) / (std::string("RawrXD.") + moduleName + ".psm1");
    return fs::exists(fullPath);
}

std::vector<std::string> DiscoverModules() {
    std::vector<std::string> modules;
    std::string modulePath = GetModulePath();
    
    if (fs::exists(modulePath)) {
        for (const auto& entry : fs::directory_iterator(modulePath)) {
            if (entry.path().extension() == ".psm1") {
                modules.push_back(entry.path().stem().string());
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

// ═════════════════════════════════════════════════════════════════════════
// Bridge Initialization Functions
// ═════════════════════════════════════════════════════════════════════════

static PowerShellExecutor* g_bridgeExecutor = nullptr;

bool InitializePowerShellBridge(const char* modulePath) {
    if (g_bridgeExecutor) {
        return true; // Already initialized
    }
    g_bridgeExecutor = new PowerShellExecutor(modulePath ? modulePath : "");
    return g_bridgeExecutor->Initialize();
}

void ShutdownPowerShellBridge() {
    if (g_bridgeExecutor) {
        delete g_bridgeExecutor;
        g_bridgeExecutor = nullptr;
    }
}

} // namespace RawrXD::Bridge

// ═════════════════════════════════════════════════════════════════════════
// C API Exports
// ═════════════════════════════════════════════════════════════════════════

extern "C" {

static RawrXD::Bridge::Omega1Engine* g_omegaEngine = nullptr;

BOOL Omega1_Initialize(void** ppContext, uint32_t flags) {
    if (!ppContext) return FALSE;
    
    if (!g_omegaEngine) {
        g_omegaEngine = new RawrXD::Bridge::Omega1Engine();
        if (!g_omegaEngine->Initialize(flags)) {
            delete g_omegaEngine;
            g_omegaEngine = nullptr;
            return FALSE;
        }
    }
    
    *ppContext = g_omegaEngine;
    return TRUE;
}

void Omega1_Shutdown(void* pContext) {
    if (g_omegaEngine) {
        delete g_omegaEngine;
        g_omegaEngine = nullptr;
    }
}

uint32_t Omega1_GetModuleCount(void* pContext) {
    if (!g_omegaEngine) return 0;
    return g_omegaEngine->GetModuleCount();
}

BOOL Omega1_IsMutant(void* pContext) {
    if (!g_omegaEngine) return FALSE;
    return g_omegaEngine->IsMutant() ? TRUE : FALSE;
}

uint32_t Omega1_GetMutationCount(void* pContext) {
    if (!g_omegaEngine) return 0;
    return g_omegaEngine->GetMutationCount();
}

BOOL Omega1_ExecuteReflective(void* pContext, const char* payload, uint32_t payloadSize, char* output, uint32_t outputSize) {
    if (!g_omegaEngine) return FALSE;
    return g_omegaEngine->ExecuteReflective(payload, payloadSize, output, outputSize) ? TRUE : FALSE;
}

BOOL Omega1_ValidateIntegrity(void* pContext, uint32_t* pChecksum) {
    if (!g_omegaEngine) return FALSE;
    return g_omegaEngine->ValidateIntegrity(pChecksum) ? TRUE : FALSE;
}

BOOL Omega1_TriggerMutation(void* pContext, uint32_t mutationType) {
    if (!g_omegaEngine) return FALSE;
    return g_omegaEngine->TriggerMutation(mutationType) ? TRUE : FALSE;
}

BOOL Omega1_GetManifestJson(void* pContext, char* buffer, uint32_t bufferSize) {
    if (!g_omegaEngine || !buffer) return FALSE;
    
    std::string manifest = g_omegaEngine->GetManifestJson();
    strncpy_s(buffer, bufferSize, manifest.c_str(), _TRUNCATE);
    return TRUE;
}

BOOL Omega1_ExecutePowerShell(void* pContext, const char* command, char* output, uint32_t outputSize) {
    if (!g_omegaEngine) return FALSE;
    return g_omegaEngine->ExecutePowerShell(command, output, outputSize) ? TRUE : FALSE;
}

HPSMODULE Omega1_LoadModule(void* pContext, const char* moduleName) {
    if (!g_omegaEngine) return nullptr;
    return g_omegaEngine->LoadModule(moduleName);
}

BOOL Omega1_InvokeModule(void* pContext, HPSMODULE hModule, const char* function, char* output, uint32_t outputSize) {
    if (!g_omegaEngine) return FALSE;
    return g_omegaEngine->InvokeModule(hModule, function, output, outputSize) ? TRUE : FALSE;
}

// Additional C API exports for test compatibility
void* Omega1_CreateContext() {
    if (!g_omegaEngine) {
        g_omegaEngine = new RawrXD::Bridge::Omega1Engine();
        if (!g_omegaEngine->Initialize(0)) {
            delete g_omegaEngine;
            g_omegaEngine = nullptr;
            return nullptr;
        }
    }
    return g_omegaEngine;
}

void Omega1_DestroyContext(void* pContext) {
    if (g_omegaEngine) {
        delete g_omegaEngine;
        g_omegaEngine = nullptr;
    }
}

uint32_t Omega1_GetVersion(char* buffer, uint32_t bufferSize) {
    if (!buffer || bufferSize == 0) return 0;
    strncpy_s(buffer, bufferSize, "OMEGA-1 v1.0.0", _TRUNCATE);
    return 1;
}

uint32_t Omega1_GetStatus(void* pContext) {
    if (!g_omegaEngine) return 0;
    return 1; // STATUS_OK
}

uint32_t Omega1_EnumModules(void* pContext, char* buffer, uint32_t bufferSize) {
    if (!g_omegaEngine || !buffer) return 0;
    auto modules = g_omegaEngine->GetLoadedModules();
    std::string result;
    for (const auto& mod : modules) {
        result += std::string(mod.name) + ";";
    }
    strncpy_s(buffer, bufferSize, result.c_str(), _TRUNCATE);
    return (uint32_t)modules.size();
}

} // extern "C"
