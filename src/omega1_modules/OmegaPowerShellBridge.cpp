// ═════════════════════════════════════════════════════════════════════════════
// RawrXD OMEGA-1 PowerShell Bridge
// Native C++ to PowerShell execution harness
// ═════════════════════════════════════════════════════════════════════════════

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

namespace RawrXD::Bridge {

class PowerShellExecutor {
private:
    std::string m_modulePath;
    HANDLE m_hReadPipe = nullptr;
    HANDLE m_hWritePipe = nullptr;
    SECURITY_ATTRIBUTES m_sa;

public:
    PowerShellExecutor(const std::string& modulePath) : m_modulePath(modulePath) {
        ZeroMemory(&m_sa, sizeof(m_sa));
        m_sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        m_sa.bInheritHandle = TRUE;
        m_sa.lpSecurityDescriptor = nullptr;
    }

    ~PowerShellExecutor() {
        CleanupPipes();
    }

    bool Initialize() {
        // Create pipes for stdout capture
        if (!CreatePipe(&m_hReadPipe, &m_hWritePipe, &m_sa, 0)) {
            return false;
        }

        // Ensure read handle is not inherited
        SetHandleInformation(m_hReadPipe, HANDLE_FLAG_INHERIT, 0);
        return true;
    }

    bool ExecuteCommand(const char* command, char* output, uint32_t outputSize) {
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
