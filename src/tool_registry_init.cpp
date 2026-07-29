<<<<<<< HEAD
#include "tool_registry_init.hpp"
#include "tool_registry.h"
#include "engine_iface.h"
#include <iostream>
#include <string>
#include <sstream>

// ============================================================================
// register_rawr_inference — Registers the RAWR inference tool with ToolRegistry.
// This tool dispatches prompts to the loaded GGUF model via EngineRegistry.
// ============================================================================
void register_rawr_inference() {
    ToolRegistry::register_tool("rawr_inference", [](const std::string& input) -> std::string {
        // Build an AgentRequest from the raw input
        AgentRequest req{};
        req.mode = 0;              // standard inference
        req.prompt = input;
        req.deep_thinking = false;
        req.deep_research = false;
        req.no_refusal = false;
        req.context_limit = 4096;

        // Try to route through EngineRegistry — pick the first available engine
        Engine* engine = EngineRegistry::get("default");
        if (!engine) engine = EngineRegistry::get("cpu");
        if (!engine) engine = EngineRegistry::get("sovereign_small");

        if (engine) {
            std::string result = engine->infer(req);
            if (!result.empty()) {
                return result;
            }
            return "[rawr_inference] Engine returned empty response";
        }

        return "[rawr_inference] No inference engine available — load a GGUF model first";
    });

    std::cout << "[REGISTRY] Registered RAWR inference tool (routes to EngineRegistry)\n";
}

// ============================================================================
// register_sovereign_engines — Registers Engine800B + SovereignSmall with EngineRegistry.
// Linker fallback: when the real engine module is not linked, this provides
// a diagnostic stub that reports the missing linkage.
// ============================================================================
void register_sovereign_engines() {
    // Check if engines are already registered (real module may have beaten us)
    Engine* existing = EngineRegistry::get("engine_800b");
    if (existing) {
        std::cout << "[REGISTRY] Engine800B already registered by engine module\n";
        return;
    }

    existing = EngineRegistry::get("sovereign_small");
    if (existing) {
        std::cout << "[REGISTRY] SovereignSmall already registered by engine module\n";
        return;
    }

    // Real engine module not linked — register diagnostic tool entries
    // so the tool registry can report availability status
    ToolRegistry::register_tool("engine_800b", [](const std::string& input) -> std::string {
        return "[engine_800b] Engine module not linked. "
               "Rebuild with -DRAWR_ENGINE_MODULE=ON to enable Engine800B.";
    });

    ToolRegistry::register_tool("sovereign_small", [](const std::string& input) -> std::string {
        return "[sovereign_small] Engine module not linked. "
               "Rebuild with -DRAWR_ENGINE_MODULE=ON to enable SovereignSmall.";
    });

    std::cout << "[REGISTRY] register_sovereign_engines — engine module not linked, "
                 "diagnostic tools registered\n";
}
=======
#include "tool_registry.hpp"
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <windows.h>
#include <algorithm>

namespace fs = std::filesystem;
using json = nlohmann::json;

// Helper function to execute process on Windows
static json executeProcessSafely(const std::string& command, const std::vector<std::string>& args, int timeoutMs = 30000, const std::string& cwd = "") {
    std::string cmdLine = command;
    for (const auto& arg : args) {
        cmdLine += " \"" + arg + "\"";
    }

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;
    HANDLE hChildStd_ERR_Rd = NULL;
    HANDLE hChildStd_ERR_Wr = NULL;

    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) return {{"success", false}, {"error", "CreatePipe failed"}};
    if (!CreatePipe(&hChildStd_ERR_Rd, &hChildStd_ERR_Wr, &saAttr, 0)) return {{"success", false}, {"error", "CreatePipe failed"}};
    SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hChildStd_ERR_Rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hChildStd_ERR_Wr;
    si.hStdOutput = hChildStd_OUT_Wr;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));

    const char* workingDir = cwd.empty() ? nullptr : cwd.c_str();

    if (!CreateProcessA(NULL, const_cast<char*>(cmdLine.c_str()), NULL, NULL, TRUE, 0, NULL, workingDir, &si, &pi)) {
        CloseHandle(hChildStd_OUT_Rd); CloseHandle(hChildStd_OUT_Wr);
        CloseHandle(hChildStd_ERR_Rd); CloseHandle(hChildStd_ERR_Wr);
        return {{"success", false}, {"error", "CreateProcess failed"}};
    }

    CloseHandle(hChildStd_OUT_Wr);
    CloseHandle(hChildStd_ERR_Wr);

    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    std::string output, error;
    
    // Read output
    DWORD dwRead;
    char buffer[4096];
    
    // Non-blocking peek could be better but for brief command execution this is sufficient
    // Note: If pipe is empty/closed, this might hang if not careful, but Win32 ReadFile returns when write end is closed.
    // However, if process hangs and keeps pipe open, we depend on WaitForSingleObject result?
    // Actually if we wait first, then the process is done (or timed out).
    // If it timed out, we kill it, then read.
    
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        error += "[Timeout]";
    }
    
    // Read remaining data from pipes
    while (true) {
        DWORD bytesAvailable = 0;
        PeekNamedPipe(hChildStd_OUT_Rd, NULL, 0, NULL, &bytesAvailable, NULL);
        if (bytesAvailable == 0) break; // Or check if process ended?
        if (ReadFile(hChildStd_OUT_Rd, buffer, std::min<DWORD>(sizeof(buffer), bytesAvailable), &dwRead, NULL) && dwRead != 0) {
            output.append(buffer, dwRead);
        } else break;
    }
    while (true) {
        DWORD bytesAvailable = 0;
        PeekNamedPipe(hChildStd_ERR_Rd, NULL, 0, NULL, &bytesAvailable, NULL);
        if (bytesAvailable == 0) break;
        if (ReadFile(hChildStd_ERR_Rd, buffer, std::min<DWORD>(sizeof(buffer), bytesAvailable), &dwRead, NULL) && dwRead != 0) {
            error.append(buffer, dwRead);
        } else break;
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hChildStd_OUT_Rd);
    CloseHandle(hChildStd_ERR_Rd);

    return {
        {"success", exitCode == 0},
        {"output", output},
        {"error", error},
        {"exitCode", (int)exitCode}
    };
}

// Function to register standard system tools
namespace RawrXD {

void registerSystemTools(ToolRegistry* registry) {
    if (!registry) return;

    // 1. Execute Command
    ToolDefinition runCmd;
    runCmd.metadata.name = "execute_command";
    runCmd.metadata.description = "Execute a shell command";
    runCmd.metadata.category = "System";
    
    ToolArgument argCmd; argCmd.name="command"; argCmd.type=ToolArgType::STRING;
    ToolArgument argCwd; argCwd.name="cwd"; argCwd.required=false; argCwd.type=ToolArgType::STRING;
    runCmd.metadata.arguments = {argCmd, argCwd};

    runCmd.handler = [](const json& args) -> json {
        std::string cmd = args["command"];
        std::string cwd = args.contains("cwd") ? args["cwd"] : "";
        
        // Split into "cmd /c ..." for shell execution
        return executeProcessSafely("cmd.exe", {"/c", cmd}, 30000, cwd);
    };
    registry->registerTool(runCmd);

    // 2. Read File
    ToolDefinition readFile;
    readFile.metadata.name = "read_file";
    readFile.metadata.description = "Read file contents";
    readFile.metadata.category = "FileSystem";
    
    ToolArgument argPath; argPath.name="path"; argPath.type=ToolArgType::STRING;
    readFile.metadata.arguments = {argPath};

    readFile.handler = [](const json& args) -> json {
        std::string path = args["path"];
        if (!fs::exists(path)) return {{"success", false}, {"error", "File not found"}};
        std::ifstream f(path, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        return {{"success", true}, {"content", content}};
    };
    registry->registerTool(readFile);

    // 3. List Directory
    ToolDefinition listDir;
    listDir.metadata.name = "list_dir";
    listDir.metadata.description = "List files in directory";
    listDir.metadata.category = "FileSystem";

    ToolArgument argListPath; argListPath.name="path"; argListPath.type=ToolArgType::STRING;
    listDir.metadata.arguments = {argListPath};

    listDir.handler = [](const json& args) -> json {
        std::string path = args["path"];
        if (!fs::exists(path) || !fs::is_directory(path)) return {{"success", false}, {"error", "Directory not found"}};
        
        json files = json::array();
        for(const auto& entry : fs::directory_iterator(path)) {
            files.push_back({
                {"name", entry.path().filename().string()},
                {"is_dir", entry.is_directory()},
                {"size", entry.is_regular_file() ? entry.file_size() : 0}
            });
        }
        return {{"success", true}, {"files", files}};
    };
    registry->registerTool(listDir);
}

} // namespace RawrXD
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
