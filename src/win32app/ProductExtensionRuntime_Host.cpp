// ProductExtensionRuntime_Host.cpp — real ExtensionHost child spawn.
// Fail-closed: missing host EXE ⇒ host_pid stays 0 (never invent PID).
#include "ProductExtensionRuntime_Internal.hpp"

namespace ProductExtensionRuntime {

void CloseHostUnlocked() {
    HostState& h = Host();
    if (h.hostProcess) {
        TerminateProcess(h.hostProcess, 0);
        CloseHandle(h.hostProcess);
        h.hostProcess = nullptr;
    }
    h.hostPid = 0;
    for (auto& [_, e] : Exts()) {
        e.active = false;
        e.processId = 0;
    }
}

bool SpawnHostUnlocked(ExtRecord& rec) {
    HostState& h = Host();
    if (h.hostProcess) {
        DWORD code = 0;
        if (GetExitCodeProcess(h.hostProcess, &code) && code == STILL_ACTIVE) {
            rec.active = true;
            rec.processId = h.hostPid;
            return true;
        }
        CloseHandle(h.hostProcess);
        h.hostProcess = nullptr;
        h.hostPid = 0;
    }
    std::string hostExe = (std::filesystem::path(ExeDir()) /
                           "RawrXD-ExtensionHost.exe").string();
    if (!std::filesystem::exists(hostExe)) {
        return false;
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::string cmd = "\"" + hostExe + "\" --extension-id " + rec.id +
                      " --extension-path \"" + rec.path + "\"";
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');
    BOOL ok = CreateProcessA(hostExe.c_str(), buf.data(), nullptr, nullptr,
                             FALSE, CREATE_NO_WINDOW, nullptr,
                             ExeDir().empty() ? nullptr : ExeDir().c_str(),
                             &si, &pi);
    if (!ok) return false;
    CloseHandle(pi.hThread);
    h.hostProcess = pi.hProcess;
    h.hostPid = pi.dwProcessId;
    h.startTick = GetTickCount64();
    rec.active = true;
    rec.processId = h.hostPid;
    return true;
}

std::string HostStatusJson() {
    std::lock_guard<std::mutex> lock(Mu());
    HostState& h = Host();
    bool running = false;
    if (h.hostProcess) {
        DWORD code = 0;
        running = GetExitCodeProcess(h.hostProcess, &code) && code == STILL_ACTIVE;
        if (!running) {
            CloseHandle(h.hostProcess);
            h.hostProcess = nullptr;
            h.hostPid = 0;
        }
    }
    ULONGLONG up = running && h.startTick
                       ? (GetTickCount64() - h.startTick) / 1000ULL
                       : 0;
    return std::string("{\"running\":") + (running ? "true" : "false") +
           ",\"host_pid\":" + std::to_string(h.hostPid) +
           ",\"extensions_loaded\":" + std::to_string(h.extensionsLoaded) +
           ",\"uptime_seconds\":" + std::to_string(up) +
           ",\"adapter\":\"product_extension_runtime\"}";
}

std::string KillHost() {
    std::lock_guard<std::mutex> lock(Mu());
    CloseHostUnlocked();
    return "{\"success\":true,\"killed\":true,"
           "\"adapter\":\"product_extension_runtime\"}";
}

} // namespace ProductExtensionRuntime
