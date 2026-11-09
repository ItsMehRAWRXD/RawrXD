// ProductExtensionRuntime_Host.cpp — real ExtensionHost child spawn.
// Fail-closed: missing host EXE ⇒ host_pid stays 0 (never invent PID).
#include "ProductExtensionRuntime_Internal.hpp"
#include <system_error>

namespace ProductExtensionRuntime {

namespace {
std::string QuoteWindowsArg(const std::string& value) {
    std::string out = "\"";
    unsigned slashes = 0;
    for (char c : value) {
        if (c == '\\') { ++slashes; continue; }
        if (c == '"') out.append(slashes * 2 + 1, '\\');
        else out.append(slashes, '\\');
        out.push_back(c);
        slashes = 0;
    }
    out.append(slashes * 2, '\\');
    out.push_back('"');
    return out;
}
}

void CloseHostUnlocked() {
    HostState& h = Host();
    if (h.stopEvent) {
        SetEvent(h.stopEvent);
    }
    if (h.hostProcess) {
        DWORD wait = WaitForSingleObject(h.hostProcess, 2000);
        if (wait == WAIT_TIMEOUT) TerminateProcess(h.hostProcess, 0);
        CloseHandle(h.hostProcess);
        h.hostProcess = nullptr;
    }
    if (h.readyEvent) { CloseHandle(h.readyEvent); h.readyEvent = nullptr; }
    if (h.stopEvent) { CloseHandle(h.stopEvent); h.stopEvent = nullptr; }
    h.hostPid = 0;
    h.readyEventName.clear();
    h.stopEventName.clear();
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
    std::error_code ec;
    auto canonicalExe = std::filesystem::weakly_canonical(hostExe, ec);
    if (ec || !std::filesystem::is_regular_file(canonicalExe, ec) || ec) {
        return false;
    }
    hostExe = canonicalExe.string();
    const std::string token = std::to_string(GetCurrentProcessId()) + "_" +
                              std::to_string(GetTickCount64());
    h.readyEventName = "Local\\RawrXD_ExtensionHost_Ready_" + token;
    h.stopEventName = "Local\\RawrXD_ExtensionHost_Stop_" + token;
    h.readyEvent = CreateEventA(nullptr, TRUE, FALSE, h.readyEventName.c_str());
    h.stopEvent = CreateEventA(nullptr, TRUE, FALSE, h.stopEventName.c_str());
    if (!h.readyEvent || !h.stopEvent) {
        if (h.readyEvent) CloseHandle(h.readyEvent);
        if (h.stopEvent) CloseHandle(h.stopEvent);
        h.readyEvent = nullptr; h.stopEvent = nullptr;
        return false;
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::string cmd = QuoteWindowsArg(hostExe) + " --extension-id " +
                      QuoteWindowsArg(rec.id) + " --extension-path " +
                      QuoteWindowsArg(rec.path) + " --ready-event " +
                      QuoteWindowsArg(h.readyEventName) + " --stop-event " +
                      QuoteWindowsArg(h.stopEventName);
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');
    BOOL ok = CreateProcessA(hostExe.c_str(), buf.data(), nullptr, nullptr,
                             FALSE, CREATE_NO_WINDOW, nullptr,
                             ExeDir().empty() ? nullptr : ExeDir().c_str(),
                             &si, &pi);
    if (!ok) {
        h.lastLaunchError = GetLastError();
        CloseHandle(h.readyEvent); h.readyEvent = nullptr;
        CloseHandle(h.stopEvent); h.stopEvent = nullptr;
        h.readyEventName.clear(); h.stopEventName.clear();
        return false;
    }
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(h.readyEvent, 5000) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        h.hostProcess = nullptr; h.hostPid = 0;
        CloseHandle(h.readyEvent); h.readyEvent = nullptr;
        CloseHandle(h.stopEvent); h.stopEvent = nullptr;
        h.readyEventName.clear(); h.stopEventName.clear();
        return false;
    }
    h.hostProcess = pi.hProcess;
    h.hostPid = pi.dwProcessId;
    h.lastLaunchError = ERROR_SUCCESS;
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
           ",\"last_launch_error\":" + std::to_string(h.lastLaunchError) +
           ",\"adapter\":\"product_extension_runtime\"}";
}

std::string KillHost() {
    std::lock_guard<std::mutex> lock(Mu());
    CloseHostUnlocked();
    return "{\"success\":true,\"killed\":true,"
           "\"adapter\":\"product_extension_runtime\"}";
}

} // namespace ProductExtensionRuntime
