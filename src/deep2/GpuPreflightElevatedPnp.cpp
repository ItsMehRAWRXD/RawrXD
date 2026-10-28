// GpuPreflightElevatedPnp.cpp — UAC RunAs → Reset-GpuDevicePnp.ps1 on Code 10/31
#include "GpuPreflight.hpp"

#include <shellapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "shell32.lib")

static bool FileExistsW(const wchar_t* path) {
    const DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool ResolvePnpScript(wchar_t* out, size_t outChars) {
    if (!out || outChars < 8) return false;
    const wchar_t* env = _wgetenv(L"RAWRXD_ROOT");
    if (env && env[0]) {
        _snwprintf_s(out, outChars, _TRUNCATE,
                     L"%s\\scripts\\Reset-GpuDevicePnp.ps1", env);
        if (FileExistsW(out)) return true;
    }
    _snwprintf_s(out, outChars, _TRUNCATE,
                 L"G:\\~dev\\rawrxd\\scripts\\Reset-GpuDevicePnp.ps1");
    if (FileExistsW(out)) return true;
    wchar_t mod[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, mod, MAX_PATH)) {
        wchar_t* slash = wcsrchr(mod, L'\\');
        if (slash) *slash = 0;
        _snwprintf_s(out, outChars, _TRUNCATE,
                     L"%s\\..\\..\\scripts\\Reset-GpuDevicePnp.ps1", mod);
        if (FileExistsW(out)) return true;
    }
    return false;
}

// Returns true if device cleared (script exit 0). Sets *launched if UAC helper ran.
static bool RunElevatedGpuPnp(bool* launched) {
    if (launched) *launched = false;
    // Same-session smoke may have already elevated via build_and_run.ps1.
    if (const wchar_t* done = _wgetenv(L"RAWRXD_PNP_ELEV_DONE")) {
        if (done[0] == L'1') {
            std::fprintf(stderr, "GPU_ELEV_PNP=SKIP reason=ALREADY_DONE_THIS_SESSION\n");
            std::fflush(stderr);
            if (launched) *launched = true; // elevation already obtained
            return false;
        }
    }
    wchar_t script[MAX_PATH] = {};
    if (!ResolvePnpScript(script, MAX_PATH)) {
        std::fprintf(stderr, "GPU_ELEV_PNP=SKIP reason=SCRIPT_MISSING\n");
        std::fflush(stderr);
        return false;
    }
    std::fprintf(stderr, "GPU_ELEV_PNP_BEGIN script=%ls\n", script);
    std::fflush(stderr);

    wchar_t params[MAX_PATH + 96] = {};
    _snwprintf_s(params, _TRUNCATE,
                 L"-NoProfile -ExecutionPolicy Bypass -File \"%s\"", script);

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) {
        std::fprintf(stderr, "GPU_ELEV_PNP=FAIL gle=%lu\n",
                     (unsigned long)GetLastError());
        std::fflush(stderr);
        return false;
    }
    if (launched) *launched = true;
    DWORD rc = 1;
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 120000);
        GetExitCodeProcess(sei.hProcess, &rc);
        CloseHandle(sei.hProcess);
    }
    std::fprintf(stderr, "GPU_ELEV_PNP_EXIT=%lu\n", (unsigned long)rc);
    std::fflush(stderr);
    return rc == 0;
}

bool AttemptElevatedGpuPnpCycle() {
    bool launched = false;
    return RunElevatedGpuPnp(&launched);
}

bool AttemptElevatedGpuPnpCycleEx(bool* outLaunched) {
    return RunElevatedGpuPnp(outLaunched);
}
