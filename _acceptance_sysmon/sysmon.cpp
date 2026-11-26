// sysmon.cpp — RAWRXD_REAL_AUTONOMOUS_ACCEPTANCE_001
// Native C++17 Win32 system monitor. No Qt, no third-party deps.
// Real system statistics only (Win32 APIs). GUI + --selftest (writes results file).
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>

struct Stats {
    double cpuPercent = 0.0;
    DWORDLONG memTotal = 0, memAvail = 0;
    double memPercent = 0.0;
    DWORDLONG diskTotal = 0, diskAvail = 0;
    std::vector<std::wstring> gpus;
};

struct CpuState { ULONGLONG idle = 0, kernel = 0, user = 0; bool valid = false; };

static ULONGLONG FtToU64(const FILETIME& f) {
    ULARGE_INTEGER u; u.LowPart = f.dwLowDateTime; u.HighPart = f.dwHighDateTime; return u.QuadPart;
}

static bool SampleCpu(CpuState& s, double& pct) {
    FILETIME idle, kernel, user;
    if (!GetSystemTimes(&idle, &kernel, &user)) return false;
    ULONGLONG i = FtToU64(idle), k = FtToU64(kernel), u = FtToU64(user);
    if (s.valid && k + u > s.kernel + s.user) {
        ULONGLONG di = i - s.idle, dk = k - s.kernel, du = u - s.user;
        ULONGLONG total = dk + du;
        pct = total > 0 ? (1.0 - (double)di / (double)total) * 100.0 : 0.0;
        if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    } else pct = 0.0;
    s.idle = i; s.kernel = k; s.user = u; s.valid = true;
    return true;
}

static void Collect(Stats& st, CpuState& cpu) {
    SampleCpu(cpu, st.cpuPercent);
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        st.memTotal = ms.ullTotalPhys; st.memAvail = ms.ullAvailPhys;
        st.memPercent = st.memTotal ? (1.0 - (double)st.memAvail / (double)st.memTotal) * 100.0 : 0.0;
    }
    ULONGLONG freeB = 0, totalB = 0;
    if (GetDiskFreeSpaceExW(L"C:\\", (PULARGE_INTEGER)&freeB, (PULARGE_INTEGER)&totalB, nullptr)) {
        st.diskTotal = totalB; st.diskAvail = freeB;
    }
    st.gpus.clear();
    DISPLAY_DEVICEW dd{}; dd.cb = sizeof(dd);
    for (DWORD i = 0; EnumDisplayDevicesW(nullptr, i, &dd, 0); ++i) {
        if (dd.StateFlags & DISPLAY_DEVICE_ACTIVE) st.gpus.push_back(dd.DeviceString);
    }
}

static std::string W2S(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0); WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static int Selftest() {
    Stats st; CpuState cpu;
    Collect(st, cpu);          // baseline
    Sleep(250);                // real sampling interval
    Collect(st, cpu);          // delta
    std::ofstream f("selftest_result.txt");
    f << "CPU_PERCENT=" << st.cpuPercent << "\n";
    f << "MEM_TOTAL_MB=" << (st.memTotal / (1024ULL * 1024ULL)) << "\n";
    f << "MEM_AVAIL_MB=" << (st.memAvail / (1024ULL * 1024ULL)) << "\n";
    f << "MEM_PERCENT=" << st.memPercent << "\n";
    f << "DISK_TOTAL_GB=" << (st.diskTotal / (1024ULL * 1024ULL * 1024ULL)) << "\n";
    f << "DISK_AVAIL_GB=" << (st.diskAvail / (1024ULL * 1024ULL * 1024ULL)) << "\n";
    f << "GPU_COUNT=" << st.gpus.size() << "\n";
    for (auto& g : st.gpus) f << "GPU=" << W2S(g) << "\n";
    f.close();
    return (st.memTotal > 0 && st.diskTotal > 0 && st.cpuPercent >= 0.0) ? 0 : 1;
}

static Stats g_stats; static CpuState g_cpu; static HWND g_text = nullptr;

static void UpdateText(HWND w) {
    Collect(g_stats, g_cpu);
    std::wstring t;
    wchar_t buf[256];
    swprintf(buf, 256, L"CPU: %.1f%%", g_stats.cpuPercent); t += buf; t += L"\r\n";
    swprintf(buf, 256, L"Memory: %.1f%%  (%llu MB / %llu MB)",
        g_stats.memPercent, (unsigned long long)(g_stats.memAvail / (1024 * 1024)),
        (unsigned long long)(g_stats.memTotal / (1024 * 1024))); t += buf; t += L"\r\n";
    swprintf(buf, 256, L"Disk C:: %.1f GB free / %.1f GB",
        (double)(g_stats.diskAvail / (1024ULL * 1024 * 1024)),
        (double)(g_stats.diskTotal / (1024ULL * 1024 * 1024))); t += buf; t += L"\r\n";
    t += L"GPUs:\r\n";
    for (auto& g : g_stats.gpus) { t += L"  "; t += g; t += L"\r\n"; }
    SetWindowTextW(g_text, t.c_str());
    (void)w;
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE:
        g_text = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 20, 560, 320, h, nullptr, nullptr, nullptr);
        SetTimer(h, 1, 1000, nullptr);
        UpdateText(h);
        return 0;
    case WM_TIMER:
        UpdateText(h); return 0;
    case WM_DESTROY:
        KillTimer(h, 1); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR cmd, int show) {
    if (cmd && (strstr(cmd, "--selftest") != nullptr)) return Selftest();
    const wchar_t* cls = L"SysMonWnd";
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst; wc.lpszClassName = cls;
    RegisterClassExW(&wc);
    HWND h = CreateWindowExW(0, cls, L"Native System Monitor (RawrXD Acceptance)",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 640, 420, nullptr, nullptr, hInst, nullptr);
    if (!h) return 1;
    ShowWindow(h, show);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    return 0;
}