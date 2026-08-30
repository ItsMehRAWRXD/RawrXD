// Win32IDE_CommandFlight.cpp — ring buffer + JSONL journal
#include "Win32IDE_CommandFlight.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace RawrXD::CommandTelemetry {
namespace {

CommandFlight g_ring[kCommandFlightCapacity];
std::atomic<uint64_t> g_seq{0};
std::atomic<size_t> g_write{0};
std::atomic<size_t> g_count{0};
thread_local CommandFlight* tls_current = nullptr;
bool g_journalEnabled = true;
char g_journalPath[MAX_PATH] = {};
ProductGenerations g_gens{};

void AppendJsonl(const CommandFlight& f)
{
    if (!g_journalEnabled)
        return;
    EnsureJournalPath();
    if (!g_journalPath[0])
        return;
    FILE* fp = nullptr;
    if (fopen_s(&fp, g_journalPath, "ab") != 0 || !fp)
        return;
    const char* result =
        (f.result == 0 && f.effectCommitted) ? "SUCCESS"
        : (f.phase == CommandFlightPhase::Failed) ? "FAILED"
                                                  : "INCOMPLETE";
    std::fprintf(fp,
                 "{\"seq\":%llu,\"raw_id\":%u,\"logical\":\"%s\",\"logical_id\":%u,"
                 "\"received\":true,\"resolved\":%s,\"handler_entered\":%s,"
                 "\"effect\":%s,\"pre_gen\":%llu,\"post_gen\":%llu,\"result\":\"%s\"",
                 static_cast<unsigned long long>(f.sequence), f.rawId,
                 f.logicalName[0] ? f.logicalName : "?",
                 f.logicalId, f.resolved ? "true" : "false",
                 f.handlerEntered ? "true" : "false",
                 f.effectCommitted ? "true" : "false",
                 static_cast<unsigned long long>(f.preGeneration),
                 static_cast<unsigned long long>(f.postGeneration), result);
    if (f.failReason[0])
        std::fprintf(fp, ",\"fail\":\"%s\"", f.failReason);
    std::fprintf(fp, "}\n");
    std::fclose(fp);
}

}  // namespace

const char* LogicalNameForRawId(UINT rawId)
{
    switch (rawId) {
    case 1001: return "FILE_NEW";
    case 1002: return "FILE_OPEN";
    case 1003: return "FILE_SAVE";
    case 1004: return "FILE_SAVE_AS";
    case 1099: return "FILE_EXIT";
    case 2016: return "EDIT_FIND";
    case 2020: return "VIEW_MINIMAP";
    default: return "UNKNOWN";
    }
}

uint32_t LogicalIdForRawId(UINT rawId)
{
    return rawId;
}

void EnsureJournalPath()
{
    if (g_journalPath[0])
        return;
    CreateDirectoryA("evidence", nullptr);
    CreateDirectoryA("evidence\\P1_UI_MENU_E2E_001", nullptr);
    strcpy_s(g_journalPath, "evidence\\P1_UI_MENU_E2E_001\\COMMAND_FLIGHT.jsonl");
}

void SetJournalEnabled(bool enabled) { g_journalEnabled = enabled; }
bool JournalEnabled() { return g_journalEnabled; }

ProductGenerations& Generations() { return g_gens; }

uint64_t BumpDocumentGeneration() { return ++g_gens.documentGeneration; }
uint64_t BumpFindGeneration() { return ++g_gens.findGeneration; }
uint64_t BumpMinimapGeneration() { return ++g_gens.minimapGeneration; }

CommandFlight& Begin(HWND hwnd, UINT rawId)
{
    const size_t slot = g_write.fetch_add(1) % kCommandFlightCapacity;
    CommandFlight& f = g_ring[slot];
    f = CommandFlight{};
    f.sequence = g_seq.fetch_add(1) + 1;
    f.rawId = rawId;
    f.targetHwnd = hwnd;
    f.phase = CommandFlightPhase::Received;
    QueryPerformanceCounter(&f.beginQpc);
    size_t c = g_count.load();
    if (c < kCommandFlightCapacity)
        g_count.store(c + 1);
    tls_current = &f;
    return f;
}

void Resolved(CommandFlight& flight, uint32_t logicalId, const char* logicalName)
{
    flight.logicalId = logicalId;
    flight.resolved = true;
    flight.phase = CommandFlightPhase::Resolved;
    if (logicalName)
        strcpy_s(flight.logicalName, logicalName);
}

void HandlerEntered(CommandFlight& flight)
{
    flight.handlerEntered = true;
    flight.phase = CommandFlightPhase::HandlerEntered;
}

void EffectCommitted(CommandFlight& flight, uint64_t generation)
{
    flight.effectCommitted = true;
    flight.postGeneration = generation;
    flight.phase = CommandFlightPhase::EffectCommitted;
}

void Fail(CommandFlight& flight, const char* reason)
{
    flight.phase = CommandFlightPhase::Failed;
    flight.result = static_cast<int>(ERROR_NOT_FOUND);
    if (reason)
        strcpy_s(flight.failReason, reason);
}

void Finish(CommandFlight& flight, int result)
{
    flight.result = result;
    QueryPerformanceCounter(&flight.endQpc);
    if (flight.phase != CommandFlightPhase::Failed) {
        if (result == 0 && flight.effectCommitted)
            flight.phase = CommandFlightPhase::Completed;
        else if (result != 0)
            flight.phase = CommandFlightPhase::Failed;
    }
    AppendJsonl(flight);
    if (tls_current == &flight)
        tls_current = nullptr;
}

CommandFlight* Current() { return tls_current; }

CommandFlight* FindLatestByRawId(UINT rawId)
{
    const size_t n = g_count.load();
    if (n == 0)
        return nullptr;
    const size_t w = g_write.load();
    const size_t start = (w == 0) ? 0 : (w - 1);
    for (size_t i = 0; i < n; ++i) {
        const size_t idx = (start + kCommandFlightCapacity - i) % kCommandFlightCapacity;
        if (g_ring[idx].rawId == rawId && g_ring[idx].sequence != 0)
            return &g_ring[idx];
    }
    return nullptr;
}

const CommandFlight* RingAt(size_t index)
{
    if (index >= g_count.load())
        return nullptr;
    return &g_ring[index % kCommandFlightCapacity];
}

size_t RingCount() { return g_count.load(); }

void MarkMainMenuReady(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd))
        return;
    SetPropW(hwnd, kPropMainMenuReady, reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1)));
}

bool IsMainMenuReady(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd))
        return false;
    return GetPropW(hwnd, kPropMainMenuReady) != nullptr;
}

void ClearMainMenuReady(HWND hwnd)
{
    if (!hwnd)
        return;
    RemovePropW(hwnd, kPropMainMenuReady);
}

bool CmdDiagActive()
{
    char buf[16] = {};
    if (GetEnvironmentVariableA("RAWRXD_P1_CMD_DIAG", buf, sizeof(buf)) > 0)
        return buf[0] != '\0' && buf[0] != '0';
    const char* v = std::getenv("RAWRXD_P1_CMD_DIAG");
    return v && v[0] && v[0] != '0';
}

// Module-dir absolute sink — CWD may move to project root after session restore.
static bool CmdDiagResolvePath(char* out, size_t outCap, const char* fileName)
{
    if (!out || outCap < 8 || !fileName)
        return false;
    char mod[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, mod, MAX_PATH) == 0 || !mod[0])
        return false;
    char* slash = strrchr(mod, '\\');
    if (!slash)
        slash = strrchr(mod, '/');
    if (slash)
        *slash = '\0';
    char ev[MAX_PATH] = {};
    char gate[MAX_PATH] = {};
    if (sprintf_s(ev, "%s\\evidence", mod) <= 0)
        return false;
    if (sprintf_s(gate, "%s\\P1_UI_MENU_E2E_001", ev) <= 0)
        return false;
    CreateDirectoryA(ev, nullptr);
    CreateDirectoryA(gate, nullptr);
    return sprintf_s(out, outCap, "%s\\%s", gate, fileName) > 0;
}

void CmdDiagBreadcrumb(int cmdId, const char* step)
{
    if (!CmdDiagActive() || !step)
        return;
    char path[MAX_PATH] = {};
    if (!CmdDiagResolvePath(path, sizeof(path), "CMD_BREADCRUMB.txt"))
        return;
    FILE* fp = nullptr;
    if (fopen_s(&fp, path, "ab") != 0 || !fp)
        return;
    SYSTEMTIME st{};
    GetSystemTime(&st);
    std::fprintf(fp, "%02u:%02u:%02u.%03u id=%d step=%s\n", st.wHour, st.wMinute,
                 st.wSecond, st.wMilliseconds, cmdId, step);
    std::fclose(fp);
}

void CmdDiagIdeGetTextBegin(const char* tag, HWND hwnd, int part, const void* buf)
{
    if (!CmdDiagActive() || !tag)
        return;
    void* frames[8] = {};
    const unsigned n = CaptureStackBackTrace(1, 8, frames, nullptr);
    const HMODULE exeMod = GetModuleHandleA(nullptr);
    unsigned long long callerRva = 0;
    if (n > 0 && frames[0] && exeMod) {
        callerRva = static_cast<unsigned long long>(
            reinterpret_cast<uintptr_t>(frames[0]) -
            reinterpret_cast<uintptr_t>(exeMod));
    }
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    char inflight[MAX_PATH] = {};
    if (CmdDiagResolvePath(inflight, sizeof(inflight), "IDE_GETTEXT_INFLIGHT.txt")) {
        FILE* ifp = nullptr;
        if (fopen_s(&ifp, inflight, "wb") == 0 && ifp) {
            std::fprintf(ifp,
                         "IDE_GETTEXT_INFLIGHT=%s\nFT=%llu\nPID=%lu\nTID=%lu\n"
                         "IDE_GETTEXT_HWND=%p\nIDE_GETTEXT_MSG=0x040D\n"
                         "PART=%d\nBUF=%p\nCALLER_RVA=0x%llX\n",
                         tag, static_cast<unsigned long long>(uli.QuadPart),
                         GetCurrentProcessId(), GetCurrentThreadId(),
                         static_cast<void*>(hwnd), part, buf, callerRva);
            std::fclose(ifp);
        }
    }
    char logPath[MAX_PATH] = {};
    if (!CmdDiagResolvePath(logPath, sizeof(logPath), "IDE_SB_GETTEXTW_OWNER.txt"))
        return;
    FILE* fp = nullptr;
    if (fopen_s(&fp, logPath, "ab") != 0 || !fp)
        return;
    std::fprintf(fp,
                 "BEGIN tag=%s FT=%llu PID=%lu TID=%lu IDE_GETTEXT_HWND=%p "
                 "IDE_GETTEXT_MSG=0x040D PART=%d BUF=%p CALLER_RVA=0x%llX\n",
                 tag, static_cast<unsigned long long>(uli.QuadPart),
                 GetCurrentProcessId(), GetCurrentThreadId(),
                 static_cast<void*>(hwnd), part, buf, callerRva);
    std::fclose(fp);
}

void CmdDiagIdeGetTextEnd(const char* tag)
{
    if (!CmdDiagActive())
        return;
    char inflight[MAX_PATH] = {};
    if (CmdDiagResolvePath(inflight, sizeof(inflight), "IDE_GETTEXT_INFLIGHT.txt"))
        DeleteFileA(inflight);
    char logPath[MAX_PATH] = {};
    if (!CmdDiagResolvePath(logPath, sizeof(logPath), "IDE_SB_GETTEXTW_OWNER.txt"))
        return;
    FILE* fp = nullptr;
    if (fopen_s(&fp, logPath, "ab") != 0 || !fp)
        return;
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    std::fprintf(fp, "END tag=%s FT=%llu TID=%lu\n", tag ? tag : "?",
                 static_cast<unsigned long long>(uli.QuadPart), GetCurrentThreadId());
    std::fclose(fp);
}

namespace {
thread_local unsigned g_diagLastMsg = 0;
thread_local unsigned long long g_diagLastWp = 0;
thread_local HWND g_diagLastHwnd = nullptr;
thread_local HWND g_diagWpHwnd = nullptr;
thread_local char g_diagLastClass[64] = {};
thread_local char g_diagWpClass[64] = {};
LONG g_vehInstalled = 0;
LONG g_fatalWritten = 0;
LPTOP_LEVEL_EXCEPTION_FILTER g_prevUnhandled = nullptr;
HHOOK g_cwpHook = nullptr;

constexpr unsigned kCwpRing = 24;
struct CwpRingEntry {
    HWND hwnd;
    UINT msg;
    char cls[48];
};
CwpRingEntry g_cwpRing[kCwpRing] = {};
volatile LONG g_cwpSeq = 0;

// SB_GETTEXTW/A entry on statusbar — stack + cert inflight correlation.
#ifndef SB_GETTEXTA
#define SB_GETTEXTA (WM_USER + 2)
#endif
#ifndef SB_GETTEXTW
#define SB_GETTEXTW (WM_USER + 13)
#endif
constexpr unsigned kGetTextFrames = 24;
struct StatusGetTextHit {
    FILETIME ft{};
    HWND hwnd = nullptr;
    UINT msg = 0;
    DWORD tid = 0;
    unsigned frameCount = 0;
    void* frames[kGetTextFrames] = {};
    char frameMods[kGetTextFrames][48] = {};
    unsigned long long frameRvas[kGetTextFrames] = {};
    bool hasRawrXd = false;
    bool hasUxtheme = false;
    char classHint[48] = {};
};
StatusGetTextHit g_lastSbGetText{};
volatile LONG g_sbGetTextSeq = 0;

void CmdDiagNoteStatusGetText(HWND hwnd, UINT msg, const char* cls)
{
    if (!hwnd || !cls || std::strstr(cls, "statusbar") == nullptr)
        return;
    if (msg != SB_GETTEXTW && msg != SB_GETTEXTA)
        return;

    StatusGetTextHit hit{};
    GetSystemTimeAsFileTime(&hit.ft);
    hit.hwnd = hwnd;
    hit.msg = msg;
    hit.tid = GetCurrentThreadId();
    void* raw[kGetTextFrames] = {};
    hit.frameCount = CaptureStackBackTrace(1, kGetTextFrames, raw, nullptr);
    const HMODULE exeMod = GetModuleHandleA(nullptr);
    for (unsigned i = 0; i < hit.frameCount; ++i) {
        hit.frames[i] = raw[i];
        HMODULE fm = nullptr;
        if (!raw[i] ||
            !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCSTR>(raw[i]), &fm) ||
            !fm)
            continue;
        char mpath[MAX_PATH] = {};
        GetModuleFileNameA(fm, mpath, MAX_PATH);
        const char* leaf = mpath;
        for (const char* p = mpath; *p; ++p)
            if (*p == '\\' || *p == '/')
                leaf = p + 1;
        strcpy_s(hit.frameMods[i], leaf);
        hit.frameRvas[i] = static_cast<unsigned long long>(
            reinterpret_cast<uintptr_t>(raw[i]) - reinterpret_cast<uintptr_t>(fm));
        if (fm == exeMod)
            hit.hasRawrXd = true;
        if (_stricmp(leaf, "uxtheme.dll") == 0)
            hit.hasUxtheme = true;
    }
    // Nested RawrXD frames ≠ IDE sent GETTEXT (cross-proc marshals mid-WndProc).
    if (hit.hasRawrXd && hit.hasUxtheme)
        strcpy_s(hit.classHint, "NESTED_IDE_OR_THEME");
    else if (hit.hasRawrXd)
        strcpy_s(hit.classHint, "NESTED_IDE_FRAMES");
    else if (hit.hasUxtheme)
        strcpy_s(hit.classHint, "THEME_HEAVY");
    else
        strcpy_s(hit.classHint, "MARSHAL_OR_EXTERNAL");

    const LONG seq = InterlockedIncrement(&g_sbGetTextSeq);
    g_lastSbGetText = hit;

    char path[MAX_PATH] = {};
    if (!CmdDiagResolvePath(path, sizeof(path), "IDE_SB_GETTEXTW_ENTRY.txt"))
        return;
    FILE* fp = nullptr;
    if (fopen_s(&fp, path, "ab") != 0 || !fp)
        return;
    ULARGE_INTEGER uli{};
    uli.LowPart = hit.ft.dwLowDateTime;
    uli.HighPart = hit.ft.dwHighDateTime;
    std::fprintf(fp, "SEQ=%ld FT=%llu TID=%lu MSG=0x%04X HWND=%p CLASS=%s HINT=%s\n",
                 static_cast<long>(seq),
                 static_cast<unsigned long long>(uli.QuadPart), hit.tid, hit.msg,
                 static_cast<void*>(hit.hwnd), cls, hit.classHint);
    for (unsigned i = 0; i < hit.frameCount; ++i) {
        std::fprintf(fp, "  FRAME[%u]=%p RVA=0x%llX MODULE=%s\n", i, hit.frames[i],
                     hit.frameRvas[i],
                     hit.frameMods[i][0] ? hit.frameMods[i] : "?");
    }
    std::fprintf(fp, "----\n");
    std::fclose(fp);
}

void CmdDiagDumpLastStatusGetText(FILE* fp)
{
    if (!fp)
        return;
    const StatusGetTextHit& hit = g_lastSbGetText;
    std::fprintf(fp, "LAST_SB_GETTEXT_SEQ=%ld\n", static_cast<long>(g_sbGetTextSeq));
    if (g_sbGetTextSeq == 0) {
        std::fprintf(fp, "LAST_SB_GETTEXT=NONE\n");
        return;
    }
    ULARGE_INTEGER uli{};
    uli.LowPart = hit.ft.dwLowDateTime;
    uli.HighPart = hit.ft.dwHighDateTime;
    std::fprintf(fp, "LAST_SB_GETTEXT_FT=%llu\n",
                 static_cast<unsigned long long>(uli.QuadPart));
    std::fprintf(fp, "LAST_SB_GETTEXT_MSG=0x%04X\n", hit.msg);
    std::fprintf(fp, "LAST_SB_GETTEXT_HWND=%p\n", static_cast<void*>(hit.hwnd));
    std::fprintf(fp, "LAST_SB_GETTEXT_TID=%lu\n", hit.tid);
    std::fprintf(fp, "LAST_SB_GETTEXT_HINT=%s\n", hit.classHint);
    std::fprintf(fp, "LAST_SB_GETTEXT_FRAME_COUNT=%u\n", hit.frameCount);
    for (unsigned i = 0; i < hit.frameCount; ++i) {
        std::fprintf(fp, "LAST_SB_GETTEXT_FRAME[%u]=%p RVA=0x%llX MODULE=%s\n", i,
                     hit.frames[i], hit.frameRvas[i],
                     hit.frameMods[i][0] ? hit.frameMods[i] : "?");
    }
    char inflight[MAX_PATH] = {};
    if (CmdDiagResolvePath(inflight, sizeof(inflight), "CERT_READSTATUS0_INFLIGHT.txt")) {
        const DWORD attr = GetFileAttributesA(inflight);
        std::fprintf(fp, "CERT_READSTATUS0_INFLIGHT=%s\n",
                     (attr != INVALID_FILE_ATTRIBUTES) ? "YES" : "NO");
    }
    char ideInflight[MAX_PATH] = {};
    if (CmdDiagResolvePath(ideInflight, sizeof(ideInflight), "IDE_GETTEXT_INFLIGHT.txt")) {
        const DWORD attr = GetFileAttributesA(ideInflight);
        std::fprintf(fp, "IDE_GETTEXT_INFLIGHT=%s\n",
                     (attr != INVALID_FILE_ATTRIBUTES) ? "YES" : "NO");
        if (attr != INVALID_FILE_ATTRIBUTES) {
            FILE* ifp = nullptr;
            if (fopen_s(&ifp, ideInflight, "rb") == 0 && ifp) {
                char line[256] = {};
                while (std::fgets(line, sizeof(line), ifp))
                    std::fprintf(fp, "IDE_GETTEXT_INFLIGHT_%s", line);
                std::fclose(ifp);
            }
        }
    }
}

bool CmdDiagInterestingCwp(UINT msg, const char* cls)
{
    // Do not flood the ring with every child WM_PAINT — that hides SB_* traffic.
    if (msg == WM_WINDOWPOSCHANGING || msg == WM_WINDOWPOSCHANGED ||
        msg == WM_SETCURSOR || msg == WM_SETFONT || msg == WM_SIZE ||
        msg == WM_MOVE || msg == WM_SHOWWINDOW)
        return true;
    // Status-bar / common-control user messages (SB_SETTEXT…SB_GETTEXTLENGTH…).
    if (msg >= WM_USER && msg < WM_USER + 0x80)
        return true;
    if (!cls || !cls[0])
        return false;
    // Paint only for COMCTL32-backed chrome (keeps statusbar paint in ring).
    if (msg == WM_PAINT &&
        (std::strstr(cls, "msctls_") != nullptr ||
         std::strstr(cls, "ToolbarWindow32") != nullptr ||
         std::strstr(cls, "SysTabControl32") != nullptr ||
         std::strstr(cls, "SysHeader32") != nullptr))
        return true;
    return (std::strstr(cls, "msctls_") != nullptr ||
            std::strstr(cls, "ToolbarWindow32") != nullptr ||
            std::strstr(cls, "ReBarWindow32") != nullptr ||
            std::strstr(cls, "SysTabControl32") != nullptr ||
            std::strstr(cls, "SysHeader32") != nullptr ||
            std::strstr(cls, "SysTreeView32") != nullptr ||
            std::strstr(cls, "SysListView32") != nullptr ||
            std::strstr(cls, "tooltips_class32") != nullptr);
}

void CmdDiagDumpStatusCorrelation(FILE* fp)
{
    if (!fp)
        return;
    HWND main = g_diagLastHwnd;
    if (!main || !IsWindow(main))
        main = g_diagWpHwnd;
    HWND child1004 = (main && IsWindow(main)) ? GetDlgItem(main, 1004) : nullptr;
    HWND child2000 = (main && IsWindow(main)) ? GetDlgItem(main, 2000) : nullptr;
    char c1004[48] = {};
    char c2000[48] = {};
    if (child1004 && IsWindow(child1004))
        GetClassNameA(child1004, c1004, 48);
    if (child2000 && IsWindow(child2000))
        GetClassNameA(child2000, c2000, 48);
    std::fprintf(fp, "STATUS_DLGITEM_1004=%p class=%s\n", static_cast<void*>(child1004),
                 c1004[0] ? c1004 : "?");
    std::fprintf(fp, "STATUS_DLGITEM_2000=%p class=%s\n", static_cast<void*>(child2000),
                 c2000[0] ? c2000 : "?");

    HWND cwpStatus = nullptr;
    UINT cwpStatusMsg = 0;
    const LONG seq = g_cwpSeq;
    const unsigned n = (seq < static_cast<LONG>(kCwpRing))
                           ? static_cast<unsigned>(seq)
                           : kCwpRing;
    for (unsigned i = n; i > 0; --i) {
        const unsigned idx =
            static_cast<unsigned>((seq - static_cast<LONG>(n) + static_cast<LONG>(i - 1)) %
                                  kCwpRing);
        const CwpRingEntry& e = g_cwpRing[idx];
        if (e.cls[0] && std::strstr(e.cls, "statusbar")) {
            cwpStatus = e.hwnd;
            cwpStatusMsg = e.msg;
            break;
        }
    }
    std::fprintf(fp, "CWP_STATUS_HWND=%p msg=0x%04X\n", static_cast<void*>(cwpStatus),
                 cwpStatusMsg);
    if (cwpStatus && IsWindow(cwpStatus)) {
        const LONG_PTR cid = GetWindowLongPtrA(cwpStatus, GWLP_ID);
        std::fprintf(fp, "CWP_STATUS_CONTROL_ID=%lld\n", static_cast<long long>(cid));
        const bool match1004 = (cwpStatus == child1004);
        const bool match2000 = (cwpStatus == child2000);
        std::fprintf(fp, "CWP_STATUS_EQ_DLGITEM_1004=%s\n", match1004 ? "YES" : "NO");
        std::fprintf(fp, "CWP_STATUS_EQ_DLGITEM_2000=%s\n", match2000 ? "YES" : "NO");
        // Part count probe (SB_GETPARTS = WM_USER+6).
        int parts[16] = {};
        const LRESULT nParts =
            SendMessageA(cwpStatus, WM_USER + 6, 16, reinterpret_cast<LPARAM>(parts));
        std::fprintf(fp, "CWP_STATUS_PARTS=%lld\n", static_cast<long long>(nParts));
    } else {
        std::fprintf(fp, "CWP_STATUS_CONTROL_ID=NONE\n");
        std::fprintf(fp, "CWP_STATUS_EQ_DLGITEM_1004=NO\n");
        std::fprintf(fp, "CWP_STATUS_EQ_DLGITEM_2000=NO\n");
        std::fprintf(fp, "CWP_STATUS_PARTS=NONE\n");
    }
}

LRESULT CALLBACK CmdDiagCallWndProc(int code, WPARAM wParam, LPARAM lParam)
{
    if (code == HC_ACTION && lParam) {
        const CWPSTRUCT* cwp = reinterpret_cast<const CWPSTRUCT*>(lParam);
        char cls[48] = {};
        if (cwp->hwnd && IsWindow(cwp->hwnd))
            GetClassNameA(cwp->hwnd, cls, 48);
        if (CmdDiagInterestingCwp(cwp->message, cls)) {
            const LONG seq = InterlockedIncrement(&g_cwpSeq);
            CwpRingEntry& e = g_cwpRing[static_cast<unsigned>(seq - 1) % kCwpRing];
            e.hwnd = cwp->hwnd;
            e.msg = cwp->message;
            std::memcpy(e.cls, cls, sizeof(e.cls));
            e.cls[sizeof(e.cls) - 1] = '\0';
            CmdDiagNoteStatusGetText(cwp->hwnd, cwp->message, cls);
        }
    }
    return CallNextHookEx(g_cwpHook, code, wParam, lParam);
}

void CmdDiagDumpCwpRing(FILE* fp)
{
    if (!fp)
        return;
    const LONG seq = g_cwpSeq;
    const unsigned n = (seq < static_cast<LONG>(kCwpRing))
                           ? static_cast<unsigned>(seq)
                           : kCwpRing;
    std::fprintf(fp, "CWP_RING_SEQ=%ld\n", static_cast<long>(seq));
    std::fprintf(fp, "CWP_RING_COUNT=%u\n", n);
    for (unsigned i = 0; i < n; ++i) {
        const unsigned idx =
            static_cast<unsigned>((seq - static_cast<LONG>(n) + static_cast<LONG>(i)) %
                                  kCwpRing);
        const CwpRingEntry& e = g_cwpRing[idx];
        std::fprintf(fp, "CWP[%u]=msg=0x%04X hwnd=%p class=%s\n", i, e.msg,
                     static_cast<void*>(e.hwnd), e.cls[0] ? e.cls : "?");
    }
    CmdDiagDumpLastStatusGetText(fp);
}

bool CmdDiagIsNoise(DWORD code)
{
    return code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP ||
           code == 0x40010006u || /* DBG_PRINTEXCEPTION_C */
           code == 0x4001000Au || /* DBG_PRINTEXCEPTION_WIDE_C */
           code == 0x40010015u || /* DBG_RIP_EXCEPTION */
           code == 0x406D1388u;   /* MS_VC_EXCEPTION (SetThreadName) */
}

void CmdDiagWriteCapture(const char* fileName, int cmdId, unsigned long code,
                         const void* addr, const void* const* frames, unsigned frameCount,
                         const char* kind, bool append)
{
    char path[MAX_PATH] = {};
    if (!CmdDiagResolvePath(path, sizeof(path), fileName))
        return;
    FILE* fp = nullptr;
    if (fopen_s(&fp, path, append ? "ab" : "wb") != 0 || !fp)
        return;
    if (!append)
        std::fprintf(fp, "P1_UI_MENU_E2E_001 FIRST_CHANCE_WM_COMMAND\n");
    else
        std::fprintf(fp, "----\n");
    const HMODULE exeMod = GetModuleHandleA(nullptr);
    const uintptr_t exeBase = reinterpret_cast<uintptr_t>(exeMod);
    HMODULE faultMod = nullptr;
    char faultModPath[MAX_PATH] = {};
    if (addr) {
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(addr), &faultMod);
        if (faultMod)
            GetModuleFileNameA(faultMod, faultModPath, MAX_PATH);
    }
    const uintptr_t faultBase = reinterpret_cast<uintptr_t>(faultMod);
    std::fprintf(fp, "KIND=%s\n", kind ? kind : "?");
    std::fprintf(fp, "CMD_ID=%d\n", cmdId);
    std::fprintf(fp, "EXCEPTION_CODE=0x%08lX\n", code);
    std::fprintf(fp, "EXCEPTION_ADDR=%p\n", addr);
    std::fprintf(fp, "EXE_MODULE_BASE=%p\n", reinterpret_cast<void*>(exeBase));
    std::fprintf(fp, "FAULT_MODULE_BASE=%p\n", reinterpret_cast<void*>(faultBase));
    std::fprintf(fp, "FAULT_MODULE=%s\n", faultModPath[0] ? faultModPath : "?");
    if (addr && faultBase)
        std::fprintf(fp, "EXCEPTION_RVA=0x%llX\n",
                     static_cast<unsigned long long>(
                         reinterpret_cast<uintptr_t>(addr) - faultBase));
    std::fprintf(fp, "LAST_MSG=0x%04X\n", g_diagLastMsg);
    std::fprintf(fp, "LAST_WPARAM=0x%llX\n", g_diagLastWp);
    std::fprintf(fp, "LAST_HWND=%p\n", static_cast<void*>(g_diagLastHwnd));
    std::fprintf(fp, "LAST_CLASS=%s\n", g_diagLastClass[0] ? g_diagLastClass : "?");
    std::fprintf(fp, "WP_HWND=%p\n", static_cast<void*>(g_diagWpHwnd));
    std::fprintf(fp, "WP_CLASS=%s\n", g_diagWpClass[0] ? g_diagWpClass : "?");
    std::fprintf(fp, "TID=%lu\n", GetCurrentThreadId());
    std::fprintf(fp, "FRAME_COUNT=%u\n", frameCount);
    for (unsigned i = 0; i < frameCount; ++i) {
        const void* f = frames ? frames[i] : nullptr;
        std::fprintf(fp, "FRAME[%u]=%p\n", i, f);
        if (!f)
            continue;
        HMODULE fm = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(f), &fm) &&
            fm) {
            const uintptr_t fb = reinterpret_cast<uintptr_t>(fm);
            char mpath[MAX_PATH] = {};
            GetModuleFileNameA(fm, mpath, MAX_PATH);
            const char* leaf = mpath;
            for (const char* p = mpath; *p; ++p)
                if (*p == '\\' || *p == '/')
                    leaf = p + 1;
            std::fprintf(fp, "FRAME[%u]_RVA=0x%llX MODULE=%s\n", i,
                         static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(f) -
                                                         fb),
                         leaf);
        }
    }
    CmdDiagDumpStatusCorrelation(fp);
    CmdDiagDumpCwpRing(fp);
    std::fclose(fp);
}

void CmdDiagCaptureFromPointers(EXCEPTION_POINTERS* ep, const char* kind, bool fatal)
{
    if (!ep || !ep->ExceptionRecord)
        return;
    void* frames[32] = {};
    unsigned n = CaptureStackBackTrace(2, 32, frames, nullptr);
    const void* addr = ep->ExceptionRecord->ExceptionAddress;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const int cmdGuess = (g_diagLastMsg == WM_COMMAND) ? (int)LOWORD(g_diagLastWp) : -1;
    if (fatal) {
        if (InterlockedCompareExchange(&g_fatalWritten, 1, 0) != 0)
            return;
        CmdDiagWriteCapture("FIRST_CHANCE_WM_COMMAND.txt", cmdGuess, code, addr,
                            reinterpret_cast<const void* const*>(frames), n, kind, false);
        CmdDiagBreadcrumb(cmdGuess, kind ? kind : "UNHANDLED");
    } else {
        // Journal caught/first-chance noise-filtered faults; do not lock fatal sink.
        CmdDiagWriteCapture("FIRST_CHANCE_JOURNAL.txt", cmdGuess, code, addr,
                            reinterpret_cast<const void* const*>(frames), n, kind, true);
    }
}

LONG CALLBACK CmdDiagVeh(EXCEPTION_POINTERS* ep)
{
    if (!CmdDiagActive() || !ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (CmdDiagIsNoise(code) || code == 0x8001010Du /* RPC_E_CANTCALLOUT_ININPUTSYNCCALL */)
        return EXCEPTION_CONTINUE_SEARCH;
    // Journal first-chance on UI threads that have seen a message.
    if (g_diagLastMsg != 0)
        CmdDiagCaptureFromPointers(ep, "VEH_FIRST_CHANCE", false);
    // Heap corruption: retain even if LAST_MSG unset (settle sibling of COMCTL32 AV).
    if (code == 0xC0000374u) {
        CmdDiagCaptureFromPointers(ep, "VEH_HEAP_CORRUPT", true);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Promote to fatal sink only for UI-thread faults (LAST_MSG set).
    // Worker AVs with LAST_MSG=0 must not lock the sink — that hid the real
    // WM_DESTROY 0xC000041D capture (SequentialBlowoffValve FreeBlock noise).
    if ((code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_STACK_OVERFLOW ||
         code == 0xC0000409u) &&
        g_diagLastMsg != 0)
        CmdDiagCaptureFromPointers(ep, "VEH_FATAL_CANDIDATE", true);
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG CALLBACK CmdDiagUnhandled(EXCEPTION_POINTERS* ep)
{
    if (CmdDiagActive() && ep && ep->ExceptionRecord &&
        !CmdDiagIsNoise(ep->ExceptionRecord->ExceptionCode)) {
        CmdDiagCaptureFromPointers(ep, "UNHANDLED_FILTER", true);
    }
    if (g_prevUnhandled)
        return g_prevUnhandled(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}
}  // namespace

void CmdDiagNoteMessage(unsigned msg, unsigned long long wParam, void* hwnd,
                        unsigned long long lParam)
{
    if (!CmdDiagActive())
        return;
    g_diagLastMsg = msg;
    g_diagLastWp = wParam;
    g_diagLastHwnd = static_cast<HWND>(hwnd);
    g_diagLastClass[0] = '\0';
    if (g_diagLastHwnd && IsWindow(g_diagLastHwnd))
        GetClassNameA(g_diagLastHwnd, g_diagLastClass, 64);
    if (msg == WM_WINDOWPOSCHANGING || msg == WM_WINDOWPOSCHANGED) {
        g_diagWpHwnd = nullptr;
        g_diagWpClass[0] = '\0';
        if (lParam) {
            auto* wp = reinterpret_cast<WINDOWPOS*>(static_cast<uintptr_t>(lParam));
            if (wp && wp->hwnd && IsWindow(wp->hwnd)) {
                g_diagWpHwnd = wp->hwnd;
                GetClassNameA(wp->hwnd, g_diagWpClass, 64);
            }
        }
    }
    // Allow a fresh fatal capture when entering destroy — prior worker AVs
    // must not suppress the WM_DESTROY / WM_NCDESTROY localizer.
    if (msg == WM_DESTROY || msg == WM_NCDESTROY)
        InterlockedExchange(&g_fatalWritten, 0);
}

void CmdDiagException(int cmdId, unsigned long code, const void* addr,
                      const void* const* frames, unsigned frameCount,
                      const char* kind)
{
    // SEH swallowed inside WM_COMMAND — localize without waiting for process death.
    CmdDiagWriteCapture("FIRST_CHANCE_WM_COMMAND.txt", cmdId, code, addr, frames, frameCount,
                        kind ? kind : "SEH_WM_COMMAND", false);
    InterlockedExchange(&g_fatalWritten, 1);
    CmdDiagBreadcrumb(cmdId, kind ? kind : "EXCEPTION");
}

void CmdDiagMarkArmed()
{
    if (!CmdDiagActive())
        return;
    if (InterlockedCompareExchange(&g_vehInstalled, 1, 0) == 0) {
        AddVectoredExceptionHandler(1, CmdDiagVeh);
        g_prevUnhandled = SetUnhandledExceptionFilter(CmdDiagUnhandled);
        g_cwpHook = SetWindowsHookExA(WH_CALLWNDPROC, CmdDiagCallWndProc, nullptr,
                                      GetCurrentThreadId());
    }

    char path[MAX_PATH] = {};
    if (!CmdDiagResolvePath(path, sizeof(path), "CMD_DIAG_ARMED.txt"))
        return;
    FILE* fp = nullptr;
    if (fopen_s(&fp, path, "wb") != 0 || !fp)
        return;
    std::fprintf(fp, "RAWRXD_P1_CMD_DIAG=1\n");
    std::fprintf(fp, "VEH=1\n");
    std::fprintf(fp, "UNHANDLED_FILTER=1\n");
    std::fprintf(fp, "CWP_HOOK=%s\n", g_cwpHook ? "1" : "0");
    char cwd[MAX_PATH] = {};
    GetCurrentDirectoryA(MAX_PATH, cwd);
    std::fprintf(fp, "CWD=%s\n", cwd);
    std::fclose(fp);
}

}  // namespace RawrXD::CommandTelemetry
