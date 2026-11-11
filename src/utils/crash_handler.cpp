// ============================================================================
// Must precede all standard headers (see secure_buffer.cpp for rationale).
// ============================================================================
#ifndef _CRT_SECURE_NO_WARNINGS
#  define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#  define _SILENCE_CXX20_U8PATH_DEPRECATION_WARNING
#endif

#include "crash_handler.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#  include <windows.h>
#  include <csignal>
#  include <dbghelp.h>
#  pragma comment(lib, "dbghelp.lib")
#else
#  include <csignal>
#  include <unistd.h>
#  include <execinfo.h>
#endif

namespace fs = std::filesystem;

namespace RawrXD {
namespace Resilience {

namespace {

// ---- safe mode state -------------------------------------------------------
std::atomic<bool> g_safeMode{false};
std::mutex g_safeModeMutex;
std::string g_safeModeReason;

// ---- re-entrancy guard ----------------------------------------------------
std::atomic<bool> g_inCapture{false};

std::string nowUtcIso()
{
    std::array<char, 32> buf{};
    const std::time_t t = std::time(nullptr);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    if (std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0) return {};
    return std::string(buf.data());
}

std::string currentModuleName()
{
#ifdef _WIN32
    std::array<char, 4096> buf{};
    const DWORD n = ::GetModuleFileNameA(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (n == 0 || n >= buf.size()) return "unknown";
    return std::string(buf.data(), n);
#else
    char buf[4096] = {};
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return "unknown";
    return std::string(buf, static_cast<size_t>(n));
#endif
}

std::string currentThreadId()
{
    std::ostringstream oss;
#ifdef _WIN32
    oss << ::GetCurrentThreadId();
#else
    oss << std::hash<std::thread::id>{}(std::this_thread::get_id());
#endif
    return oss.str();
}

/// Capture up to 64 native frames, nearest first. Never allocates unboundedly.
std::vector<void*> captureStack()
{
    std::vector<void*> out;
    out.reserve(64);
#ifdef _WIN32
    // CaptureStackBackTrace is safe to call from a fault handler (unlike
    // StackWalk64), allocation-free, and does not require dbghelp.
    void* frames[64] = {};
    const USHORT n = ::CaptureStackBackTrace(0, 64, frames, nullptr);
    for (USHORT i = 0; i < n; ++i) out.push_back(frames[i]);
#else
    void* frames[64] = {};
    const int n = ::backtrace(frames, 64);
    for (int i = 0; i < n; ++i) out.push_back(frames[i]);
#endif
    return out;
}

/// Minimal JSON string escaping (no exceptions, no dependencies).
std::string jsonEscape(const std::string& s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", c);
                    o += b;
                } else {
                    o.push_back(c);
                }
        }
    }
    return o;
}

std::string hex64(uint64_t v)
{
    char b[32] = {};
    std::snprintf(b, sizeof(b), "0x%llx", static_cast<unsigned long long>(v));
    return std::string(b);
}

/**
 * @brief Convert an ISO-8601 UTC timestamp into a filesystem-safe stamp.
 *
 * The raw ISO form contains ':' characters, which are illegal in Windows
 * filenames -- constructing a path from it makes the ofstream/CreateFile open
 * fail silently, which loses the crash record entirely. This happened once,
 * which is why the mapping is centralized and unit-tested.
 */
std::string safeStamp(const std::string& iso)
{
    std::string s = iso.empty() ? std::string("unknown") : iso;
    for (char& c : s) {
        if (c == ':' || c == ' ') c = '-';
    }
    return s;
}

} // anonymous namespace

// --------------------------------------------------------------------
// Safe mode
// --------------------------------------------------------------------

void CrashHandler::enterSafeMode(std::string reason)
{
    std::lock_guard<std::mutex> lk(g_safeModeMutex);
    if (reason.empty()) {
        g_safeMode.store(false, std::memory_order_release);
        g_safeModeReason.clear();
        return;
    }
    // Root-cause retention: keep the FIRST reason that degraded us. Later
    // failures are usually consequences of the first one, so overwriting the
    // reason would erase the most diagnostic part of the state.
    if (!g_safeMode.load(std::memory_order_acquire) || g_safeModeReason.empty()) {
        g_safeModeReason = std::move(reason);
    }
    g_safeMode.store(true, std::memory_order_release);
}

bool CrashHandler::inSafeMode() noexcept
{
    return g_safeMode.load(std::memory_order_acquire);
}

const char* CrashHandler::safeModeReason() noexcept
{
    if (!inSafeMode()) return "";
    std::lock_guard<std::mutex> lk(g_safeModeMutex);
    return g_safeModeReason.c_str();
}

// --------------------------------------------------------------------
// Core capture path
// --------------------------------------------------------------------

void CrashHandler::capture(const char* kind, const char* message,
                           uint64_t code, const char* name) noexcept
{
    // Re-entrancy guard: a crash inside the crash handler must not recurse.
    bool expected = false;
    if (!g_inCapture.compare_exchange_strong(expected, true)) return;

    // Never let an allocation failure during reporting become a second crash.
    try {
        ++m_fatalCount;

        CrashReport r;
        r.timestampUtc = nowUtcIso();
        r.kind = kind ? kind : "Unknown";
        r.message = message ? message : "";
        r.exceptionCode = code ? hex64(code) : "0x0";
        r.exceptionName = name ? name : "";
        r.moduleName = currentModuleName();
        r.threadId = static_cast<uint64_t>(std::stoull(currentThreadId()));
        r.stack = captureStack();

        {   // publish the report (flexible access)
            static std::mutex lastMutex;
            std::lock_guard<std::mutex> lk(lastMutex);
            m_lastReport = r;
        }

        writeTextRecord(r);

        // A captured fatal condition always degrades the session: later
        // requests get conservative behaviour rather than the same crash.
        CrashHandler::enterSafeMode("CrashHandler: " + r.kind + " - " + r.message);

        if (m_callback) {
            try { m_callback(r); } catch (...) { /* callback must not throw */ }
        }
    } catch (...) {
        // Swallow: reporting must never escalate.
    }

    g_inCapture.store(false, std::memory_order_release);
}

void CrashHandler::writeTextRecord(const CrashReport& r) noexcept
{
    try {
        std::error_code ec;
        if (!m_dumpDir.empty()) fs::create_directories(fs::u8path(m_dumpDir), ec);

        const std::string fileName = m_dumpDir + "/crash-"
                                   + safeStamp(r.timestampUtc)
                                   + "-" + std::to_string(r.threadId) + ".json";
        std::ofstream f(fs::u8path(fileName), std::ios::binary | std::ios::trunc);
        if (!f) return;

        f << "{\n";
        f << "  \"schema\": \"rawrxd.crash/1\",\n";
        f << "  \"timestamp_utc\": \"" << jsonEscape(r.timestampUtc) << "\",\n";
        f << "  \"kind\": \"" << jsonEscape(r.kind) << "\",\n";
        f << "  \"exception_code\": \"" << jsonEscape(r.exceptionCode) << "\",\n";
        f << "  \"exception_name\": \"" << jsonEscape(r.exceptionName) << "\",\n";
        f << "  \"message\": \"" << jsonEscape(r.message) << "\",\n";
        f << "  \"module\": \"" << jsonEscape(r.moduleName) << "\",\n";
        f << "  \"thread_id\": " << r.threadId << ",\n";
        f << "  \"stack_frames\": " << r.stack.size() << ",\n";
        f << "  \"stack\": [";
        for (size_t i = 0; i < r.stack.size(); ++i) {
            char b[32] = {};
            std::snprintf(b, sizeof(b), "\"0x%llx\"",
                          static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(r.stack[i])));
            f << b << (i + 1 < r.stack.size() ? ", " : "");
        }
        f << "]\n";
        f << "}\n";
        f.flush();
    } catch (...) {
        // Best effort only.
    }
}

// --------------------------------------------------------------------
// Singleton + public API
// --------------------------------------------------------------------

CrashHandler& CrashHandler::instance()
{
    static CrashHandler s_instance;
    return s_instance;
}

CrashReport CrashHandler::lastReport() const
{
    static std::mutex lastMutex;
    std::lock_guard<std::mutex> lk(lastMutex);
    return m_lastReport;
}

void CrashHandler::setDumpDirectory(const std::string& dir)
{
    m_dumpDir = dir.empty() ? "crashes" : dir;
    try {
        std::error_code ec;
        fs::create_directories(fs::u8path(m_dumpDir), ec);
    } catch (...) {}
}

bool CrashHandler::install(const std::string& dumpDirectory, CrashCallback callback)
{
    if (m_installed.exchange(true)) return true;   // idempotent
    setDumpDirectory(dumpDirectory);
    m_callback = std::move(callback);
    const bool ok = installPlatformHooks();
    if (!ok) m_installed.store(false, std::memory_order_release);
    return ok;
}

bool CrashHandler::uninstall() noexcept
{
    if (!m_installed.exchange(false)) return false;
    try {
        removePlatformHooks();
        m_callback = nullptr;
        return true;
    } catch (...) {
        return false;
    }
}

bool CrashHandler::reportFatal(const std::string& kind,
                               const std::string& message,
                               const std::string& exceptionCode,
                               const std::string& exceptionName)
{
    const bool guard = g_inCapture.exchange(true);
    if (guard) return false;   // already inside capture
    try {
        ++m_fatalCount;
        CrashReport r;
        r.timestampUtc = nowUtcIso();
        r.kind = kind;
        r.message = message;
        r.exceptionCode = exceptionCode.empty() ? "0x0" : exceptionCode;
        r.exceptionName = exceptionName;
        r.moduleName = currentModuleName();
        r.threadId = std::stoull(currentThreadId());
        r.stack = captureStack();

        {   static std::mutex lastMutex;
            std::lock_guard<std::mutex> lk(lastMutex);
            m_lastReport = r;
        }

        writeTextRecord(r);
        CrashHandler::enterSafeMode("reportFatal: " + kind + " - " + message);
        if (m_callback) {
            try { m_callback(r); } catch (...) {}
        }
    } catch (...) {}
    g_inCapture.store(false, std::memory_order_release);
    return true;
}

// --------------------------------------------------------------------
// Windows platform hooks
// --------------------------------------------------------------------
#ifdef _WIN32

namespace {

/// Write a real minidump from an EXCEPTION_POINTERS (the only place we have
/// both a context and fault info). Fails softly on every error path.
void writeMiniDump(EXCEPTION_POINTERS* ep, const char* name, const char* reason,
                   const std::string& dumpDir)
{
    try {
        std::error_code ec;
        if (!dumpDir.empty()) fs::create_directories(fs::u8path(dumpDir), ec);
        const std::string path = dumpDir + "/crash-" + safeStamp(nowUtcIso()) + "-"
                               + std::to_string(::GetCurrentThreadId()) + ".dmp";

        HANDLE hFile = ::CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return;

        MINIDUMP_EXCEPTION_INFORMATION mei;
        mei.ThreadId = ::GetCurrentThreadId();
        mei.ExceptionPointers = ep;
        mei.ClientPointers = FALSE;

        // Include the stacks, module list, handles and unloaded modules.
        const MINIDUMP_TYPE type = static_cast<MINIDUMP_TYPE>(
            MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpScanMemory
            | MiniDumpWithUnloadedModules | MiniDumpWithIndirectlyReferencedMemory);

        const BOOL okDump = ::MiniDumpWriteDump(::GetCurrentProcess(),
                                                ::GetCurrentProcessId(),
                                                hFile, type, ep ? &mei : nullptr,
                                                nullptr, nullptr);
        ::CloseHandle(hFile);
        if (!okDump) ::DeleteFileA(path.c_str());
        (void)name; (void)reason;
    } catch (...) {}
}

// --------------------------------------------------------------------
// Stack-overflow capture on a fresh thread
// --------------------------------------------------------------------
//
// Why this exists (established empirically by tests/crash_probe.cpp):
//
//   On StackOverflow the faulting thread's stack is exhausted. The SEH filter
//   IS entered, but _resetstkoflw() does NOT make the CRT/heap usable again -
//   the very next nested call re-faults and the process dies before any
//   artifact is written. Verified: filter ran, wrote its first marker, then
//   died silently; zero .dmp and zero .json produced.
//
//   The only reliable way to capture a stack overflow is to do the capture
//   work on a thread that still has a real stack. This spawns a capture thread
//   with a large dedicated stack, performs the reporting there, and waits for
//   it. The exception pointers are passed through for the minidump.
//
//   Everything here is allocation-free in the fault path so the thread can be
//   created from a nearly-dead stack.
// --------------------------------------------------------------------

/// Fixed-size, allocation-free context for the capture thread.
struct SehCaptureContext {
    char name[64];          ///< human-readable exception name
    char codeHex[32];       ///< hex-encoded exception code
    EXCEPTION_POINTERS* ep; ///< valid for the duration of the capture
};

/// Capture thread body: writes the crash record + minidump and returns.
static DWORD WINAPI sehCaptureThread(LPVOID param)
{
    auto* ctx = static_cast<SehCaptureContext*>(param);
    if (!ctx) return 0;

    CrashHandler& h = CrashHandler::instance();

    // reportFatal() has its own re-entrancy guard and is exception-safe.
    h.reportFatal("Seh", ctx->name, ctx->codeHex, ctx->name);
    writeMiniDump(ctx->ep, ctx->name, "seh.stackoverflow", h.dumpDirectory());
    return 0;
}

/**
 * @brief Capture a stack-overflow fault from a fresh-thread stack.
 *
 * @return true if the capture thread completed within the timeout.
 */
static bool captureStackOverflow(EXCEPTION_POINTERS* ep, const char* name,
                                  const char* codeHex)
{
    // The context must live in static storage: the caller's (dead) stack cannot
    // hold it safely, and the thread must be able to read it after return.
    static SehCaptureContext ctx;

    const size_t nlen = ::lstrlenA(name);
    for (size_t i = 0; i < sizeof(ctx.name) - 1; ++i) {
        ctx.name[i] = (i < nlen) ? name[i] : '\0';
    }
    ctx.name[sizeof(ctx.name) - 1] = '\0';

    const size_t clen = ::lstrlenA(codeHex);
    for (size_t i = 0; i < sizeof(ctx.codeHex) - 1; ++i) {
        ctx.codeHex[i] = (i < clen) ? codeHex[i] : '\0';
    }
    ctx.codeHex[sizeof(ctx.codeHex) - 1] = '\0';

    ctx.ep = ep;

    // A dedicated, generously sized stack: 1 MB is enough for the ofstream /
    // filesystem work reportFatal() performs.
    constexpr SIZE_T kCaptureStackBytes = 1024u * 1024u;
    const HANDLE hThread = ::CreateThread(
        nullptr, kCaptureStackBytes, sehCaptureThread, &ctx,
        STACK_SIZE_PARAM_IS_A_RESERVATION, nullptr);

    if (!hThread) return false;   // cannot capture; caller still terminates

    const DWORD wait = ::WaitForSingleObject(hThread, 15000);
    ::CloseHandle(hThread);
    return wait == WAIT_OBJECT_0;
}

extern "C" LONG WINAPI rawrxdSehFilter(EXCEPTION_POINTERS* ep)
{
    const DWORD code = ep ? ep->ExceptionRecord->ExceptionCode : 0;

    const char* name = "EXCEPTION_UNKNOWN";
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:      name = "EXCEPTION_ACCESS_VIOLATION"; break;
        case EXCEPTION_STACK_OVERFLOW:        name = "EXCEPTION_STACK_OVERFLOW"; break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:   name = "EXCEPTION_ILLEGAL_INSTRUCTION"; break;
        case EXCEPTION_IN_PAGE_ERROR:         name = "EXCEPTION_IN_PAGE_ERROR"; break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:    name = "EXCEPTION_INT_DIVIDE_BY_ZERO"; break;
        case EXCEPTION_DATATYPE_MISALIGNMENT: name = "EXCEPTION_DATATYPE_MISALIGNMENT"; break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: name = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"; break;
        default: break;
    }

    CrashHandler& h = CrashHandler::instance();

    if (code == EXCEPTION_STACK_OVERFLOW) {
        // A stack overflow kills the faulting thread's stack, so _resetstkoflw()
        // is NOT sufficient (the next nested call re-faults). Capture on a
        // fresh-thread stack instead. See captureStackOverflow() for evidence.
        char codeHex[32] = {};
        std::snprintf(codeHex, sizeof(codeHex), "0x%lX", static_cast<unsigned long>(code));
        captureStackOverflow(ep, name, codeHex);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    h.reportFatal("Seh", name, "0x" + std::to_string(code), name);
    writeMiniDump(ep, name, "seh", h.dumpDirectory());

    // A crash must terminate: do not let the process limp on with corrupted
    // state. Return the default handling after we recorded everything.
    return EXCEPTION_EXECUTE_HANDLER;
}

extern "C" void rawrxdTerminateHandler()
{
    // An uncaught C++ exception reached terminate(): record what() if present,
    // write a minidump, then abort. Never returns.
    if (std::exception_ptr e = std::current_exception()) {
        try { std::rethrow_exception(e); }
        catch (const std::exception& ex) {
            CrashHandler::instance().reportFatal("CppException", ex.what());
            writeMiniDump(nullptr, "CppException", ex.what(),
                          CrashHandler::instance().dumpDirectory());
            std::abort();
        }
        catch (...) {
            // Unknown exception type: no what() available.
        }
    }
    CrashHandler::instance().reportFatal("CppException",
                                        "std::terminate without active exception");
    std::abort();
}

extern "C" void rawrxdPurecallHandler()
{
    CrashHandler::instance().reportFatal("CrtFatal", "pure virtual function call");
    std::abort();
}

extern "C" void rawrxdInvalidParamHandler(const wchar_t* expr, const wchar_t* func,
                                          const wchar_t* file, unsigned int line,
                                          uintptr_t)
{
    std::ostringstream oss;
    oss << "CRT invalid parameter";
    if (expr) { char b[256] = {}; ::wcstombs(b, expr, sizeof(b) - 1); oss << " expr=" << b; }
    if (func) { char b[256] = {}; ::wcstombs(b, func, sizeof(b) - 1); oss << " func=" << b; }
    if (file) { char b[256] = {}; ::wcstombs(b, file, sizeof(b) - 1); oss << " file=" << b; }
    oss << " line=" << line;
    CrashHandler::instance().reportFatal("CrtFatal", oss.str());
}

extern "C" void rawrxdAbortHandler(int)
{
    CrashHandler::instance().reportFatal("CrtFatal", "abort() signal");
}

} // anonymous namespace

bool CrashHandler::installPlatformHooks()
{
    // 1) SEH filter captures genuine access violations / stack overflow.
    m_prevSehFilter = reinterpret_cast<void*>(
        ::SetUnhandledExceptionFilter(rawrxdSehFilter));

    // 2) std::terminate catches C++ exceptions escaping main/matches.
    m_prevAbort = reinterpret_cast<void*>(std::set_terminate(rawrxdTerminateHandler));

    // 3) CRT fatal paths: purecall and invalid parameters.
    m_prevPurecall = reinterpret_cast<void*>(::_set_purecall_handler(rawrxdPurecallHandler));
    m_prevInvalidParam = reinterpret_cast<void*>(
        ::_set_invalid_parameter_handler(rawrxdInvalidParamHandler));

    // 4) DebugBuild symbol resolution for any stack walking we add later.
    ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
    ::SymInitialize(::GetCurrentProcess(), nullptr, TRUE);

    // 5) SIGABRT so abort() reports before dying.
    std::signal(SIGABRT, rawrxdAbortHandler);

    return true;
}

void CrashHandler::removePlatformHooks() noexcept
{
    if (m_prevSehFilter) ::SetUnhandledExceptionFilter(
        reinterpret_cast<LPTOP_LEVEL_EXCEPTION_FILTER>(m_prevSehFilter));
    m_prevAbort = nullptr;   // std::set_terminate has no "get previous"
    m_prevPurecall = nullptr;
    m_prevInvalidParam = nullptr;
    m_prevSehFilter = nullptr;
    ::SymCleanup(::GetCurrentProcess());
}

// --------------------------------------------------------------------
// POSIX platform hooks
// --------------------------------------------------------------------
#else

namespace {
extern "C" void rawrxdSignalHandler(int sig)
{
    const char* name = strsignal(sig);
    CrashHandler::instance().reportFatal("Signal", name ? name : "unknown",
                                         std::to_string(sig), name ? name : "unknown");
    // Restore default and re-raise so the exit status is correct.
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}
} // anonymous namespace

bool CrashHandler::installPlatformHooks()
{
    m_prevSignals.clear();
    static const int kSigs[] = {SIGSEGV, SIGABRT, SIGILL, SIGFPE, SIGBUS, SIGSYS};
    for (int s : kSigs) {
        if (std::signal(s, rawrxdSignalHandler) != SIG_ERR) m_prevSignals.push_back(s);
    }
    std::set_terminate([]{
        if (std::exception_ptr e = std::current_exception()) {
            try { std::rethrow_exception(e); }
            catch (const std::exception& ex) {
                CrashHandler::instance().reportFatal("CppException", ex.what());
            }
            catch (...) {}
        }
        CrashHandler::instance().reportFatal("CppException", "std::terminate");
        std::abort();
    });
    return !m_prevSignals.empty();
}

void CrashHandler::removePlatformHooks() noexcept
{
    for (int s : m_prevSignals) std::signal(s, SIG_DFL);
    m_prevSignals.clear();
}

#endif // _WIN32

} // namespace Resilience
} // namespace RawrXD
