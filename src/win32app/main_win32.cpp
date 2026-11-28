#include "Win32IDE.h"
#include "IDELogger.h"
#include "Win32TerminalManager.h"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <fstream>
#include <mutex>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <dbghelp.h>
#include <filesystem>
#include "rawrxd/config/AppPaths.h"
#if defined(RAWRXD_NATIVE_IDE_EXT) && RAWRXD_NATIVE_IDE_EXT
#include "Win32IDE_ExtHostWire.h"
#endif

namespace {
std::string rawrxdRoot() {
    static const std::string root = rawrxd::config::AppPaths::resolve().applicationRoot;
    return root;
}
std::string rawrxdEvidence(const std::string& sub) {
    return (std::filesystem::path(rawrxdRoot()) / "evidence" / sub).string();
}

// --health-check: headless product health (no GUI/GPU). Reports config/model
// discovery and backend reachability, then exits 0 (healthy) or 1.
static bool probeOllama11434() {
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Health/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    bool ok = false;
    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 11434, 0);
    if (hConnect) {
        HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", L"/api/tags", nullptr,
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (hReq) {
            if (WinHttpSendRequest(hReq, WINHTTP_NO_REQUEST_DATA, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hReq, nullptr)) {
                DWORD code = 0, len = sizeof(code);
                if (WinHttpQueryHeaders(hReq,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &len, WINHTTP_NO_HEADER_INDEX)) {
                    ok = (code == 200);
                }
            }
            WinHttpCloseHandle(hReq);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    return ok;
}

static int runHealthCheck() {
    namespace fs = std::filesystem;
    const rawrxd::config::AppPaths paths = rawrxd::config::AppPaths::resolve();
    size_t modelCount = 0;
    {
        std::error_code ec;
        if (fs::is_directory(paths.modelDir, ec)) {
            for (const auto& de : fs::directory_iterator(paths.modelDir, ec)) {
                if (!ec && de.is_regular_file() && de.path().extension() == ".gguf") ++modelCount;
            }
        }
    }
    const bool ollama = probeOllama11434();
    std::printf("[HEALTH] applicationRoot=%s\n", paths.applicationRoot.c_str());
    std::printf("[HEALTH] configDir=%s\n", paths.configDir.c_str());
    std::printf("[HEALTH] modelDir=%s models=%zu\n", paths.modelDir.c_str(), modelCount);
    std::printf("[HEALTH] backend ollama:11434=%s\n", ollama ? "UP" : "DOWN");
    const bool pass = ollama && modelCount > 0;
    std::printf("IDE_HEALTH=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
LONG WINAPI rawrxdUnhandledException(EXCEPTION_POINTERS* ep)
{
    CreateDirectoryA(rawrxdEvidence("production_win32_crash_20261118").c_str(), nullptr);
    const std::string path = rawrxdEvidence("production_win32_crash_20261118\\RawrXD-Win32IDE-Native.dmp");
    HANDLE file = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION info{};
        info.ThreadId = GetCurrentThreadId();
        info.ExceptionPointers = ep;
        info.ClientPointers = FALSE;
        // The thread-info/unloaded-module dump can fail on some faulting paths
        // (e.g. 0xC000041D fatal user-callback), leaving a 0-byte file. Retry
        // with a plain normal dump so the minidump is never empty.
        if (!MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file,
                              static_cast<MINIDUMP_TYPE>(
                                  MiniDumpWithDataSegs | MiniDumpWithHandleData |
                                  MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules),
                              ep ? &info : nullptr, nullptr, nullptr)) {
            SetFilePointer(file, 0, nullptr, FILE_BEGIN);
            SetEndOfFile(file);
            MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file,
                              MiniDumpNormal, ep ? &info : nullptr, nullptr, nullptr);
        }
        CloseHandle(file);
    }
    HANDLE log = CreateFileA(
        rawrxdEvidence("production_win32_crash_20261118\\exception_stack.txt").c_str(),
        GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (log != INVALID_HANDLE_VALUE) {
        char line[1024];
        DWORD written = 0;
        auto writeLine = [&](const char* text) {
            WriteFile(log, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        };
        const auto* record = ep ? ep->ExceptionRecord : nullptr;
        const auto* context = ep ? ep->ContextRecord : nullptr;
        // Fault line is written UNCONDITIONALLY (outside any SymInitialize
        // guard) so a missing PDB can never reduce the log to 0 bytes.
        std::snprintf(line, sizeof(line),
                      "fault=0x%08lX access=%llu address=0x%llX rip=0x%llX rsp=0x%llX rbp=0x%llX rcx=0x%llX rdx=0x%llX r8=0x%llX r9=0x%llX\n",
                      record ? record->ExceptionCode : 0,
                      record && record->NumberParameters > 0
                          ? static_cast<unsigned long long>(record->ExceptionInformation[0]) : 0ull,
                      record && record->NumberParameters > 1
                          ? static_cast<unsigned long long>(record->ExceptionInformation[1]) : 0ull,
                      context ? static_cast<unsigned long long>(context->Rip) : 0ull,
                      context ? static_cast<unsigned long long>(context->Rsp) : 0ull,
                      context ? static_cast<unsigned long long>(context->Rbp) : 0ull,
                      context ? static_cast<unsigned long long>(context->Rcx) : 0ull,
                      context ? static_cast<unsigned long long>(context->Rdx) : 0ull,
                      context ? static_cast<unsigned long long>(context->R8) : 0ull,
                      context ? static_cast<unsigned long long>(context->R9) : 0ull);
        writeLine(line);
        void* frames[64]{};
        const USHORT count = CaptureStackBackTrace(0, 64, frames, nullptr);
        std::snprintf(line, sizeof(line), "exception=0x%08lX thread=%lu frames=%u\n",
                      record ? record->ExceptionCode : 0,
                      GetCurrentThreadId(), static_cast<unsigned>(count));
        writeLine(line);
        // Symbolication is best-effort. Module+RVA is ALWAYS emitted per frame
        // so the fault resolves against a PDB/.map even when SymInitialize fails
        // (the previous 0-byte-log failure mode).
        SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
        const bool symReady =
            SymInitialize(GetCurrentProcess(), (rawrxdRoot() + "\\build\\bin\\Release").c_str(), TRUE) != FALSE;
        for (USHORT i = 0; i < count; ++i) {
            const DWORD64 address = reinterpret_cast<DWORD64>(frames[i]);
            char modName[MAX_PATH];
            modName[0] = '\0';
            DWORD64 base = 0;
            HMODULE mod = nullptr;
            if (GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(address), &mod) && mod) {
                base = reinterpret_cast<DWORD64>(mod);
                GetModuleFileNameA(mod, modName, MAX_PATH);
            } else {
                std::snprintf(modName, sizeof(modName), "<unknown>");
            }
            const DWORD64 rva = (base && address >= base) ? (address - base) : 0ull;
            bool symbolized = false;
            if (symReady) {
                alignas(SYMBOL_INFO) char storage[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
                auto* symbol = reinterpret_cast<PSYMBOL_INFO>(storage);
                symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                symbol->MaxNameLen = MAX_SYM_NAME;
                DWORD64 displacement = 0;
                if (SymFromAddr(GetCurrentProcess(), address, &displacement, symbol)) {
                    std::snprintf(line, sizeof(line),
                                  "#%u %s+0x%llX @0x%llX (%s+0x%llX)\n",
                                  static_cast<unsigned>(i), symbol->Name,
                                  static_cast<unsigned long long>(displacement),
                                  static_cast<unsigned long long>(address),
                                  modName, static_cast<unsigned long long>(rva));
                    writeLine(line);
                    symbolized = true;
                }
            }
            if (!symbolized) {
                std::snprintf(line, sizeof(line), "#%u <unknown> @0x%llX (%s+0x%llX)\n",
                              static_cast<unsigned>(i),
                              static_cast<unsigned long long>(address),
                              modName, static_cast<unsigned long long>(rva));
                writeLine(line);
            }
        }
        if (symReady) SymCleanup(GetCurrentProcess());
        CloseHandle(log);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

void startupTrace(const char* message)
{
    std::ofstream trace((rawrxdRoot() + "\\startup_trace.log").c_str(), std::ios::app);
    if (trace) trace << message << '\n';
}

// SEH-only wrapper: noinline + no C++ objects in this frame (MSVC C2712/C2713).
// Do not call startupTrace (ofstream) from inside __try — inlining mixes EH forms.
#if defined(_MSC_VER)
__declspec(noinline) static int stopTerminalSeh(Win32TerminalManager* term)
{
    if (!term) return 0;
    __try {
        term->stop();
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
}
#endif

// Product ConPTY smoke: exercises Win32TerminalManager start/write/drain.
// Writes oneshot receipt; --term-quit ExitProcess before ConPTY dtor/stop.
int runTermSmoke(const char* lpCmdLine)
{
    const char* receiptPath =
        rawrxdEvidence("FULL_FEATURE_ONESHOT_001\\artifacts\\term_smoke_receipt.txt").c_str();
    startupTrace("runTermSmoke entered");
    try {
        std::mutex mu;
        std::string out;
        std::atomic<bool> finished{false};
        int exitCode = -1;

        Win32TerminalManager term;
        term.onOutput = [&](const std::string& chunk) {
            std::lock_guard<std::mutex> lk(mu);
            out += chunk;
        };
        term.onError = [&](const std::string& chunk) {
            std::lock_guard<std::mutex> lk(mu);
            out += chunk;
        };
        term.onFinished = [&](int code) {
            exitCode = code;
            finished = true;
        };

        startupTrace("runTermSmoke before start");
        const bool started = term.start(Win32TerminalManager::PowerShell);
        const auto transport = term.transport();
        const DWORD livePid = started ? term.pid() : 0;
        const char* transportName =
            transport == Win32TerminalManager::TransportConPTY ? "CONPTY" :
            transport == Win32TerminalManager::TransportPipe ? "PIPE" : "NONE";
        startupTrace(started ? "runTermSmoke start OK" : "runTermSmoke start FAIL");

        if (started) {
            // Interactive ConPTY expects CR. Keep smoke minimal + measurable.
            term.writeInput("Write-Output ONESHOT_CONPTY_ALIVE\r\n");
            for (int i = 0; i < 40; ++i) {
                {
                    std::lock_guard<std::mutex> lk(mu);
                    if (out.find("ONESHOT_CONPTY_ALIVE") != std::string::npos) break;
                }
                if (finished) break;
                Sleep(250);
            }
        }

        std::string captured;
        {
            std::lock_guard<std::mutex> lk(mu);
            captured = out;
        }
        const bool alive = captured.find("ONESHOT_CONPTY_ALIVE") != std::string::npos;
        const bool conpty = transport == Win32TerminalManager::TransportConPTY;

        // Write receipt BEFORE stop so a ConPTY teardown crash still leaves
        // measurable START/CONPTY/ALIVE evidence for the harness.
        CreateDirectoryA(
            rawrxdEvidence("FULL_FEATURE_ONESHOT_001\\artifacts").c_str(), nullptr);
        std::ofstream rec(receiptPath, std::ios::trunc);
        if (rec) {
            rec << "START=" << (started ? "PASS" : "FAIL") << "\n"
                << "TRANSPORT=" << transportName << "\n"
                << "CONPTY=" << (conpty ? "PASS" : "FAIL") << "\n"
                << "ALIVE_ECHO=" << (alive ? "PASS" : "FAIL") << "\n"
                << "PID=" << livePid << "\n"
                << "EXIT_CODE=" << exitCode << "\n"
                << "OUT_LEN=" << captured.size() << "\n";
            rec.flush();
        }
        startupTrace("runTermSmoke receipt written");

        const bool pass = started && conpty && alive;
        startupTrace(pass ? "term-smoke PASS" : "term-smoke FAIL");

        // --term-quit must not run term.stop() or ~Win32TerminalManager:
        // ClosePseudoConsole/join hung or aborted (EXIT!=0 / FORCE_KILL).
        if (lpCmdLine && std::strstr(lpCmdLine, "--term-quit")) {
            if (livePid != 0) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, livePid);
                if (hp) {
                    TerminateProcess(hp, 0);
                    CloseHandle(hp);
                }
            }
            startupTrace("term-quit ExitProcess from smoke");
            ::ExitProcess(pass ? 0u : 2u);
        }

        if (started) {
            startupTrace("runTermSmoke before stop");
#if defined(_MSC_VER)
            const int stopRc = stopTerminalSeh(&term);
            if (stopRc < 0) startupTrace("runTermSmoke stop SEH");
            else startupTrace("runTermSmoke after stop");
#else
            try {
                term.stop();
                startupTrace("runTermSmoke after stop");
            } catch (...) {
                startupTrace("runTermSmoke stop exception");
            }
#endif
        }
        return pass ? 0 : 2;
    } catch (const std::exception& ex) {
        startupTrace(ex.what());
        startupTrace("runTermSmoke exception");
        return 3;
    } catch (...) {
        startupTrace("runTermSmoke unknown exception");
        return 3;
    }
}
}

namespace {
// Bind --user-data-dir=PATH (or space form) to RAWRXD_USER_DATA_DIR before
// Win32IDE ctor so ide_session.json / profile reads honor isolation (W4-PER).
void applyUserDataDirFromCmdLine(const char* lpCmdLine)
{
    if (!lpCmdLine || !*lpCmdLine) return;
    const char* key = "--user-data-dir";
    const char* hit = std::strstr(lpCmdLine, key);
    if (!hit) return;
    const char* p = hit + std::strlen(key);
    while (*p == ' ' || *p == '\t') ++p;
    if (*p == '=') {
        ++p;
        while (*p == ' ' || *p == '\t') ++p;
    }
    if (!*p) return;
    std::string path;
    if (*p == '"') {
        ++p;
        while (*p && *p != '"') path.push_back(*p++);
    } else {
        while (*p && *p != ' ' && *p != '\t') path.push_back(*p++);
    }
    if (path.empty()) return;
    SetEnvironmentVariableA("RAWRXD_USER_DATA_DIR", path.c_str());
    startupTrace("user-data-dir bound");
}
} // namespace


// RAWRXD_GUARD_5: authoritative top-level unhandled-exception filter.
// Writes a lightweight witness (code / address / module / thread) using only
// stack storage and C stdio (no heap, no locks), then chains to the minidump
// filter so a SINGLE install produces both the witness line and the full dump.
// Fixes two prior defects: (1) a second SetUnhandledExceptionFilter() replaced
// this filter and left the witness dead; (2) `if (std::FILE* f = nullptr)` was
// always false, so the witness never wrote at all.
static LONG WINAPI RawrxdCrashFilter(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    const void* addr = (const void*)ep->ExceptionRecord->ExceptionInformation[1];
    char module[MAX_PATH] = "<unknown>";
    HMODULE mod = nullptr;
    if (addr && GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)addr, &mod)) {
        GetModuleFileNameA(mod, module, MAX_PATH);
    }
    char line[512];
    std::snprintf(line, sizeof(line),
                  "[CRASH] code=0x%08lX addr=%p module=%s tid=%lu\n",
                  (unsigned long)code, addr, module, (unsigned long)GetCurrentThreadId());
    std::FILE* f = nullptr;
    if (fopen_s(&f, rawrxdEvidence("IDE_CRASH.log").c_str(), "a") == 0 && f) {
        fputs(line, f);
        fclose(f);
    }
    // Chain to the minidump filter (single authoritative install in WinMain).
    return rawrxdUnhandledException(ep);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Single authoritative filter: RawrxdCrashFilter writes the witness and
    // chains to rawrxdUnhandledException (minidump). Installing the minidump
    // filter again here would replace the witness and leave it dead (prior bug).
    SetUnhandledExceptionFilter(RawrxdCrashFilter);
    startupTrace("WinMain entered");
    startupTrace(lpCmdLine && *lpCmdLine ? lpCmdLine : "WinMain command line empty");

    // Test hook (E2E acceptance for the crash filter): --crash-inject=<av|div0|abort>
    // deliberately faults so the unhandled-exception filter -> witness ->
    // minidump -> termination path can be validated end-to-end. Defense in depth:
    // it is inert unless BOTH the CLI flag AND the RAWRXD_TEST_HOOKS env var are
    // present, so it cannot be activated in a distributed production config.
    if (lpCmdLine && std::strstr(lpCmdLine, "--crash-inject") &&
        GetEnvironmentVariableA("RAWRXD_TEST_HOOKS", nullptr, 0) != 0) {
        const char* kind = std::strstr(lpCmdLine, "--crash-inject=");
        kind = kind ? kind + 15 : "av";
        startupTrace("crash-inject requested");
        if (std::strstr(kind, "div0")) {
            volatile int z = 0;
            volatile int x = 1 / z;  // EXCEPTION_INT_DIVIDE_BY_ZERO
            (void)x;
        } else if (std::strstr(kind, "abort")) {
            std::abort();            // SIGABRT / fail-fast
        } else {
            volatile int* p = nullptr;
            *p = 1;                  // EXCEPTION_ACCESS_VIOLATION (default)
        }
    }

    applyUserDataDirFromCmdLine(lpCmdLine);

    // Headless product health: config/model discovery + backend reachability,
    // then ExitProcess before any GUI/GPU init (no UI races).
    if (lpCmdLine && std::strstr(lpCmdLine, "--health-check")) {
        const int hc = runHealthCheck();
        startupTrace(hc == 0 ? "health-check PASS" : "health-check FAIL");
        ::ExitProcess(static_cast<UINT>(hc));
    }

    // Terminal product ConPTY smoke: run before IDE ctor (no UI/GPU races).
    // --term-quit ExitProcess happens inside runTermSmoke after receipt.
    if (lpCmdLine && std::strstr(lpCmdLine, "--term-smoke")) {
        const int termRc = runTermSmoke(lpCmdLine);
        if (lpCmdLine && std::strstr(lpCmdLine, "--term-quit")) {
            // Fallback if smoke returned instead of ExitProcess.
            startupTrace("term-quit ExitProcess fallback");
            ::ExitProcess(termRc == 0 ? 0 : static_cast<UINT>(termRc));
        }
    }

    // Initialize logger early. P0: workspace-local by default (the old
    // C:\ path is outside the sandbox and unreadable for diagnostics).
    try {
        const char* logEnv = std::getenv("RAWRXD_IDE_LOG");
        IDELogger::getInstance().initialize(
            logEnv && *logEnv ? logEnv : ".rawrxd/ide.log");
        IDELogger::getInstance().setLevel(IDELogger::Level::DEBUG);
        LOG_INFO("WinMain started - RawrXD Win32 IDE initializing");
    } catch (...) {
        // Fallback to file diagnostic if logger fails
        std::ofstream errLog("C:\\LOGGER_INIT_FAILED.txt");
        errLog << "Logger initialization threw exception" << std::endl;
        errLog.close();
    }

    LOG_DEBUG("Creating Win32IDE instance");
    startupTrace("before Win32IDE constructor");
    Win32IDE ide(hInstance);
    startupTrace("after Win32IDE constructor");
    LOG_DEBUG("Win32IDE constructor completed");

    if (!ide.createWindow()) {
        startupTrace("createWindow failed");
        LOG_ERROR("createWindow() failed");
        MessageBoxA(nullptr, "Failed to create window", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    std::string initialPath;
    // The verification and normal shell launch paths may provide an initial
    // document.  WinMain receives the command line without argv[0]; accept a
    // single quoted or unquoted path and load it only after the editor HWND
    // exists so the normal document/session machinery is used.
    if (lpCmdLine && *lpCmdLine) {
        initialPath = lpCmdLine;
        while (!initialPath.empty() &&
               (initialPath.front() == ' ' || initialPath.front() == '\t')) {
            initialPath.erase(initialPath.begin());
        }
        while (!initialPath.empty() &&
               (initialPath.back() == ' ' || initialPath.back() == '\t')) {
            initialPath.pop_back();
        }
        if (initialPath.size() >= 2 && initialPath.front() == '"' &&
            initialPath.back() == '"') {
            initialPath = initialPath.substr(1, initialPath.size() - 2);
        }
    }
    // Problems GUI gate: RAWRXD_PROBLEMS_FIXTURE binds editor when argv open
    // is missing/unsupported by the harness.
    if (initialPath.empty()) {
        char fixtureEnv[1024];
        fixtureEnv[0] = '\0';
        const DWORD n = GetEnvironmentVariableA(
            "RAWRXD_PROBLEMS_FIXTURE", fixtureEnv, sizeof(fixtureEnv));
        if (n > 0 && n < sizeof(fixtureEnv)) {
            initialPath.assign(fixtureEnv, n);
        }
    }

    LOG_INFO("Main window created successfully");
    startupTrace("createWindow succeeded");
    ide.showWindow();
    startupTrace("showWindow returned");

    // Native GUI chat smoke (local-first Ollama): send → tokens → cancel →
    // second request → editor save/open. Writes receipt then ExitProcess.
    if (lpCmdLine && std::strstr(lpCmdLine, "--chat-smoke")) {
        startupTrace("chat-smoke begin");
        const char* receipt = nullptr;
        if (const char* env = std::getenv("RAWRXD_CHAT_SMOKE_RECEIPT")) {
            if (*env) receipt = env;
        }
        ide.beginChatSmoke(receipt);
    }

    // A5 native graphical agent E2E: isolated workspace, real agent-panel
    // submission path, host verdict -> receipt -> ExitProcess.
    if (lpCmdLine && std::strstr(lpCmdLine, "--agent-e2e-test")) {
        CreateDirectoryA(rawrxdEvidence("AGENT_E2E").c_str(), nullptr);
        std::string receipt = rawrxdEvidence("AGENT_E2E\\receipt.txt");
        if (const char* env = std::getenv("RAWRXD_AGENT_E2E_RECEIPT")) {
            if (*env) receipt = env;
        }
        startupTrace("agent-e2e-test begin");
        ide.beginAgentE2ETest(receipt.c_str());
    }

    bool extQuit = false;
#if defined(RAWRXD_NATIVE_IDE_EXT) && RAWRXD_NATIVE_IDE_EXT
    ExtHostWireResult extWire{};
    const bool extCmd = RawrXD_ExtHost_HandleCmdLine(lpCmdLine, &extWire);
    if (extCmd) {
        startupTrace(extWire.loadOk ? "ext-host wire load OK" : "ext-host wire load FAIL/SKIP");
        initialPath.clear();
        // --ext-quit must DestroyWindow: PostQuitMessage alone leaves HWND alive
        // and ~Win32IDE can block forever joining model-discovery (FORCE_KILL).
        if (lpCmdLine && std::strstr(lpCmdLine, "--ext-quit")) {
            extQuit = true;
            HWND hw = ide.getMainWindow();
            if (hw && IsWindow(hw)) {
                startupTrace("ext-quit DestroyWindow");
                DestroyWindow(hw);
            }
            // Re-arm: nested pumps during onDestroy can consume prior WM_QUIT.
            PostQuitMessage(0);
            startupTrace("ext-quit PostQuitMessage re-armed");
        }
    }
#endif
    if (!initialPath.empty() &&
        !(lpCmdLine && (std::strstr(lpCmdLine, "--ext-") ||
                        std::strstr(lpCmdLine, "--vsix") ||
                        std::strstr(lpCmdLine, "--term-smoke") ||
                        std::strstr(lpCmdLine, "--chat-smoke") ||
                        std::strstr(lpCmdLine, "--user-data-dir")))) {
        // Directories are workspace roots, not documents. Queuing a directory
        // as the initial path was observed to tear down Native tip F8249 with
        // process EXIT=-1 ~6s after finishSession.done. Keep the HWND alive.
        const DWORD attrs = GetFileAttributesA(initialPath.c_str());
        const bool isDir =
            attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if (isDir) {
            LOG_INFO("Ignoring directory argv as initial document: " +
                     initialPath);
            startupTrace("initial document skipped (directory argv)");
        } else {
            // Do NOT open here: finishSession loadEditorSession runs after the
            // message loop starts and would overwrite the buffer/title with the
            // sticky session (INITIALPATH_BUFFER_LEN_0_TITLE_MISS / broken_multi).
            // Queue until flushPendingInitialDocument after session materialize.
            LOG_INFO("Queueing initial document (post-session): " + initialPath);
            ide.queueInitialDocumentPath(initialPath);
            startupTrace("initial document queued for post-session flush");
        }
    }
    LOG_INFO("Entering message loop");
    startupTrace("entering message loop");
    int rc = ide.runMessageLoop();
    LOG_INFO("Message loop exited with code " + std::to_string(rc));
    if (extQuit) {
        // Skip ~Win32IDE join of discovery/HTTP workers past smoke WaitForExit.
        startupTrace("ext-quit ExitProcess");
        ::ExitProcess(rc == 0 ? 0 : static_cast<UINT>(rc));
    }
    return rc;
}
