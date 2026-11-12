// aggregate_decode_single_smoke - cold+warm single-session aggregate decode.
#include "aggregate_decode/AggregateDecodeSession.hpp"
#include "aggregate_decode/AggregateDecodeOllamaBackend.hpp"
#include "aggregate_decode/AggregateDecodeDeep2Backend.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace rawr::aggdec;

// ---------------------------------------------------------------------------
// First-chance exception recorder (diagnostic only, env-gated).
//
// Enabled only when DEEP2_VEH_STACK is set. When unset this block is inert:
// no handler is installed and no symbol engine is initialised, so benchmark
// behaviour and timing are unchanged.
//
// The engine catches its own C++ exceptions, so a normal run never surfaces a
// stack. std::mutex::lock throws std::system_error with
// resource_deadlock_would_occur when the calling thread already owns the mutex.
// A vectored exception handler sees that throw at the moment it is raised, on
// the offending thread, before any unwinding.
// ---------------------------------------------------------------------------
#if defined(_WIN32)
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>

#pragma comment(lib, "dbghelp.lib")

namespace
{
    volatile LONG g_veRecorded    = 0;
    PVOID           g_veHandle     = nullptr;
    bool            g_veSymbolReady = false;

    void VeWriteAllThreads(const char* path, DWORD faultingThread)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return;
        FILE* f = std::fopen(path, "a");
        if (!f)
        {
            CloseHandle(snap);
            return;
        }
        std::fprintf(f, "--- other threads ---\n");
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te))
        {
            do
            {
                if (te.th32ThreadID == faultingThread)
                    continue;
                HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                      FALSE, te.th32ThreadID);
                if (!h)
                {
                    std::fprintf(f, "tid=%lu open_failed\n", te.th32ThreadID);
                    continue;
                }
                if (SuspendThread(h) == (DWORD)-1)
                {
                    std::fprintf(f, "tid=%lu suspend_failed\n", te.th32ThreadID);
                    CloseHandle(h);
                    continue;
                }
                CONTEXT ctx;
                std::memset(&ctx, 0, sizeof(ctx));
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(h, &ctx))
                    std::fprintf(f, "tid=%lu rip=%p rsp=%p\n", te.th32ThreadID,
                                 (void*)ctx.Rip, (void*)ctx.Rsp);
                else
                    std::fprintf(f, "tid=%lu getcontext_failed\n", te.th32ThreadID);
                ResumeThread(h);
                CloseHandle(h);
            } while (Thread32Next(snap, &te));
        }
        std::fclose(f);
        CloseHandle(snap);
    }

    LONG CALLBACK VeHandler(EXCEPTION_POINTERS* ep)
    {
        if (!ep || !ep->ExceptionRecord)
            return EXCEPTION_CONTINUE_SEARCH;
        const DWORD code = ep->ExceptionRecord->ExceptionCode;
        if (code != 0xE06D7363u && code != EXCEPTION_ACCESS_VIOLATION &&
            code != EXCEPTION_ILLEGAL_INSTRUCTION)
            return EXCEPTION_CONTINUE_SEARCH;
        if (InterlockedIncrement(&g_veRecorded) > 12)
            return EXCEPTION_CONTINUE_SEARCH;

        const char* outDir = std::getenv("DEEP2_VEH_OUT");
        if (!outDir || !outDir[0])
            outDir = ".";

        char path[MAX_PATH * 2];
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\THROW_%02ld.txt", outDir,
                    (long)g_veRecorded);

        if (!g_veSymbolReady)
        {
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
            SymInitialize(GetCurrentProcess(), nullptr, TRUE);
            g_veSymbolReady = true;
        }

        void* frames[64];
        const USHORT n = CaptureStackBackTrace(0, 64, frames, nullptr);

        FILE* f = std::fopen(path, "a");
        if (!f)
            return EXCEPTION_CONTINUE_SEARCH;

        std::fprintf(f, "CODE=0x%08lX\n", (unsigned long)code);
        std::fprintf(f, "THROW_ADDRESS=%p\n", ep->ExceptionRecord->ExceptionAddress);
        std::fprintf(f, "THREAD=%lu\n", GetCurrentThreadId());
        std::fprintf(f, "--- stack (throw site first) ---\n");
        for (USHORT i = 0; i < n; ++i)
        {
            char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
            SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(symBuf);
            std::memset(si, 0, sizeof(symBuf));
            si->SizeOfStruct = sizeof(SYMBOL_INFO);
            si->MaxNameLen   = MAX_SYM_NAME;
            DWORD64 disp = 0;
            const char* name = "?";
            if (SymFromAddr(GetCurrentProcess(), (DWORD64)frames[i], &disp, si))
                name = si->Name;
            IMAGEHLP_LINE64 line;
            std::memset(&line, 0, sizeof(line));
            line.SizeOfStruct = sizeof(line);
            DWORD ldisp = 0;
            const char* file = "";
            int lineno = 0;
            if (SymGetLineFromAddr64(GetCurrentProcess(), (DWORD64)frames[i], &ldisp, &line))
            {
                file   = line.FileName;
                lineno = (int)line.LineNumber;
            }
            std::fprintf(f, "  #%02u %p  %s + 0x%llX  (%s:%d)\n", i, frames[i], name,
                         (unsigned long long)disp, file, lineno);
        }
        std::fclose(f);
        VeWriteAllThreads(path, GetCurrentThreadId());
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void VeInstall()
    {
        if (!std::getenv("DEEP2_VEH_STACK") || g_veHandle)
            return;
        g_veHandle = AddVectoredExceptionHandler(1, VeHandler);
        std::printf("[VEH] first-chance recorder armed (out=%s)\n",
                    std::getenv("DEEP2_VEH_OUT") ? std::getenv("DEEP2_VEH_OUT") : ".");
        std::fflush(stdout);
    }
}
#endif // _WIN32

static const char* env_or(const char* k, const char* d) {
    const char* v = std::getenv(k);
    return (v && v[0]) ? v : d;
}

static bool env_truthy(const char* k) {
    const char* v = std::getenv(k);
    return v && v[0] && v[0] != '0';
}

int main(int argc, char** argv) {
#if defined(_WIN32)
    VeInstall();
#endif
    const char* host = env_or("AGGREGATE_DECODE_OLLAMA_HOST",
                              "http://127.0.0.1:11434");
    const char* model = env_or("AGGREGATE_DECODE_MODEL",
                               "n4-tiny-oracle:latest");
    const char* gguf = env_or("AGGREGATE_DECODE_GGUF", "");
    bool require_deep2 =
        env_truthy("AGGREGATE_DECODE_REQUIRE_DEEP2") ||
        env_truthy("AGGREGATE_DECODE_USE_DEEP2");
    uint32_t max_tok = 16;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--model") && i + 1 < argc) model = argv[++i];
        else if (!std::strcmp(argv[i], "--gguf") && i + 1 < argc) gguf = argv[++i];
        else if (!std::strcmp(argv[i], "--tokens") && i + 1 < argc)
            max_tok = (uint32_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--require-deep2")) require_deep2 = true;
    }

    std::unique_ptr<IAggregateDecodeBackend> be;
    int deep2_runtime_reached = 0;
    if (gguf && gguf[0]) {
        auto* d2 = new AggregateDecodeDeep2Backend(gguf);
        std::printf("DEEP2_LINKED=%d\n", d2->linked() ? 1 : 0);
        if (d2->linked() && d2->open()) {
            be.reset(d2);
            std::printf("BACKEND=DEEP2\nBACKEND_LABEL=DEEP2_ENGINE\nMODEL=%s\n",
                        gguf);
        } else {
            const bool linked = d2->linked();
            delete d2;
            std::printf("DEEP2_OPEN_FAILED=1 LINKED=%d\n", linked ? 1 : 0);
            if (require_deep2 || linked) {
                std::printf("FALLBACK=REFUSED\n");
                std::printf("SOURCE_WIRED=1\nRUNTIME_REACHED=0\n");
                std::printf("deep2_runtime_reached=0\n");
                std::printf("GENERATED_TOKENS=0\nCERTIFIED=0\nPROMOTE=0\n");
                return 3;
            }
            std::printf("FALLBACK=OLLAMA_HTTP\n");
        }
    } else if (require_deep2) {
        std::printf("DEEP2_REQUIRED=1 GGUF_MISSING=1\n");
        std::printf("SOURCE_WIRED=1\nRUNTIME_REACHED=0\ndeep2_runtime_reached=0\n");
        std::printf("GENERATED_TOKENS=0\nCERTIFIED=0\nPROMOTE=0\n");
        return 3;
    }
    if (!be) {
        be.reset(new AggregateDecodeOllamaBackend(host, model));
        std::printf("BACKEND=OLLAMA_HTTP\nMODEL=%s\nHOST=%s\n", model, host);
    }

    AggregateDecodeSession session(be.get());
    if (!session.open()) {
        std::printf("SOURCE_WIRED=1 RUNTIME_REACHED=0 OPEN_FAIL=1\n");
        std::printf("deep2_runtime_reached=0\n");
        return 2;
    }

    DecodeRequest req;
    req.session_id = 0;
    req.prompt = "Write one short sentence about aggregate decode throughput.";
    req.max_tokens = max_tok;

    std::printf("PHASE=COLD_WARM\n");
    AggregateResult r = session.run(req, true);
    session.close();

    if (r.backend == BackendKind::Deep2Engine && r.all_sessions_worked &&
        r.total_tokens > 0)
        deep2_runtime_reached = 1;

    std::printf("GENERATED_TOKENS=%llu\n",
                (unsigned long long)r.total_tokens);
    std::printf("WALL_NS=%llu\n", (unsigned long long)r.wall_ns);
    std::printf("AGGREGATE_DECODE_TPS_SINGLE=%.6f\n", r.aggregate_tps);
    std::printf("BACKEND_LABEL=%s\n", r.backend_label.c_str());
    std::printf("SOURCE_WIRED=1\n");
    std::printf("RUNTIME_REACHED=%d\n", r.all_sessions_worked ? 1 : 0);
    std::printf("deep2_runtime_reached=%d\n", deep2_runtime_reached);
    std::printf("CERTIFIED=0\nPROMOTE=0\nTIP_CLIMB=HOLD\n");
    if (require_deep2 && !deep2_runtime_reached) return 4;
    return r.all_sessions_worked ? 0 : 1;
}

