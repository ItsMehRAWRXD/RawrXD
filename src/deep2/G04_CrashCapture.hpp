// ============================================================================
// G04 crash capture — in-process access-violation reporter.
//
// The WER LocalDumps for this binary carry no thread CONTEXT, so the faulting
// instruction and call stack cannot be recovered from the .dmp. A vectored
// exception handler runs ON the faulting thread's context, so it can read the
// faulting address, RIP, RSP and a real backtrace at the moment of the fault.
//
// The addresses are printed to stderr and symbolized offline against the
// linker .map file. No failures are suppressed: after reporting, the exception
// is re-raised so the process still dies with the original status.
// ============================================================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dbghelp.h>
#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "dbghelp.lib")

namespace g04crash {

static PVOID  g_veh = nullptr;
static LONG   g_count = 0;

static const char* op_name(ULONG_PTR p1) {
    // EXCEPTION_WRITE_FAULT = 2, EXCEPTION_READ_FAULT = 0, EXCEPTION_EXECUTE_FAULT = 8
    switch (p1 & 0xFF) {
        case 0: return "READ";
        case 2: return "WRITE";
        case 8: return "EXECUTE";
        default: return "?";
    }
}

static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* info) {
    if (!info || !info->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const EXCEPTION_RECORD* er = info->ExceptionRecord;

    // Only report genuine access violations; let everything else through.
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    LONG n = InterlockedIncrement(&g_count);
    fprintf(stderr, "\n[G04CRASH] ==== ACCESS VIOLATION #%ld ====\n", (long)n);
    fprintf(stderr, "[G04CRASH] thread        : %lu\n",
            (unsigned long)GetCurrentThreadId());
    fprintf(stderr, "[G04CRASH] code          : 0x%08lx\n",
            (unsigned long)er->ExceptionCode);
    fprintf(stderr, "[G04CRASH] fault address : 0x%016llx\n",
            (unsigned long long)er->ExceptionInformation[0]);
    fprintf(stderr, "[G04CRASH] operation     : %s\n",
            op_name(er->NumberParameters > 1 ? er->ExceptionInformation[1] : 0));
    fprintf(stderr, "[G04CRASH] rip           : 0x%016llx\n",
            (unsigned long long)info->ContextRecord->Rip);
    fprintf(stderr, "[G04CRASH] rsp           : 0x%016llx\n",
            (unsigned long long)info->ContextRecord->Rsp);
    fprintf(stderr, "[G04CRASH] rcx           : 0x%016llx (base ptr on write)\n",
            (unsigned long long)info->ContextRecord->Rcx);
    fprintf(stderr, "[G04CRASH] rdx           : 0x%016llx\n",
            (unsigned long long)info->ContextRecord->Rdx);
    fprintf(stderr, "[G04CRASH] r8            : 0x%016llx\n",
            (unsigned long long)info->ContextRecord->R8);

    // Backtrace. CaptureStackBackTrace from the handler frame; skip the first
    // frame (the handler itself) and the vectored-export trampoline.
    void* frames[48];
    USHORT nf = CaptureStackBackTrace(2, 48, frames, nullptr);
    fprintf(stderr, "[G04CRASH] backtrace (%u frames):\n", (unsigned)nf);
    for (USHORT i = 0; i < nf; ++i) {
        fprintf(stderr, "[G04CRASH]   [%02u] 0x%016llx\n", (unsigned)i,
                (unsigned long long)frames[i]);
    }

    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    HANDLE proc = GetCurrentProcess();
    if (SymInitialize(proc, nullptr, TRUE)) {
        for (USHORT i = 0; i < nf; ++i) {
            char buf[sizeof(SYMBOL_INFO) + 255];
            SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buf);
            memset(buf, 0, sizeof(buf));
            si->SizeOfStruct = sizeof(SYMBOL_INFO);
            si->MaxNameLen = 255;
            DWORD64 d = 0;
            if (SymFromAddr(proc, (DWORD64)frames[i], &d, si)) {
                IMAGEHLP_LINE64 ln;
                memset(&ln, 0, sizeof(ln));
                ln.SizeOfStruct = sizeof(ln);
                DWORD c = 0;
                if (SymGetLineFromAddr64(proc, (DWORD64)frames[i], &c, &ln)) {
                    fprintf(stderr, "[G04CRASH]   [%02u] %s +0x%llx  (%s:%lu)\n",
                            (unsigned)i, si->Name, (unsigned long long)d,
                            ln.FileName, (unsigned long)ln.LineNumber);
                } else {
                    fprintf(stderr, "[G04CRASH]   [%02u] %s +0x%llx\n",
                            (unsigned)i, si->Name, (unsigned long long)d);
                }
            }
        }
    }

    fprintf(stderr, "[G04CRASH] ==== end report ====\n");
    fflush(stderr);

    // Do not suppress: the original exception must still terminate the process
    // so the exit code and WER report keep the real failure.
    return EXCEPTION_CONTINUE_SEARCH;
}

inline bool Install() {
    g_veh = AddVectoredExceptionHandler(1, VectoredHandler);
    return g_veh != nullptr;
}

inline void Remove() {
    if (g_veh) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = nullptr;
    }
}

} // namespace g04crash
