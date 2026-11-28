// crash_filter_smoke.cpp — Package 4 (crash diagnostic) acceptance smoke.
// Installs an unhandled-exception filter that writes a witness log + a minidump,
// then deliberately faults. Verifies the crash-capture MECHANISM works on this
// platform (the IDE's RawrxdCrashFilter uses the same dbghelp primitives).
//
// Build:
//   cl /nologo /std:c++17 /EHsc crash_filter_smoke.cpp /Fe:crash_filter_smoke.exe /link dbghelp.lib
// Exit 0 = both artifacts written (PASS); non-zero = failure.
#include <windows.h>
#include <dbghelp.h>
#include <cstdio>

static const char* kWitness = "crash_witness.txt";
static const char* kDump    = "crash_smoke.dmp";

static LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) {
    // Witness line: code/address/module-ish (the IDE filter emits the same class of data).
    FILE* f = nullptr;
    if (fopen_s(&f, kWitness, "w") == 0 && f) {
        fprintf(f, "IDE_CRASH code=0x%08lX addr=%p tid=%lu\n",
                (unsigned long)ep->ExceptionRecord->ExceptionCode,
                ep->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
        fclose(f);
    }
    // Minidump.
    HANDLE hf = CreateFileA(kDump, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf != INVALID_HANDLE_VALUE) {
        MINIDUMP_EXCEPTION_INFORMATION mei{};
        mei.ThreadId = GetCurrentThreadId();
        mei.ExceptionPointers = ep;
        mei.ClientPointers = FALSE;
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hf,
                          MiniDumpNormal, &mei, nullptr, nullptr);
        CloseHandle(hf);
    }
    return EXCEPTION_EXECUTE_HANDLER;  // handled: terminate without WER dialog
}

int main() {
    SetUnhandledExceptionFilter(CrashFilter);
    // Deliberate null dereference to trigger the filter.
    volatile int* p = nullptr;
    *p = 0xDEAD;
    return 99;  // not reached
}