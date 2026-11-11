// ============================================================================
// CrashHandler.cpp — Native Crash Handler Implementation
// ============================================================================

#include "CrashHandler.hpp"
#include "../runtime/RawrRuntime.hpp"
#include <chrono>
#include <cstdio>
#include <optional>

#ifdef _WIN32
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

namespace rawr {

CrashHandler& CrashHandler::Get() {
    static CrashHandler instance;
    return instance;
}

void CrashHandler::Initialize() {
#ifdef _WIN32
    // Set up vectored exception handler
    m_vectoredHandle = AddVectoredExceptionHandler(1, VectoredHandler);

    // Initialize minidump support
    SetUnhandledExceptionFilter(nullptr);

    RawrRuntime::Get().Log(LogLevel::Info, "CrashHandler initialized");
#endif
}

void CrashHandler::Shutdown() {
#ifdef _WIN32
    if (m_vectoredHandle) {
        RemoveVectoredExceptionHandler(m_vectoredHandle);
        m_vectoredHandle = nullptr;
    }
#endif
}

bool CrashHandler::WriteMinidump(const char* path) {
#ifdef _WIN32
    if (!path) path = "rawrxd_crash.dmp";

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    MINIDUMP_EXCEPTION_INFORMATION mei = {};
    // In a real handler, we'd pass the exception pointers

    BOOL result = MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        hFile,
        MiniDumpWithDataSegs,
        nullptr, nullptr, nullptr
    );

    CloseHandle(hFile);
    return result != 0;
#else
    return false;
#endif
}

void CrashHandler::Reset() {
    m_crashCount = 0;
    m_lastCrash.reset();
}

LONG WINAPI CrashHandler::VectoredHandler(EXCEPTION_POINTERS* ep) {
    auto& handler = Get();
    handler.m_crashCount++;

    CrashInfo info;
    info.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    info.code = ep->ExceptionRecord->ExceptionCode;
    info.address = (uint64_t)ep->ExceptionRecord->ExceptionAddress;

    switch (ep->ExceptionRecord->ExceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:   info.description = "Access violation"; break;
        case EXCEPTION_ILLEGAL_INSTRUCTION: info.description = "Illegal instruction"; break;
        case EXCEPTION_STACK_OVERFLOW:     info.description = "Stack overflow"; break;
        case EXCEPTION_BREAKPOINT:         info.description = "Breakpoint"; break;
        default:                           info.description = "Unknown exception"; break;
    }

    handler.m_lastCrash = info;

    if (handler.m_onCrash) {
        handler.m_onCrash(info);
    }

    // Write minidump
    handler.WriteMinidump();

    // Return EXCEPTION_CONTINUE_SEARCH to let the default handler terminate
    return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace rawr
