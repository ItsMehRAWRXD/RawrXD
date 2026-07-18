// RawrXD Crash Reporter
// Phase 8 - Task 19: Crash Reporter

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#pragma comment(lib, "dbghelp.lib")

// Crash report configuration
#define CRASH_REPORT_DIR "crash_reports"
#define MAX_STACK_FRAMES 64
#define MAX_SYMBOL_LENGTH 256
#define MAX_MODULE_NAME 128

// Crash information
struct CrashInfo {
    EXCEPTION_POINTERS* exception;
    DWORD threadId;
    char timestamp[64];
    char executablePath[MAX_PATH];
    char reportPath[MAX_PATH];
};

// Crash handler context
static HANDLE g_hProcess = nullptr;
static char g_reportDir[MAX_PATH] = {0};
static bool g_initialized = false;

// Function prototypes
LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* exception);
void GenerateCrashReport(const CrashInfo& info);
void WriteMinidump(const CrashInfo& info);
void WriteStackTrace(HANDLE hFile, CONTEXT* context);
void WriteSystemInfo(HANDLE hFile);
void WriteModuleList(HANDLE hFile);

// Initialize crash reporter
bool CrashReporter_Init(const char* reportDirectory) {
    if (g_initialized) return true;
    
    // Store report directory
    if (reportDirectory) {
        strcpy_s(g_reportDir, reportDirectory);
    } else {
        // Use default location
        GetModuleFileNameA(nullptr, g_reportDir, MAX_PATH);
        char* lastSlash = strrchr(g_reportDir, '\\');
        if (lastSlash) {
            *(lastSlash + 1) = '\0';
            strcat_s(g_reportDir, CRASH_REPORT_DIR);
        }
    }
    
    // Create report directory
    CreateDirectoryA(g_reportDir, nullptr);
    
    // Initialize symbol handler
    g_hProcess = GetCurrentProcess();
    SymInitialize(g_hProcess, nullptr, TRUE);
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS);
    
    // Set unhandled exception filter
    SetUnhandledExceptionFilter(ExceptionHandler);
    
    g_initialized = true;
    return true;
}

// Shutdown crash reporter
void CrashReporter_Shutdown() {
    if (!g_initialized) return;
    
    SymCleanup(g_hProcess);
    g_initialized = false;
}

// Exception handler
LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* exception) {
    CrashInfo info;
    info.exception = exception;
    info.threadId = GetCurrentThreadId();
    
    // Get timestamp
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    strftime(info.timestamp, sizeof(info.timestamp), "%Y%m%d_%H%M%S", &timeinfo);
    
    // Get executable path
    GetModuleFileNameA(nullptr, info.executablePath, MAX_PATH);
    
    // Generate report path
    snprintf(info.reportPath, MAX_PATH, "%s\\crash_%s_%lu.txt", 
             g_reportDir, info.timestamp, info.threadId);
    
    // Generate crash report
    GenerateCrashReport(info);
    
    // Write minidump
    WriteMinidump(info);
    
    // Show crash dialog (if not silent)
    char message[512];
    snprintf(message, sizeof(message), 
             "RawrXD has encountered an error and needs to close.\n\n"
             "A crash report has been saved to:\n%s\n\n"
             "Please report this issue with the crash report attached.",
             info.reportPath);
    
    MessageBoxA(nullptr, message, "RawrXD Crash", MB_OK | MB_ICONERROR);
    
    // Return to let Windows handle the exception
    return EXCEPTION_EXECUTE_HANDLER;
}

// Generate text crash report
void GenerateCrashReport(const CrashInfo& info) {
    HANDLE hFile = CreateFileA(info.reportPath, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    // Write header
    char header[1024];
    snprintf(header, sizeof(header),
             "========================================\n"
             "RawrXD Crash Report\n"
             "========================================\n"
             "Timestamp: %s\n"
             "Thread ID: %lu\n"
             "Executable: %s\n"
             "\n",
             info.timestamp, info.threadId, info.executablePath);
    
    DWORD written;
    WriteFile(hFile, header, (DWORD)strlen(header), &written, nullptr);
    
    // Write exception info
    if (info.exception) {
        EXCEPTION_RECORD* record = info.exception->ExceptionRecord;
        char exceptionInfo[512];
        
        const char* exceptionName = "Unknown";
        switch (record->ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION: exceptionName = "ACCESS_VIOLATION"; break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: exceptionName = "ARRAY_BOUNDS_EXCEEDED"; break;
            case EXCEPTION_BREAKPOINT: exceptionName = "BREAKPOINT"; break;
            case EXCEPTION_DATATYPE_MISALIGNMENT: exceptionName = "DATATYPE_MISALIGNMENT"; break;
            case EXCEPTION_FLT_DENORMAL_OPERAND: exceptionName = "FLT_DENORMAL_OPERAND"; break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO: exceptionName = "FLT_DIVIDE_BY_ZERO"; break;
            case EXCEPTION_FLT_INVALID_OPERATION: exceptionName = "FLT_INVALID_OPERATION"; break;
            case EXCEPTION_FLT_OVERFLOW: exceptionName = "FLT_OVERFLOW"; break;
            case EXCEPTION_FLT_UNDERFLOW: exceptionName = "FLT_UNDERFLOW"; break;
            case EXCEPTION_ILLEGAL_INSTRUCTION: exceptionName = "ILLEGAL_INSTRUCTION"; break;
            case EXCEPTION_IN_PAGE_ERROR: exceptionName = "IN_PAGE_ERROR"; break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO: exceptionName = "INT_DIVIDE_BY_ZERO"; break;
            case EXCEPTION_INT_OVERFLOW: exceptionName = "INT_OVERFLOW"; break;
            case EXCEPTION_INVALID_DISPOSITION: exceptionName = "INVALID_DISPOSITION"; break;
            case EXCEPTION_NONCONTINUABLE_EXCEPTION: exceptionName = "NONCONTINUABLE_EXCEPTION"; break;
            case EXCEPTION_PRIV_INSTRUCTION: exceptionName = "PRIV_INSTRUCTION"; break;
            case EXCEPTION_SINGLE_STEP: exceptionName = "SINGLE_STEP"; break;
            case EXCEPTION_STACK_OVERFLOW: exceptionName = "STACK_OVERFLOW"; break;
        }
        
        snprintf(exceptionInfo, sizeof(exceptionInfo),
                 "Exception Code: 0x%08X (%s)\n"
                 "Exception Address: 0x%p\n"
                 "\n",
                 record->ExceptionCode, exceptionName, record->ExceptionAddress);
        
        WriteFile(hFile, exceptionInfo, (DWORD)strlen(exceptionInfo), &written, nullptr);
    }
    
    // Write stack trace
    WriteStackTrace(hFile, info.exception->ContextRecord);
    
    // Write system info
    WriteSystemInfo(hFile);
    
    // Write module list
    WriteModuleList(hFile);
    
    CloseHandle(hFile);
}

// Write minidump
void WriteMinidump(const CrashInfo& info) {
    char dumpPath[MAX_PATH];
    snprintf(dumpPath, MAX_PATH, "%s\\crash_%s_%lu.dmp", 
             g_reportDir, info.timestamp, info.threadId);
    
    HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    MINIDUMP_EXCEPTION_INFORMATION dumpInfo;
    dumpInfo.ThreadId = info.threadId;
    dumpInfo.ExceptionPointers = info.exception;
    dumpInfo.ClientPointers = FALSE;
    
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile,
                      MiniDumpNormal, &dumpInfo, nullptr, nullptr);
    
    CloseHandle(hFile);
}

// Write stack trace
void WriteStackTrace(HANDLE hFile, CONTEXT* context) {
    const char* header = "\nStack Trace:\n";
    DWORD written;
    WriteFile(hFile, header, (DWORD)strlen(header), &written, nullptr);
    
    STACKFRAME64 stackFrame = {};
    DWORD machineType;
    
#ifdef _M_X64
    machineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = context->Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#else
    machineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = context->Eip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Ebp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Esp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
#endif
    
    for (int frameNum = 0; frameNum < MAX_STACK_FRAMES; frameNum++) {
        if (!StackWalk64(machineType, g_hProcess, GetCurrentThread(), &stackFrame, context, 
                         nullptr, SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
            break;
        }
        
        // Get symbol info
        char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYMBOL_LENGTH];
        SYMBOL_INFO* symbol = (SYMBOL_INFO*)symbolBuffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYMBOL_LENGTH;
        
        DWORD64 displacement = 0;
        char lineBuffer[512];
        
        if (SymFromAddr(g_hProcess, stackFrame.AddrPC.Offset, &displacement, symbol)) {
            snprintf(lineBuffer, sizeof(lineBuffer), 
                     "  %2d: 0x%p %s + 0x%llX\n",
                     frameNum, (void*)stackFrame.AddrPC.Offset, 
                     symbol->Name, displacement);
        } else {
            snprintf(lineBuffer, sizeof(lineBuffer), 
                     "  %2d: 0x%p [unknown]\n",
                     frameNum, (void*)stackFrame.AddrPC.Offset);
        }
        
        WriteFile(hFile, lineBuffer, (DWORD)strlen(lineBuffer), &written, nullptr);
    }
}

// Write system information
void WriteSystemInfo(HANDLE hFile) {
    const char* header = "\nSystem Information:\n";
    DWORD written;
    WriteFile(hFile, header, (DWORD)strlen(header), &written, nullptr);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    char info[1024];
    snprintf(info, sizeof(info),
             "  OS Version: Windows %lu.%lu\n"
             "  Processor Architecture: %s\n"
             "  Number of Processors: %lu\n"
             "  Total Physical Memory: %llu MB\n"
             "  Available Physical Memory: %llu MB\n"
             "\n",
             GetVersion() & 0xFF, (GetVersion() >> 8) & 0xFF,
             sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86",
             sysInfo.dwNumberOfProcessors,
             memStatus.ullTotalPhys / (1024 * 1024),
             memStatus.ullAvailPhys / (1024 * 1024));
    
    WriteFile(hFile, info, (DWORD)strlen(info), &written, nullptr);
}

// Write module list
void WriteModuleList(HANDLE hFile) {
    const char* header = "\nLoaded Modules:\n";
    DWORD written;
    WriteFile(hFile, header, (DWORD)strlen(header), &written, nullptr);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    if (Module32First(hSnapshot, &me32)) {
        do {
            char moduleInfo[512];
            snprintf(moduleInfo, sizeof(moduleInfo),
                     "  0x%p - 0x%p %s\n",
                     me32.modBaseAddr,
                     (BYTE*)me32.modBaseAddr + me32.modBaseSize,
                     me32.szModule);
            WriteFile(hFile, moduleInfo, (DWORD)strlen(moduleInfo), &written, nullptr);
        } while (Module32Next(hSnapshot, &me32));
    }
    
    CloseHandle(hSnapshot);
}

// C API
extern "C" {

bool CrashReporter_Initialize(const char* reportDir) {
    return CrashReporter_Init(reportDir);
}

void CrashReporter_Cleanup() {
    CrashReporter_Shutdown();
}

} // extern "C"
