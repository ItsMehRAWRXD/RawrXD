// AgentExceptionHandler.cpp — Win32 SEH for agent stress test crash dumps
// Captures telemetry state on EXCEPTION_ACCESS_VIOLATION, OOM, etc.
// Build: cl /O2 /EHsc /c AgentExceptionHandler.cpp

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>

// Include the telemetry header
#include "AgentTelemetry.h"

// ============================================================================
// EXCEPTION CONTEXT — What we capture on crash
// ============================================================================

struct CrashContext {
    DWORD exceptionCode;
    ULONG_PTR exceptionAddress;
    CONTEXT cpuContext;
    AgentTelemetry telemetrySnapshot;
    char timestamp[64];
    char dumpPath[MAX_PATH];
};

static CrashContext g_crashContext;
static LPTOP_LEVEL_EXCEPTION_FILTER g_prevFilter = nullptr;

// ============================================================================
// TELEMETRY DUMP — Write state to disk before termination
// ============================================================================

void WriteTelemetryDump(const CrashContext* ctx) {
    // Generate filename: agent_crash_YYYYMMDD_HHMMSS.txt
    char filename[MAX_PATH];
    snprintf(filename, sizeof(filename), 
             "agent_crash_%s.txt", ctx->timestamp);
    
    // Try multiple locations
    const char* paths[] = {
        "D:\\rawrxd-ci-bootstrap\\telemetry\\",
        "D:\\rawrxd\\telemetry\\",
        ".\\telemetry\\",
        ".\\",
        nullptr
    };
    
    FILE* fp = nullptr;
    for (int i = 0; paths[i]; ++i) {
        char fullPath[MAX_PATH];
        snprintf(fullPath, sizeof(fullPath), "%s%s", paths[i], filename);
        
        // Create directory if needed
        CreateDirectoryA(paths[i], nullptr);
        
        if (fopen_s(&fp, fullPath, "w") == 0 && fp) {
            strncpy_s(const_cast<char*>(ctx->dumpPath), 
                     sizeof(ctx->dumpPath), fullPath, _TRUNCATE);
            break;
        }
    }
    
    if (!fp) {
        // Last resort: write to temp
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        strcat_s(tempPath, filename);
        fopen_s(&fp, tempPath, "w");
    }
    
    if (!fp) return;
    
    // Write crash report
    fprintf(fp, "=================================================================\n");
    fprintf(fp, "  RawrXD Agent Stress Test — CRASH DUMP\n");
    fprintf(fp, "  Timestamp: %s\n", ctx->timestamp);
    fprintf(fp, "=================================================================\n\n");
    
    // Exception info
    fprintf(fp, "EXCEPTION INFORMATION\n");
    fprintf(fp, "  Code: 0x%08X (", ctx->exceptionCode);
    switch (ctx->exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:         fprintf(fp, "ACCESS_VIOLATION"); break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    fprintf(fp, "ARRAY_BOUNDS_EXCEEDED"); break;
        case EXCEPTION_BREAKPOINT:               fprintf(fp, "BREAKPOINT"); break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:    fprintf(fp, "DATATYPE_MISALIGNMENT"); break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       fprintf(fp, "FLT_DIVIDE_BY_ZERO"); break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:      fprintf(fp, "ILLEGAL_INSTRUCTION"); break;
        case EXCEPTION_IN_PAGE_ERROR:            fprintf(fp, "IN_PAGE_ERROR"); break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       fprintf(fp, "INT_DIVIDE_BY_ZERO"); break;
        case EXCEPTION_INT_OVERFLOW:             fprintf(fp, "INT_OVERFLOW"); break;
        case EXCEPTION_INVALID_DISPOSITION:      fprintf(fp, "INVALID_DISPOSITION"); break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: fprintf(fp, "NONCONTINUABLE_EXCEPTION"); break;
        case EXCEPTION_PRIV_INSTRUCTION:         fprintf(fp, "PRIV_INSTRUCTION"); break;
        case EXCEPTION_SINGLE_STEP:              fprintf(fp, "SINGLE_STEP"); break;
        case EXCEPTION_STACK_OVERFLOW:           fprintf(fp, "STACK_OVERFLOW"); break;
        case STATUS_NO_MEMORY:                   fprintf(fp, "OUT_OF_MEMORY"); break;
        default:                               fprintf(fp, "UNKNOWN"); break;
    }
    fprintf(fp, ")\n");
    fprintf(fp, "  Address: 0x%p\n", (void*)ctx->exceptionAddress);
    fprintf(fp, "\n");
    
    // CPU context (key registers)
    fprintf(fp, "CPU CONTEXT\n");
    fprintf(fp, "  RIP: 0x%016llX\n", ctx->cpuContext.Rip);
    fprintf(fp, "  RSP: 0x%016llX\n", ctx->cpuContext.Rsp);
    fprintf(fp, "  RBP: 0x%016llX\n", ctx->cpuContext.Rbp);
    fprintf(fp, "  RAX: 0x%016llX\n", ctx->cpuContext.Rax);
    fprintf(fp, "  RBX: 0x%016llX\n", ctx->cpuContext.Rbx);
    fprintf(fp, "  RCX: 0x%016llX\n", ctx->cpuContext.Rcx);
    fprintf(fp, "  RDX: 0x%016llX\n", ctx->cpuContext.Rdx);
    fprintf(fp, "\n");
    
    // Telemetry snapshot
    const AgentTelemetry* t = &ctx->telemetrySnapshot;
    fprintf(fp, "TELEMETRY SNAPSHOT\n");
    fprintf(fp, "  Heap Used:        %llu bytes (%.2f MB)\n", 
            t->heapUsed.load(), t->heapUsed.load() / (1024.0 * 1024.0));
    fprintf(fp, "  Peak Heap:        %llu bytes (%.2f MB)\n",
            t->peakHeap.load(), t->peakHeap.load() / (1024.0 * 1024.0));
    fprintf(fp, "  VRAM Used:        %llu bytes (%.2f MB)\n",
            t->vramUsed.load(), t->vramUsed.load() / (1024.0 * 1024.0));
    fprintf(fp, "  Peak VRAM:        %llu bytes (%.2f MB)\n",
            t->peakVram.load(), t->peakVram.load() / (1024.0 * 1024.0));
    fprintf(fp, "\n");
    
    fprintf(fp, "  Swarm Messages:   %u\n", t->swarmMessageCount.load());
    fprintf(fp, "  Context Switches: %u\n", t->contextSwitches.load());
    fprintf(fp, "\n");
    
    fprintf(fp, "  Proposals Generated: %u\n", t->proposalsGenerated.load());
    fprintf(fp, "  Proposals Applied:   %u\n", t->proposalsApplied.load());
    fprintf(fp, "  Files Ingested:      %u\n", t->filesIngested.load());
    fprintf(fp, "  Errors Caught:       %u\n", t->errorsCaught.load());
    fprintf(fp, "\n");
    
    fprintf(fp, "  Memory Fidelity:  0x%016llX\n", t->memoryFidelity.load());
    fprintf(fp, "  Fidelity Variance: %.4f%%\n", t->fidelityVariance.load() / 10000.0);
    fprintf(fp, "\n");
    
    uint64_t elapsed = GetTickCount64() - t->testStartTime;
    fprintf(fp, "  Test Duration:    %02llu:%02llu:%02llu\n",
            elapsed / 3600000, (elapsed % 3600000) / 60000, (elapsed % 60000) / 1000);
    fprintf(fp, "\n");
    
    fprintf(fp, "=================================================================\n");
    fprintf(fp, "  END OF CRASH DUMP\n");
    fprintf(fp, "=================================================================\n");
    
    fclose(fp);
}

// ============================================================================
// EXCEPTION FILTER — Top-level SEH handler
// ============================================================================

LONG WINAPI AgentExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo) {
    // Capture timestamp
    time_t now = time(nullptr);
    struct tm tm;
    localtime_s(&tm, &now);
    strftime(g_crashContext.timestamp, sizeof(g_crashContext.timestamp),
             "%Y%m%d_%H%M%S", &tm);
    
    // Capture exception info
    g_crashContext.exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    g_crashContext.exceptionAddress = 
        (ULONG_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress;
    
    // Capture CPU context
    if (ExceptionInfo->ContextRecord) {
        memcpy(&g_crashContext.cpuContext, ExceptionInfo->ContextRecord, 
               sizeof(CONTEXT));
    }
    
    // Capture telemetry snapshot
    memcpy(&g_crashContext.telemetrySnapshot, &g_telemetry, sizeof(g_telemetry));
    
    // Write dump
    WriteTelemetryDump(&g_crashContext);
    
    // Also write to stderr for immediate visibility
    fprintf(stderr, "\n");
    fprintf(stderr, "=================================================================\n");
    fprintf(stderr, "  AGENT STRESS TEST CRASH\n");
    fprintf(stderr, "  Exception: 0x%08X at 0x%p\n", 
            g_crashContext.exceptionCode, 
            (void*)g_crashContext.exceptionAddress);
    fprintf(stderr, "  Dump written to: %s\n", g_crashContext.dumpPath);
    fprintf(stderr, "=================================================================\n\n");
    
    // Call previous filter if exists
    if (g_prevFilter) {
        return g_prevFilter(ExceptionInfo);
    }
    
    // Default: terminate
    return EXCEPTION_EXECUTE_HANDLER;
}

// ============================================================================
// PUBLIC API
// ============================================================================

extern "C" {

__declspec(dllexport) void AgentExceptionHandler_Install() {
    // Install our filter, save previous
    g_prevFilter = SetUnhandledExceptionFilter(AgentExceptionFilter);
    
    // Also set up termination handler for clean shutdown
    // (not implemented here - would need atexit handler)
}

__declspec(dllexport) void AgentExceptionHandler_Uninstall() {
    // Restore previous filter
    SetUnhandledExceptionFilter(g_prevFilter);
    g_prevFilter = nullptr;
}

__declspec(dllexport) const char* AgentExceptionHandler_GetLastDumpPath() {
    return g_crashContext.dumpPath[0] ? g_crashContext.dumpPath : nullptr;
}

__declspec(dllexport) void AgentExceptionHandler_ForceDump() {
    // Manual dump trigger (for testing)
    __try {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, nullptr);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Handled by our filter
    }
}

} // extern "C"

// ============================================================================
// TEST MAIN (optional - build as exe to test)
// ============================================================================
#ifdef AGENT_EXCEPTION_HANDLER_TEST

int main(int argc, char** argv) {
    printf("Agent Exception Handler Test\n");
    printf("============================\n\n");
    
    // Install handler
    AgentExceptionHandler_Install();
    printf("Exception handler installed.\n");
    
    // Initialize telemetry
    Telemetry_Init();
    printf("Telemetry initialized.\n");
    
    // Simulate some activity
    for (int i = 0; i < 100; ++i) {
        Telemetry_ProposalGenerated();
        Telemetry_FileIngested();
    }
    printf("Simulated 100 proposals and files.\n");
    
    // Force a crash (if requested)
    if (argc > 1 && strcmp(argv[1], "--crash") == 0) {
        printf("Triggering access violation...\n");
        int* p = nullptr;
        *p = 42;  // Crash!
    }
    
    // Or force a dump
    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        printf("Triggering manual dump...\n");
        AgentExceptionHandler_ForceDump();
        printf("Dump written to: %s\n", AgentExceptionHandler_GetLastDumpPath());
    }
    
    printf("\nTest complete.\n");
    return 0;
}

#endif // AGENT_EXCEPTION_HANDLER_TEST
