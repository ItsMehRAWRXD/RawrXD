// ============================================================================
// native_log_stub.cpp - Stub implementation for RawrXD_Native_Log
// ============================================================================

#include <windows.h>
#include <cstdarg>
#include <cstdio>

extern "C" {

void RawrXD_Native_Log(const char* level, const char* format, ...) {
    (void)level;
    
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    OutputDebugStringA("[RawrXD_Native_Log] ");
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");
}

} // extern "C"
