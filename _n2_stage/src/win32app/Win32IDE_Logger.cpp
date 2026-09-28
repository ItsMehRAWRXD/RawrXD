// Win32IDE_Logger.cpp — IDE logger: OutputDebugString + optional file sink
#include <windows.h>
#include <string>
#include <cstdio>
#include <cstdarg>
#include <mutex>
#include <fstream>

namespace RawrXD::IDE {

static std::mutex   g_logMtx;
static std::ofstream g_logFile;
static bool         g_fileEnabled = false;

void Logger_Init(const std::string& path)
{
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (!path.empty()) {
        g_logFile.open(path, std::ios::app);
        g_fileEnabled = g_logFile.is_open();
    }
}

void Logger_Shutdown()
{
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_logFile.is_open()) g_logFile.close();
    g_fileEnabled = false;
}

void Logger_Log(const char* level, const char* fmt, ...)
{
    char buf[2048];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);

    char out[2176];
    snprintf(out, sizeof(out), "[RawrXD][%s] %s\n", level, buf);

    OutputDebugStringA(out);

    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_fileEnabled && g_logFile.is_open())
        g_logFile << out << std::flush;
}

void Logger_Info (const char* fmt, ...) { char b[2048]; va_list v; va_start(v,fmt); vsnprintf(b,sizeof(b),fmt,v); va_end(v); Logger_Log("INFO",  "%s", b); }
void Logger_Warn (const char* fmt, ...) { char b[2048]; va_list v; va_start(v,fmt); vsnprintf(b,sizeof(b),fmt,v); va_end(v); Logger_Log("WARN",  "%s", b); }
void Logger_Error(const char* fmt, ...) { char b[2048]; va_list v; va_start(v,fmt); vsnprintf(b,sizeof(b),fmt,v); va_end(v); Logger_Log("ERROR", "%s", b); }

} // namespace RawrXD::IDE
