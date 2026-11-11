/*============================================================================
 * RAWRXD Compiler Driver Integration Implementation
 * Shared between GUI IDE and CLI IDE
 *============================================================================*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>
#include "compiler_integration.h"

/*============================================================================
 * Constants
 *============================================================================*/

#define RAWRXD_COMPILER_EXE "rawrxd-compiler.exe"
#define MAX_CMD_LENGTH 32768
#define DEFAULT_TIMEOUT_MS 60000

static const char* g_languageNames[] = {
    "C",
    "Assembly",
    "C#",
    "Unknown"
};

static const char* g_extensions[] = {
    ".c", ".h",           // C
    ".asm", ".s", ".nasm", // Assembly
    ".cs", ".csharp"      // C#
};

static const RawrxdLanguage g_extLanguages[] = {
    RAWRXD_LANG_C, RAWRXD_LANG_C,
    RAWRXD_LANG_ASSEMBLY, RAWRXD_LANG_ASSEMBLY, RAWRXD_LANG_ASSEMBLY,
    RAWRXD_LANG_CSHARP, RAWRXD_LANG_CSHARP
};

static char g_lastError[4096] = {0};
static char g_compilerPath[MAX_PATH] = {0};
static bool g_initialized = false;

/*============================================================================
 * Internal Helpers
 *============================================================================*/

static bool FindCompiler(void) {
    // Try relative path first (from IDE location)
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    char* lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        lastSlash = strrchr(exePath, '\\');
        if (lastSlash) {
            *lastSlash = '\0';
            // Try ../tools/compiler_driver/bin/
            snprintf(g_compilerPath, MAX_PATH, "%s\\tools\\compiler_driver\\bin\\%s", 
                     exePath, RAWRXD_COMPILER_EXE);
            if (GetFileAttributesA(g_compilerPath) != INVALID_FILE_ATTRIBUTES) {
                return true;
            }
        }
    }
    
    // Try PATH
    if (SearchPathA(NULL, RAWRXD_COMPILER_EXE, NULL, MAX_PATH, g_compilerPath, NULL)) {
        return true;
    }
    
    // Try common locations
    const char* commonPaths[] = {
        "C:\\Program Files\\RAWRXD\\bin\\rawrxd-compiler.exe",
        "C:\\Program Files (x86)\\RAWRXD\\bin\\rawrxd-compiler.exe",
        "C:\\RAWRXD\\bin\\rawrxd-compiler.exe",
        ".\\tools\\compiler_driver\\bin\\rawrxd-compiler.exe",
        ".\\bin\\rawrxd-compiler.exe"
    };
    
    for (int i = 0; i < sizeof(commonPaths)/sizeof(commonPaths[0]); i++) {
        if (GetFileAttributesA(commonPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            strncpy(g_compilerPath, commonPaths[i], MAX_PATH-1);
            return true;
        }
    }
    
    return false;
}

static bool ExecuteCommand(const char* cmd, char* output, size_t outputSize, 
                          int* exitCode, DWORD timeoutMs) {
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead, hWrite;
    
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        strncpy(g_lastError, "Failed to create pipe", sizeof(g_lastError)-1);
        return false;
    }
    
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOA si = {sizeof(si)};
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi = {0};
    
    char cmdCopy[MAX_CMD_LENGTH];
    strncpy(cmdCopy, cmd, MAX_CMD_LENGTH-1);
    cmdCopy[MAX_CMD_LENGTH-1] = '\0';
    
    if (!CreateProcessA(NULL, cmdCopy, NULL, NULL, TRUE, 
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        snprintf(g_lastError, sizeof(g_lastError), "Failed to create process: %lu", GetLastError());
        return false;
    }
    
    CloseHandle(hWrite);
    
    // Read output
    DWORD totalRead = 0;
    DWORD bytesRead;
    char buffer[4096];
    
    while (totalRead < outputSize - 1) {
        if (!ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) || bytesRead == 0) {
            break;
        }
        buffer[bytesRead] = '\0';
        size_t toCopy = bytesRead;
        if (totalRead + toCopy > outputSize - 1) {
            toCopy = outputSize - 1 - totalRead;
        }
        memcpy(output + totalRead, buffer, toCopy);
        totalRead += toCopy;
    }
    output[totalRead] = '\0';
    
    CloseHandle(hRead);
    
    // Wait for process
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        *exitCode = -1;
        strncpy(g_lastError, "Process timed out", sizeof(g_lastError)-1);
    } else {
        DWORD ec;
        GetExitCodeProcess(pi.hProcess, &ec);
        *exitCode = (int)ec;
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return waitResult != WAIT_TIMEOUT;
}

/*============================================================================
 * Public API Implementation
 *============================================================================*/

bool RawrxdCompiler_Init(void) {
    if (g_initialized) {
        return true;
    }
    
    if (!FindCompiler()) {
        strncpy(g_lastError, "RAWRXD compiler not found. Please install or add to PATH.", 
                sizeof(g_lastError)-1);
        return false;
    }
    
    g_initialized = true;
    return true;
}

void RawrxdCompiler_Shutdown(void) {
    g_initialized = false;
    g_compilerPath[0] = '\0';
    g_lastError[0] = '\0';
}

RawrxdLanguage RawrxdCompiler_DetectLanguage(const char* filePath) {
    const char* ext = strrchr(filePath, '.');
    if (!ext) {
        return RAWRXD_LANG_UNKNOWN;
    }
    
    for (int i = 0; i < sizeof(g_extensions)/sizeof(g_extensions[0]); i++) {
        if (_stricmp(ext, g_extensions[i]) == 0) {
            return g_extLanguages[i];
        }
    }
    
    return RAWRXD_LANG_UNKNOWN;
}

RawrxdCompileResult RawrxdCompiler_Compile(const char* sourcePath, const RawrxdBuildConfig* config) {
    RawrxdCompileResult result = {0};
    result.success = false;
    result.exitCode = -1;
    
    if (!g_initialized && !RawrxdCompiler_Init()) {
        strncpy(result.error, g_lastError, sizeof(result.error)-1);
        return result;
    }
    
    // Build command
    char cmd[MAX_CMD_LENGTH];
    snprintf(cmd, sizeof(cmd), "\"%s\" compile \"%s\"", g_compilerPath, sourcePath);
    
    // Add options
    if (config) {
        if (config->optimize) {
            strncat(cmd, " -O", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->debug) {
            strncat(cmd, " -g", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->verbose) {
            strncat(cmd, " -v", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->outputName[0]) {
            strncat(cmd, " -o \"", sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, config->outputName, sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, "\"", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->includePaths[0]) {
            strncat(cmd, " -I \"", sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, config->includePaths, sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, "\"", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->defines[0]) {
            strncat(cmd, " -D \"", sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, config->defines, sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, "\"", sizeof(cmd)-strlen(cmd)-1);
        }
    }
    
    // Execute
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    bool ok = ExecuteCommand(cmd, result.output, sizeof(result.output), 
                            &result.exitCode, DEFAULT_TIMEOUT_MS);
    
    QueryPerformanceCounter(&end);
    result.compileTimeMs = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    
    if (!ok) {
        strncpy(result.error, g_lastError, sizeof(result.error)-1);
        return result;
    }
    
    result.success = (result.exitCode == 0);
    
    // Determine output path
    if (config && config->outputName[0]) {
        strncpy(result.outputPath, config->outputName, sizeof(result.outputPath)-1);
    } else {
        // Default output name
        char outPath[MAX_PATH];
        strncpy(outPath, sourcePath, MAX_PATH-1);
        char* ext = strrchr(outPath, '.');
        if (ext) {
            *ext = '\0';
        }
        strncat(outPath, ".exe", MAX_PATH-strlen(outPath)-1);
        strncpy(result.outputPath, outPath, sizeof(result.outputPath)-1);
    }
    
    return result;
}

RawrxdCompileResult RawrxdCompiler_Build(const char** sourcePaths, int count, const RawrxdBuildConfig* config) {
    RawrxdCompileResult result = {0};
    result.success = false;
    result.exitCode = -1;
    
    if (!g_initialized && !RawrxdCompiler_Init()) {
        strncpy(result.error, g_lastError, sizeof(result.error)-1);
        return result;
    }
    
    // Build command with multiple files
    char cmd[MAX_CMD_LENGTH];
    snprintf(cmd, sizeof(cmd), "\"%s\" build", g_compilerPath);
    
    for (int i = 0; i < count && strlen(cmd) < MAX_CMD_LENGTH - MAX_PATH - 10; i++) {
        strncat(cmd, " \"", sizeof(cmd)-strlen(cmd)-1);
        strncat(cmd, sourcePaths[i], sizeof(cmd)-strlen(cmd)-1);
        strncat(cmd, "\"", sizeof(cmd)-strlen(cmd)-1);
    }
    
    // Add options
    if (config) {
        if (config->optimize) {
            strncat(cmd, " -O", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->debug) {
            strncat(cmd, " -g", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->verbose) {
            strncat(cmd, " -v", sizeof(cmd)-strlen(cmd)-1);
        }
        if (config->outputName[0]) {
            strncat(cmd, " -o \"", sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, config->outputName, sizeof(cmd)-strlen(cmd)-1);
            strncat(cmd, "\"", sizeof(cmd)-strlen(cmd)-1);
        }
    }
    
    // Execute
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    bool ok = ExecuteCommand(cmd, result.output, sizeof(result.output), 
                            &result.exitCode, DEFAULT_TIMEOUT_MS * count);
    
    QueryPerformanceCounter(&end);
    result.compileTimeMs = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    
    if (!ok) {
        strncpy(result.error, g_lastError, sizeof(result.error)-1);
        return result;
    }
    
    result.success = (result.exitCode == 0);
    
    if (config && config->outputName[0]) {
        strncpy(result.outputPath, config->outputName, sizeof(result.outputPath)-1);
    }
    
    return result;
}

bool RawrxdCompiler_Clean(const char* projectPath) {
    if (!g_initialized && !RawrxdCompiler_Init()) {
        return false;
    }
    
    char cmd[MAX_CMD_LENGTH];
    snprintf(cmd, sizeof(cmd), "\"%s\" clean \"%s\"", g_compilerPath, projectPath);
    
    int exitCode;
    char output[4096];
    return ExecuteCommand(cmd, output, sizeof(output), &exitCode, DEFAULT_TIMEOUT_MS);
}

const char* RawrxdCompiler_GetVersion(void) {
    if (!g_initialized && !RawrxdCompiler_Init()) {
        return "unknown";
    }
    
    static char version[256] = {0};
    if (version[0]) {
        return version;
    }
    
    char cmd[MAX_CMD_LENGTH];
    snprintf(cmd, sizeof(cmd), "\"%s\" --version", g_compilerPath);
    
    int exitCode;
    if (ExecuteCommand(cmd, version, sizeof(version), &exitCode, 5000)) {
        // Trim whitespace
        char* end = version + strlen(version) - 1;
        while (end > version && (*end == '\n' || *end == '\r' || *end == ' ')) {
            *end-- = '\0';
        }
        return version;
    }
    
    return "unknown";
}

bool RawrxdCompiler_IsAvailable(void) {
    return RawrxdCompiler_Init();
}

const char* RawrxdCompiler_GetLastError(void) {
    return g_lastError;
}

const char* RawrxdCompiler_LanguageName(RawrxdLanguage lang) {
    if (lang >= 0 && lang <= RAWRXD_LANG_UNKNOWN) {
        return g_languageNames[lang];
    }
    return "Unknown";
}

bool RawrxdCompiler_IsCompilable(const char* filePath) {
    return RawrxdCompiler_DetectLanguage(filePath) != RAWRXD_LANG_UNKNOWN;
}

const char** RawrxdCompiler_GetExtensions(int* count) {
    *count = sizeof(g_extensions) / sizeof(g_extensions[0]);
    return g_extensions;
}

void RawrxdCompiler_FormatError(const RawrxdCompileResult* result, char* buffer, size_t bufferSize) {
    if (result->success) {
        snprintf(buffer, bufferSize, "Compilation successful (%.2f ms)", result->compileTimeMs);
    } else {
        snprintf(buffer, bufferSize, "Compilation failed (exit code %d): %s", 
                 result->exitCode, result->error[0] ? result->error : result->output);
    }
}

RawrxdCompileResult RawrxdCompiler_CompileWithProgress(
    const char* sourcePath,
    const RawrxdBuildConfig* config,
    RawrxdCompileProgressCallback callback,
    void* userData) {
    
    if (callback) {
        callback(sourcePath, 1, 1, userData);
    }
    
    return RawrxdCompiler_Compile(sourcePath, config);
}

int RawrxdCompiler_ParseErrors(
    const char* compilerOutput,
    char* errorFile,
    int* errorLine,
    char* errorMessage,
    size_t messageSize) {
    
    // Simple parser - look for common error patterns
    const char* patterns[] = {
        ": error ",
        ": warning ",
        "error:",
        "Error:"
    };
    
    for (int i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        const char* found = strstr(compilerOutput, patterns[i]);
        if (found) {
            // Try to extract file and line
            const char* colon = found;
            while (colon > compilerOutput && *colon != ':') colon--;
            if (colon > compilerOutput) {
                const char* prevColon = colon - 1;
                while (prevColon > compilerOutput && *prevColon != ':') prevColon--;
                
                if (prevColon > compilerOutput) {
                    size_t fileLen = colon - prevColon - 1;
                    if (fileLen < MAX_PATH) {
                        memcpy(errorFile, prevColon + 1, fileLen);
                        errorFile[fileLen] = '\0';
                    }
                    
                    char lineStr[16];
                    size_t lineLen = found - colon - 1;
                    if (lineLen < sizeof(lineStr)) {
                        memcpy(lineStr, colon + 1, lineLen);
                        lineStr[lineLen] = '\0';
                        *errorLine = atoi(lineStr);
                    }
                }
            }
            
            // Extract message
            const char* msgStart = found + strlen(patterns[i]);
            while (*msgStart == ' ' || *msgStart == ':') msgStart++;
            
            const char* msgEnd = strchr(msgStart, '\n');
            if (!msgEnd) msgEnd = msgStart + strlen(msgStart);
            
            size_t msgLen = msgEnd - msgStart;
            if (msgLen >= messageSize) msgLen = messageSize - 1;
            memcpy(errorMessage, msgStart, msgLen);
            errorMessage[msgLen] = '\0';
            
            return (i < 2) ? 1 : 2; // 1 = error, 2 = warning
        }
    }
    
    return 0; // No error found
}

void RawrxdCompiler_GetDefaultConfig(RawrxdBuildConfig* config, const char* projectPath) {
    memset(config, 0, sizeof(RawrxdBuildConfig));
    config->optimize = true;
    config->debug = false;
    config->verbose = false;
}
