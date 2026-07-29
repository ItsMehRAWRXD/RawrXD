/**
 * @file hot_reload.cpp
 * @brief Hot-reload module rebuild via subprocess (Qt-free, Win32/POSIX)
 */
#include "hot_reload.hpp"
<<<<<<< HEAD
#include <cstdio>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace {

int runProcess(const std::string& cmdLine) {
#ifdef _WIN32
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);

    PROCESS_INFORMATION pi{};
    std::string cmd = cmdLine;
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr,
                        TRUE, 0, nullptr, nullptr, &si, &pi)) {
        fprintf(stderr, "[WARN] [HotReload] CreateProcess failed: %lu\n", GetLastError());
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 60000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exitCode);
#else
    int rc = std::system(cmdLine.c_str());
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
#endif
}

} // namespace

HotReload::HotReload() {}

bool HotReload::reloadQuant(const std::string& quantType) {
    fprintf(stderr, "[INFO] [HotReload] Hot-reloading quantization: %s\n", quantType.c_str());

    std::string cmd = "cmake --build build --config Release --target quant_ladder_avx2";
    int rc = runProcess(cmd);
    if (rc != 0) {
        std::string err = "Build failed for quant_ladder_avx2 (exit " + std::to_string(rc) + ")";
        fprintf(stderr, "[WARN] [HotReload] %s\n", err.c_str());
        if (onReloadFailed) onReloadFailed(err);
        return false;
    }

    fprintf(stderr, "[INFO] [HotReload] Quant library rebuilt successfully\n");
    if (onQuantReloaded) onQuantReloaded(quantType);
=======
#include <windows.h>
#include <string>
#include <vector>
#include <iostream>

HotReload::HotReload() {}

static bool runBuild(const std::string& target, int timeoutMs) {
    std::string cmd = "cmake --build build --config Release --target " + target;
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    char* cmdLine = _strdup(cmd.c_str());
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        free(cmdLine);
        return false;
    }
    free(cmdLine);
    
    DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return exitCode == 0;
}

bool HotReload::reloadQuant(const std::string& quantType) {


    // Step 1: Rebuild only the quant library
    if (!runBuild("quant_ladder_avx2", 30000)) {
        if (onReloadFailed) onReloadFailed("Build failed or timed out for quant_ladder_avx2");
        return false;
    }


    // Step 2: Signal upper layer
    if (onQuantReloaded) onQuantReloaded(quantType);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

bool HotReload::reloadModule(const std::string& moduleName) {
<<<<<<< HEAD
    fprintf(stderr, "[INFO] [HotReload] Hot-reloading module: %s\n", moduleName.c_str());

    std::string cmd = "cmake --build build --config Release --target " + moduleName;
    int rc = runProcess(cmd);
    if (rc != 0) {
        std::string err = "Build failed for " + moduleName + " (exit " + std::to_string(rc) + ")";
        fprintf(stderr, "[WARN] [HotReload] %s\n", err.c_str());
        if (onReloadFailed) onReloadFailed(err);
        return false;
    }

    fprintf(stderr, "[INFO] [HotReload] Module rebuilt: %s\n", moduleName.c_str());
    if (onModuleReloaded) onModuleReloaded(moduleName);
=======


    // Build specific target
    if (!runBuild(moduleName, 60000)) {
        if (onReloadFailed) onReloadFailed("Build failed or timed out for " + moduleName);
        return false;
    }
    
    if (onModuleReloaded) onModuleReloaded(moduleName);
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}
