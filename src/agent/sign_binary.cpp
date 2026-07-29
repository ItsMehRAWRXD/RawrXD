<<<<<<< HEAD
/**
 * @file sign_binary.cpp
 * @brief Binary signing – Qt-free (C++20 / Win32)
 *
 * Signs an executable using signtool.exe (Windows SDK).
 * Falls back to no-op if signtool or certificate not available.
 */

#include "sign_binary.hpp"
#include "process_utils.hpp"
#include <cstdio>
#include <filesystem>

namespace fs = std::filesystem;

bool signBinary(const std::string& exePath) {
    if (!fs::exists(exePath)) {
        fprintf(stderr, "[SignBinary] File not found: %s\n", exePath.c_str());
        return false;
    }

    // Resolve certificate from environment
    std::string certFile    = getEnvVar("RAWRXD_SIGN_CERT");
    std::string certPass    = getEnvVar("RAWRXD_SIGN_PASS");
    std::string timestampUrl = getEnvVar("RAWRXD_SIGN_TIMESTAMP",
                                          "http://timestamp.digicert.com");

    // If no cert configured, check for a certificate thumbprint (Azure-style)
    std::string thumbprint = getEnvVar("RAWRXD_SIGN_THUMBPRINT");

    if (certFile.empty() && thumbprint.empty()) {
        fprintf(stderr, "[SignBinary] No signing certificate configured "
                "(set RAWRXD_SIGN_CERT or RAWRXD_SIGN_THUMBPRINT)\n");
        fprintf(stderr, "[SignBinary] Skipping signing for: %s\n", exePath.c_str());
        return true; // Not an error in dev
    }

    // Try to find signtool.exe
    std::string signtool = getEnvVar("RAWRXD_SIGNTOOL", "signtool.exe");

    // Build signtool command
    std::vector<std::string> args;
    args.push_back("sign");
    args.push_back("/fd");
    args.push_back("SHA256");

    if (!thumbprint.empty()) {
        // Certificate store signing (thumbprint)
        args.push_back("/sha1");
        args.push_back(thumbprint);
        args.push_back("/s");
        args.push_back("My");
    } else {
        // PFX file signing
        args.push_back("/f");
        args.push_back(certFile);
        if (!certPass.empty()) {
            args.push_back("/p");
            args.push_back(certPass);
        }
    }

    // Timestamp
    args.push_back("/tr");
    args.push_back(timestampUrl);
    args.push_back("/td");
    args.push_back("SHA256");

    // Target binary
    args.push_back(exePath);

    ProcResult pr = proc::run(signtool, args, 60000);

    if (!pr.ok()) {
        fprintf(stderr, "[SignBinary] signtool failed (exit=%d):\n%s\n%s\n",
                pr.exitCode, pr.stdoutStr.c_str(), pr.stderrStr.c_str());
        return false;
    }

    fprintf(stderr, "[SignBinary] Successfully signed: %s\n", exePath.c_str());
    return true;
=======
#include "sign_binary.hpp"
#include <vector>
#include <algorithm>
#include <string>
#include <windows.h>
#include <iostream>

static std::string getEnvVar(const std::string& name) {
    char* val = nullptr;
    size_t len = 0;
    if (_dupenv_s(&val, &len, name.c_str()) == 0 && val) {
        std::string s(val);
        free(val);
        return s;
    }
    return "";
}

bool signBinary(const std::string& exePath) {
    std::string signtool = getEnvVar("SIGNTOOL_PATH");
    if (signtool.empty()) signtool = "signtool.exe";
    
    std::string cert = getEnvVar("CERT_PATH");
    std::string pass = getEnvVar("CERT_PASS");
    
    // If cert not configured, skip assume success (dev mode)
    if (cert.empty() || pass.empty()) {
        return true;
    }
    
    std::string commandLine = "\"" + signtool + "\" sign /f \"" + cert + "\" /p \"" + pass + "\" " +
                              "/fd sha256 /tr http://timestamp.digicert.com /td sha256 \"" + exePath + "\"";

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    char* cmd = _strdup(commandLine.c_str());
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        free(cmd);
        std::cerr << "Failed to run signtool" << std::endl;
        return false;
    }
    free(cmd);

    DWORD waitResult = WaitForSingleObject(pi.hProcess, 60000); // 60s timeout
    bool success = false;
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        std::cerr << "Signtool timed out" << std::endl;
    } else {
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        success = (exitCode == 0);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return success;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
