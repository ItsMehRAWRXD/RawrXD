// Auto-generated GUI wiring implementation
// Generated: 2026-07-08 08:27:40

#include "Integration_Wiring.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>

namespace RawrXD {
namespace Integration {

bool BuildSystem::CompileFile(const wchar_t* sourceFile, const wchar_t* outputFile) {
    std::wstringstream cmd;
    cmd << L"\"" << COMPILER_PATH << L"\" \"" << sourceFile << L"\"";
    if (outputFile) {
        cmd << L" -o \"" << outputFile << L"\"";
    }
    
    // TODO: Show build output in IDE console panel
    // TODO: Update status bar with progress
    // TODO: Parse compiler output for error highlighting
    
    DWORD result = ProcessRunner::RunProcess(cmd.str().c_str(), nullptr);
    return (result == 0);
}

bool BuildSystem::AssembleFile(const wchar_t* sourceFile, const wchar_t* outputFile) {
    std::wstringstream cmd;
    cmd << L"\"" << ASSEMBLER_PATH << L"\" \"" << sourceFile << L"\" \"" << outputFile << L"\"";
    
    DWORD result = ProcessRunner::RunProcess(cmd.str().c_str(), nullptr);
    return (result == 0);
}

bool BuildSystem::LinkObject(const wchar_t* objectFile, const wchar_t* outputFile) {
    std::wstringstream cmd;
    cmd << L"\"" << LINKER_PATH << L"\" \"" << objectFile << L"\" /out:\"" << outputFile << L"\" /subsystem:3";
    
    DWORD result = ProcessRunner::RunProcess(cmd.str().c_str(), nullptr);
    return (result == 0);
}

bool BuildSystem::BuildProject(const wchar_t* projectFile) {
    // Parse .rxproj file (JSON format)
    std::ifstream file(projectFile);
    if (!file.is_open()) return false;
    
    std::string json((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();
    
    // Extract project directory
    std::wstring projPath = projectFile;
    size_t lastSlash = projPath.find_last_of(L"\\/");
    std::wstring projDir = (lastSlash != std::wstring::npos) ? 
                           projPath.substr(0, lastSlash) : L".";
    
    // Parse sources array from JSON
    std::vector<std::wstring> sources;
    size_t sourcesPos = json.find("\"sources\"");
    if (sourcesPos != std::string::npos) {
        size_t arrStart = json.find("[", sourcesPos);
        size_t arrEnd = json.find("]", arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string arr = json.substr(arrStart + 1, arrEnd - arrStart - 1);
            size_t pos = 0;
            while ((pos = arr.find("\"", pos)) != std::string::npos) {
                size_t end = arr.find("\"", pos + 1);
                if (end == std::string::npos) break;
                std::string src = arr.substr(pos + 1, end - pos - 1);
                sources.push_back(std::wstring(src.begin(), src.end()));
                pos = end + 1;
            }
        }
    }
    
    if (sources.empty()) return false;
    
    // Compile each source file
    std::vector<std::wstring> objectFiles;
    for (const auto& src : sources) {
        std::wstring sourcePath = projDir + L"\\" + src;
        std::wstring objFile = src;
        size_t dotPos = objFile.find_last_of(L".");
        if (dotPos != std::wstring::npos) objFile = objFile.substr(0, dotPos);
        objFile += L".obj";
        std::wstring objPath = projDir + L"\\" + objFile;
        
        if (!CompileFile(sourcePath.c_str(), objPath.c_str())) {
            return false;
        }
        objectFiles.push_back(objPath);
    }
    
    // Link all objects
    std::wstring outputFile = projDir + L"\\output.exe";
    if (!objectFiles.empty()) {
        // Link first object as main, others as additional
        return LinkObject(objectFiles[0].c_str(), outputFile.c_str());
    }
    
    return true;
}

bool BuildSystem::RunExecutable(const wchar_t* executable) {
    // TODO: Capture output to IDE console
    // TODO: Show exit code in status bar
    // TODO: Support debugging if requested
    
    DWORD result = ProcessRunner::RunProcess(executable, nullptr);
    return (result == 0);
}

bool BuildSystem::DebugExecutable(const wchar_t* executable) {
    // Start DAP server process
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    std::wstringstream cmd;
    cmd << L"\"" << executable << L"\" --dap-server";
    
    if (!CreateProcessW(nullptr, const_cast<wchar_t*>(cmd.str().c_str()),
                       nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                       nullptr, nullptr, &si, &pi)) {
        return false;
    }
    
    // Store process info for later control
    // In real implementation, this would connect to DAP server
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return true;
}

bool AnalysisTools::AnalyzePE(const wchar_t* executable) {
    std::wstringstream cmd;
    cmd << L"\"" << ANALYZER_PATH << L"\" \"" << executable << L"\"";
    
    DWORD result = ProcessRunner::RunProcess(cmd.str().c_str(), nullptr);
    return (result == 0);
}

bool AnalysisTools::FixImports(const wchar_t* executable) {
    // Call repair_imports.ps1 using PowerShell
    std::wstringstream cmd;
    cmd << L"powershell.exe -ExecutionPolicy Bypass -File \"" 
        << L"D:\\rawrxd\\native_toolchain\\repair_imports.ps1\" \"" 
        << executable << L"\"";
    
    DWORD result = ProcessRunner::RunProcess(cmd.str().c_str(), nullptr);
    return (result == 0);
}

bool AnalysisTools::PatchBinary(const wchar_t* executable, const wchar_t* patchFile) {
    std::wstringstream cmd;
    cmd << L"\"" << PATCHER_PATH << L"\" /patch \"" << executable << L"\" \"" << patchFile << L"\"";
    
    DWORD result = ProcessRunner::RunProcess(cmd.str().c_str(), nullptr);
    return (result == 0);
}

DWORD ProcessRunner::RunProcess(const wchar_t* executable, const wchar_t* args, bool wait) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    std::wstring cmdLine = executable;
    if (args) {
        cmdLine += L" ";
        cmdLine += args;
    }
    
    if (!CreateProcessW(nullptr, const_cast<wchar_t*>(cmdLine.c_str()), 
                       nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        return GetLastError();
    }
    
    if (wait) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return exitCode;
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

DWORD ProcessRunner::RunCompiler(const wchar_t* sourceFile) {
    return RunProcess(COMPILER_PATH, sourceFile);
}

DWORD ProcessRunner::RunWithOutput(const wchar_t* executable, std::wstring& output) {
    // Capture stdout/stderr to string using pipes
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    
    HANDLE hStdOutRead, hStdOutWrite;
    HANDLE hStdErrRead, hStdErrWrite;
    
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0) ||
        !CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0)) {
        return GetLastError();
    }
    
    // Ensure read handles are not inherited
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdErrWrite;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    
    PROCESS_INFORMATION pi = {};
    
    std::wstring cmdLine = executable;
    
    if (!CreateProcessW(nullptr, const_cast<wchar_t*>(cmdLine.c_str()),
                       nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hStdOutRead); CloseHandle(hStdOutWrite);
        CloseHandle(hStdErrRead); CloseHandle(hStdErrWrite);
        return GetLastError();
    }
    
    // Close write ends (child has them now)
    CloseHandle(hStdOutWrite);
    CloseHandle(hStdErrWrite);
    
    // Read output
    char buffer[4096];
    DWORD bytesRead;
    std::string result;
    
    // Read stdout
    while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer;
    }
    
    // Read stderr
    while (ReadFile(hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer;
    }
    
    // Convert to wstring
    output = std::wstring(result.begin(), result.end());
    
    // Cleanup
    CloseHandle(hStdOutRead);
    CloseHandle(hStdErrRead);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return exitCode;
}

} // namespace Integration
} // namespace RawrXD
