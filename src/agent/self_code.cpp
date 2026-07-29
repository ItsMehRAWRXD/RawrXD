#include "self_code.hpp"
<<<<<<< HEAD
#include "process_utils.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

bool SelfCode::editSource(const std::string& filePath,
                          const std::string& oldSnippet,
                          const std::string& newSnippet) {
    std::string content = fileutil::readAll(filePath);
=======
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <vector>
#include <windows.h>

namespace fs = std::filesystem;

// Helper cleanup
static std::string readFileContent(const std::string& path) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool writeFileContent(const std::string& path, const std::string& content) {
    std::ofstream f(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << content;
    return true;
}

bool SelfCode::runProcess(const std::string& cmd, const std::vector<std::string>& args) {
    std::string commandLine = cmd;
    for (const auto& arg : args) {
        commandLine += " \"" + arg + "\"";
    }
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    
    char* cmdLine = _strdup(commandLine.c_str());
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        free(cmdLine);
        return false;
    }
    free(cmdLine);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (exitCode == 0);
}

// --------------------------------------------------------------------------

bool SelfCode::editSource(const std::string& filePath,
                          const std::string& oldSnippet,
                          const std::string& newSnippet) {
    std::string content = readFileContent(filePath);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    if (content.empty()) {
        m_lastError = "Cannot read " + filePath;
        return false;
    }

<<<<<<< HEAD
    if (content.find(oldSnippet) == std::string::npos) {
=======
    size_t pos = content.find(oldSnippet);
    if (pos == std::string::npos) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        m_lastError = "Old snippet not found in " + filePath;
        return false;
    }

    if (!replaceInFile(filePath, oldSnippet, newSnippet))
        return false;

<<<<<<< HEAD
=======
    // No MOC regeneration needed as we are moving away from Qt
    
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

bool SelfCode::addInclude(const std::string& hppFile,
                          const std::string& includeLine) {
<<<<<<< HEAD
    if (includeLine.rfind("#include", 0) != 0)
        return false;

    std::string content = fileutil::readAll(hppFile);
=======
    if (includeLine.find("#include") != 0)
        return false;

    std::string content = readFileContent(hppFile);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    if (content.empty()) {
        m_lastError = "Cannot read " + hppFile;
        return false;
    }

    if (content.find(includeLine) != std::string::npos)
        return true;

<<<<<<< HEAD
    // Find last #include
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    size_t lastInclude = content.rfind("#include");
    if (lastInclude == std::string::npos) {
        return insertAfterIncludeGuard(hppFile, includeLine);
    }
<<<<<<< HEAD
    size_t insertPos = content.find('\n', lastInclude);
    if (insertPos == std::string::npos)
        insertPos = content.size();
    else
        insertPos += 1;

    std::string newContent = content.substr(0, insertPos)
                           + includeLine + "\n"
                           + content.substr(insertPos);
    return fileutil::writeAll(hppFile, newContent);
}

bool SelfCode::regenerateMOC(const std::string& /*header*/) {
    // MOC is a Qt concept — no longer needed in non-Qt build
    return true;
}

bool SelfCode::rebuildTarget(const std::string& target,
                             const std::string& config) {
    ProcResult pr = proc::run("cmake",
        {"--build", "build", "--config", config, "--target", target},
        120000);

    if (!pr.ok()) {
        m_lastError = "cmake build failed: " + pr.stderrStr;
        return false;
    }

    std::filesystem::path exe = std::filesystem::current_path() / "build" / "bin" / config / "RawrXD-Shell.exe";
    std::error_code ec;
    if (!std::filesystem::exists(exe, ec) || std::filesystem::file_size(exe, ec) == 0) {
        m_lastError = "Binary not produced or zero size";
        return false;
=======
    
    size_t insertPos = content.find('\n', lastInclude);
    if (insertPos == std::string::npos)
        insertPos = content.length();
    else
        insertPos += 1;

    std::string newContent = content.substr(0, insertPos) 
                           + includeLine + "\n" 
                           + content.substr(insertPos);
    
    return replaceInFile(hppFile, content, newContent);
}

bool SelfCode::regenerateMOC(const std::string& header) {
    // Deprecated / No-op
    return true;
}

bool SelfCode::createFile(const std::string& filePath,
                          const std::string& content) {
    if (fs::exists(filePath)) {
        m_lastError = "File already exists: " + filePath;
        return false;
    }
    // Ensure directory exists
    try {
        fs::path p(filePath);
        if (p.has_parent_path()) {
            fs::create_directories(p.parent_path());
        }
    } catch (const fs::filesystem_error& e) {
        m_lastError = "Could not create directory for " + filePath + ": " + e.what();
        return false;
    }
    
    return writeFileContent(filePath, content);
}

bool SelfCode::rebuildTarget(const std::string& target,
                             const std::string& config) {
    // "cmake --build build --config <config> --target <target>"
    std::vector<std::string> args = {"--build", "build", "--config", config, "--target", target};
    if (!runProcess("cmake", args)) {
        m_lastError = "CMake build failed for target: " + target;
        return false;
    }

    // Skip verification for meta-targets
    if (target == "ALL_BUILD" || target == "ZERO_CHECK" || target == "install") {
        return true;
    }

    // Verify binary exists
    // Common output paths for CMake on Windows
    std::vector<std::string> potentialPaths = {
        "build/" + config + "/" + target + ".exe",
        "build/bin/" + config + "/" + target + ".exe",
        "build/" + target + ".exe",
        "build/bin/" + target + ".exe"
    };

    for (const auto& p : potentialPaths) {
        if (fs::exists(p)) return true;
    }

    // Recursive search fallback
    if (fs::exists("build")) {
        try {
            for (const auto& entry : fs::recursive_directory_iterator("build")) {
                if (entry.is_regular_file() && entry.path().extension() == ".exe") {
                    // Check if stem matches target (case-insensitive on Windows usually, but let's do sensitive for now or relaxed)
                    if (entry.path().stem().string() == target) {
                        return true;
                    }
                }
            }
        } catch (...) {
            // Identifier permission errors or other FS issues
        }
    }

    m_lastError = "Build successful but binary not found for target: " + target;
    return false;
}

bool SelfCode::replaceInFile(const std::string& path,
                             const std::string& oldText,
                             const std::string& newText) {
    // Note: oldText and newText here are likely the *whole file content* 
    // or *snippets* depending on caller.
    // In editSource, it calls replaceInFile(path, oldSnippet, newSnippet).
    // In addInclude, it calls replaceInFile(path, oldContent, newContent).
    
    // The original logic for replaceInFile likely handled the actual writing.
    // If oldText == content (full replacement), we just write.
    // If oldText is a snippet, we finding-replace.
    
    std::string content = readFileContent(path);
    if (content == oldText) {
        // Full replacement
        return writeFileContent(path, newText);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    
    // Snippet replacement
    size_t pos = content.find(oldText);
    if (pos != std::string::npos) {
        content.replace(pos, oldText.length(), newText);
        return writeFileContent(path, content);
    }
    
    m_lastError = "Could not locate text to replace";
    return false;
}

<<<<<<< HEAD
bool SelfCode::replaceInFile(const std::string& path,
                             const std::string& oldText,
                             const std::string& newText) {
    std::string content = fileutil::readAll(path);
    if (content.empty()) {
        m_lastError = "Cannot read " + path;
        return false;
    }

    size_t idx = content.find(oldText);
    if (idx == std::string::npos) {
        m_lastError = "Old text not found (exact match required)";
        return false;
    }
    content.replace(idx, oldText.length(), newText);
    if (!fileutil::writeAll(path, content)) {
        m_lastError = "Failed to write " + path;
        return false;
    }
    return true;
}

bool SelfCode::insertAfterIncludeGuard(const std::string& hpp,
                                       const std::string& includeLine) {
    std::string content = fileutil::readAll(hpp);
    if (content.empty()) {
        m_lastError = "Cannot read " + hpp;
        return false;
    }

    size_t pos = 0;
    if (content.rfind("#pragma once", 0) == 0) {
        pos = content.find('\n');
        if (pos != std::string::npos) pos += 1;
    } else {
        size_t ifndef = content.find("#ifndef");
        if (ifndef != std::string::npos) {
            size_t define = content.find("#define", ifndef);
            if (define != std::string::npos) {
                pos = content.find('\n', define);
                if (pos != std::string::npos) pos += 1;
            }
        }
    }
    if (pos == std::string::npos) pos = 0;

    std::string newContent = content.substr(0, pos)
                           + includeLine + "\n"
                           + content.substr(pos);
    return fileutil::writeAll(hpp, newContent);
}

bool SelfCode::runProcess(const std::string& program,
                          const std::vector<std::string>& args) {
    ProcResult pr = proc::run(program, args, 120000);
    if (pr.timedOut) {
        m_lastError = program + " timed out";
        return false;
    }
    if (pr.exitCode != 0) {
        m_lastError = program + " failed: " + pr.stderrStr;
        return false;
    }
    return true;
=======
bool SelfCode::insertAfterIncludeGuard(const std::string& path, const std::string& code) {
    std::string content = readFileContent(path);
    // Look for #pragma once
    size_t pos = content.find("#pragma once");
    if (pos != std::string::npos) {
        size_t endLine = content.find('\n', pos);
        if (endLine == std::string::npos) endLine = content.length();
        else endLine += 1;
        
        std::string newContent = content.substr(0, endLine) + code + "\n" + content.substr(endLine);
        return writeFileContent(path, newContent);
    }
    // Fallback: prepend
    std::string newContent = code + "\n" + content;
    return writeFileContent(path, newContent);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}
