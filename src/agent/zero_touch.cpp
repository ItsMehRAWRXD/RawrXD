// zero_touch.cpp – Qt-free ZeroTouch implementation (C++20 / Win32)
// Provides automated dev-environment bootstrapping: file watchers, git hooks, voice triggers
#include "zero_touch.hpp"
<<<<<<< HEAD

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void zt_log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[ZeroTouch] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static bool writeTextFile(const fs::path& path, const std::string& content) {
    std::ofstream ofs(path, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) return false;
    ofs << content;
    return ofs.good();
}

// ---------------------------------------------------------------------------
// ZeroTouch
// ---------------------------------------------------------------------------

ZeroTouch::ZeroTouch() = default;

void ZeroTouch::installAll() {
    zt_log("Installing all zero-touch components...");
    installFileWatcher();
    installGitHook();
    installVoiceTrigger();
    zt_log("All zero-touch components installed.");
=======
#include "auto_bootstrap.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <algorithm>
#include <map>

namespace fs = std::filesystem;

ZeroTouch::ZeroTouch() : m_running(false) {}

void ZeroTouch::installAll() {
    installGitHook();
    
    // File watcher and voice trigger need a running loop or thread. 
    // Since this is called from installAll which seemed synchronous, 
    // but the original used QFileSystemWatcher (async) and void* (async event loop).
    // We should probably spawn threads for these.
    
    std::thread([this]() { installFileWatcher(); }).detach();
    std::thread([this]() { installVoiceTrigger(); }).detach();


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ---------------------------------------------------------------------------
// File watcher – creates a .vscode/settings.json entry for watcherExclude
// (actual directory monitoring is handled by the Win32IDE / HeadlessIDE loop)
// ---------------------------------------------------------------------------
void ZeroTouch::installFileWatcher() {
<<<<<<< HEAD
    zt_log("Installing file watcher configuration...");

    fs::path vscodePath = fs::current_path() / ".vscode";
    std::error_code ec;
    fs::create_directories(vscodePath, ec);
    if (ec) {
        zt_log("  WARNING: Could not create .vscode directory: %s", ec.message().c_str());
        return;
    }

    fs::path settingsPath = vscodePath / "settings.json";
    if (fs::exists(settingsPath)) {
        zt_log("  .vscode/settings.json already exists – skipping watcher config.");
        return;
    }

    const char* defaultSettings =
        "{\n"
        "  \"files.watcherExclude\": {\n"
        "    \"**/build/**\": true,\n"
        "    \"**/.git/objects/**\": true,\n"
        "    \"**/node_modules/**\": true\n"
        "  }\n"
        "}\n";

    if (writeTextFile(settingsPath, defaultSettings)) {
        zt_log("  Created %s", settingsPath.string().c_str());
    } else {
        zt_log("  WARNING: Failed to write %s", settingsPath.string().c_str());
    }
=======
    fs::path srcRoot = fs::current_path() / "src";
    if (!fs::exists(srcRoot)) {
        
        return;
    }

    // Simple polling watcher since we can't use QFileSystemWatcher and don't want complex ReadDirectoryChangesW loop here immediately
    std::map<std::string, fs::file_time_type> lastWriteTimes;
    
    for (const auto& entry : fs::recursive_directory_iterator(srcRoot)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".cpp" || ext == ".hpp") {
                lastWriteTimes[entry.path().string()] = fs::last_write_time(entry);
            }
        }
    }
    
    m_running = true;
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        for (const auto& entry : fs::recursive_directory_iterator(srcRoot)) {
            if (entry.is_regular_file()) {
                std::string path = entry.path().string();
                std::string ext = entry.path().extension().string();
                if (ext != ".cpp" && ext != ".hpp") continue;

                auto currentStr = fs::last_write_time(entry);
                if (lastWriteTimes.find(path) == lastWriteTimes.end()) {
                    lastWriteTimes[path] = currentStr;
                    // New file
                } else {
                    if (lastWriteTimes[path] != currentStr) {
                        lastWriteTimes[path] = currentStr;
                        // Changed


                        // Debounce/wait a bit? 
                        // Original had 5s delay.
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        
                        std::string wish = "Auto-fix and ship after source change in " + entry.path().filename().string();
                        _putenv_s("RAWRXD_AUTO_APPROVE", "1");
                        AutoBootstrap::startWithWish(wish);
                    }
                }
            }
        }
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

// ---------------------------------------------------------------------------
// Git hook – installs a pre-commit hook that runs self_test_gate
// ---------------------------------------------------------------------------
void ZeroTouch::installGitHook() {
<<<<<<< HEAD
    zt_log("Installing git pre-commit hook...");

    fs::path gitHooksDir = fs::current_path() / ".git" / "hooks";
    if (!fs::is_directory(gitHooksDir)) {
        zt_log("  No .git/hooks directory found – not a git repo? Skipping.");
        return;
    }

    fs::path hookPath = gitHooksDir / "pre-commit";
    if (fs::exists(hookPath)) {
        // Check if it's ours
        std::ifstream existing(hookPath);
        std::string firstLine;
        if (std::getline(existing, firstLine) && firstLine.find("RawrXD") != std::string::npos) {
            zt_log("  RawrXD pre-commit hook already installed – skipping.");
            return;
        }
        zt_log("  WARNING: pre-commit hook already exists (third-party) – not overwriting.");
        return;
    }

    const char* hookScript =
        "#!/bin/sh\n"
        "# RawrXD auto-installed pre-commit hook\n"
        "# Runs the self-test gate before allowing commits\n"
        "echo \"[RawrXD] Running self-test gate...\"\n"
        "if command -v ./build/self_test_gate >/dev/null 2>&1; then\n"
        "  ./build/self_test_gate\n"
        "  exit $?\n"
        "elif command -v ./build/Release/self_test_gate.exe >/dev/null 2>&1; then\n"
        "  ./build/Release/self_test_gate.exe\n"
        "  exit $?\n"
        "else\n"
        "  echo \"[RawrXD] self_test_gate not found – skipping.\"\n"
        "  exit 0\n"
        "fi\n";

    if (writeTextFile(hookPath, hookScript)) {
        zt_log("  Installed pre-commit hook at %s", hookPath.string().c_str());
    } else {
        zt_log("  WARNING: Failed to write pre-commit hook.");
    }
}

// ---------------------------------------------------------------------------
// Voice trigger — named-pipe listener for RawrXD_VoiceTrigger
// GUI voice engine writes transcribed commands to the pipe.
// ---------------------------------------------------------------------------
void ZeroTouch::installVoiceTrigger() {
    zt_log("Installing voice trigger named-pipe listener...");
    m_lastVoiceWish.clear();

    // Create a named pipe that GUI voice engine can write transcribed commands to.
    // Pipe name: \\.\pipe\RawrXD_VoiceTrigger
    // Protocol: UTF-8 text lines, newline-delimited.
    // The pipe listener runs in a background thread.

    m_voicePipeRunning.store(true);
    m_voiceThread = std::thread([this]() {
        const wchar_t* pipeName = L"\\\\.\\pipe\\RawrXD_VoiceTrigger";

        while (m_voicePipeRunning.load()) {
            HANDLE hPipe = CreateNamedPipeW(
                pipeName,
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,           // max instances
                0,           // out buffer
                4096,        // in buffer
                1000,        // default timeout ms
                nullptr      // security
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                zt_log("  WARNING: CreateNamedPipe failed (err=%lu) — voice trigger disabled.",
                       GetLastError());
                return;
            }

            zt_log("  Voice pipe created, waiting for connection...");

            // Wait for client connection (blocking)
            BOOL connected = ConnectNamedPipe(hPipe, nullptr)
                ? TRUE
                : (GetLastError() == ERROR_PIPE_CONNECTED ? TRUE : FALSE);

            if (!connected || !m_voicePipeRunning.load()) {
                CloseHandle(hPipe);
                continue;
            }

            zt_log("  Voice client connected.");

            // Read transcribed commands line by line
            char buf[4096];
            DWORD bytesRead = 0;
            std::string lineBuffer;

            while (m_voicePipeRunning.load() &&
                   ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                buf[bytesRead] = '\0';
                lineBuffer += buf;

                // Process complete lines
                size_t nlPos;
                while ((nlPos = lineBuffer.find('\n')) != std::string::npos) {
                    std::string command = lineBuffer.substr(0, nlPos);
                    lineBuffer.erase(0, nlPos + 1);

                    // Trim \r if present
                    if (!command.empty() && command.back() == '\r')
                        command.pop_back();

                    if (!command.empty()) {
                        m_lastVoiceWish = command;
                        zt_log("  Voice command received: \"%s\"", command.c_str());

                        // Dispatch to voice callback if registered
                        if (m_voiceCallback) {
                            m_voiceCallback(command);
                        }
                    }
                }
            }

            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            zt_log("  Voice client disconnected.");
        }
    });
    m_voiceThread.detach();

    zt_log("  Voice trigger pipe listener started on \\\\.\\pipe\\RawrXD_VoiceTrigger");
}
=======
    fs::path hooksDir = fs::current_path() / ".git" / "hooks";
    if (!fs::exists(hooksDir)) {
        
        return;
    }

    fs::path hookPath = hooksDir / "post-commit";
    fs::path agentExe = fs::current_path() / "build" / "bin" / "Release" / "RawrXD-Agent.exe";
    std::string agentExeStr = agentExe.string();
    std::replace(agentExeStr.begin(), agentExeStr.end(), '\\', '/');

    std::string hookScript = 
        "#!/bin/sh\n"
        "# RawrXD zero-touch trigger\n"
        "WISH=$(git log -1 --pretty=%B | head -1)\n"
        "if echo \"$WISH\" | grep -qE \"(ship|release|fix|add)\"; then\n"
        "  export RAWRXD_WISH=\"$WISH\"\n"
        "  " + agentExeStr + "\n"
        "fi\n";

    std::ofstream hookFile(hookPath);
    if (!hookFile) {
        
        return;
    }

    hookFile << hookScript;
    hookFile.close();
    
    // Set executable permissions? On Windows fs::permissions might work or is ignored.
    // fs::permissions(hookPath, fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec, fs::perm_options::add);


}

void ZeroTouch::installVoiceTrigger() {
    // Polling clipboard 
    m_running = true;
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_TEXT);
            if (hData != NULL) {
                char* pszText = static_cast<char*>(GlobalLock(hData));
                if (pszText != NULL) {
                    std::string spoken(pszText);
                    GlobalUnlock(hData);
                    CloseClipboard();
                    
                    if (!spoken.empty() && spoken != m_lastVoiceWish) {
                         if (spoken.length() > 10 && spoken.length() < 200) {
                             std::string lowerSpoken = spoken;
                             std::transform(lowerSpoken.begin(), lowerSpoken.end(), lowerSpoken.begin(), ::tolower);
                             
                             if (lowerSpoken.find("ship") != std::string::npos || 
                                 lowerSpoken.find("release") != std::string::npos || 
                                 lowerSpoken.find("fix") != std::string::npos) {
                                     
                                m_lastVoiceWish = spoken;
                                // Clear clipboard? 
                                if (OpenClipboard(NULL)) {
                                    EmptyClipboard();
                                    CloseClipboard();
                                }
                                
                                _putenv_s("RAWRXD_AUTO_APPROVE", "1");
                                AutoBootstrap::startWithWish(spoken);
                             }
                         }
                    }
                } else {
                    CloseClipboard();
                }
            } else {
                CloseClipboard();
            }
        }
    }
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
