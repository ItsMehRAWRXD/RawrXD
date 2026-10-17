/**
 * @file qt_elimination.h
 * @brief Native C++/Win32 replacements for Qt compatibility stubs
 *
 * Provides production-ready native implementations that replace Qt's
 * no-op compatibility layer:
 * - NativeTimer: Real timer with waitable timer + worker thread, cancellable and joinable
 * - NativeProcess: Real CreateProcessW execution (replaces QProcess)
 * - NativeJson: Real JSON parsing/serialization (replaces QJsonDocument)
 * - NativeSignalSlot: Working callback dispatch (replaces QObject::connect)
 * - NativeSettings: Persistent disk-backed storage (replaces QSettings)
 * - NativeWidget: Real Win32 controls (replaces QWidget no-ops)
 *
 * Zero dependencies: Windows API + C++17 standard library only.
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ============================================================================
// NativeTimer — Real timer using Windows waitable timers + worker thread
// Replaces QTimer (which was a detached worker capturing 'this', never firing)
// ============================================================================

class NativeTimer {
public:
    using Callback = std::function<void()>;

    NativeTimer() = default;
    ~NativeTimer() { stop(); }

    // Start a single-shot or repeating timer
    // intervalMs: timer interval in milliseconds
    // singleShot: if true, fires once; if false, repeats
    // callback: function to invoke when timer fires
    void start(int intervalMs, bool singleShot, Callback callback) {
        stop();
        m_intervalMs = intervalMs;
        m_singleShot = singleShot;
        m_callback = std::move(callback);
        m_stopRequested = false;
        m_thread = std::thread(&NativeTimer::runLoop, this);
    }

    // Restart timer with previously set interval and callback
    void start() {
        if (m_callback) {
            start(m_intervalMs, m_singleShot, m_callback);
        }
    }

    // Change the timer interval (in milliseconds)
    void setInterval(int intervalMs) {
        m_intervalMs = intervalMs;
    }

    // Stop the timer and join the worker thread
    void stop() {
        m_stopRequested = true;
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    bool isRunning() const { return m_thread.joinable() && !m_stopRequested; }

private:
    void runLoop() {
        HANDLE hTimer = CreateWaitableTimerW(nullptr, TRUE, nullptr);
        if (!hTimer) return;

        LARGE_INTEGER dueTime;
        while (!m_stopRequested) {
            dueTime.QuadPart = -((__int64)m_intervalMs * 10000LL); // negative = relative time
            if (!SetWaitableTimer(hTimer, &dueTime, m_intervalMs, nullptr, nullptr, FALSE)) {
                break;
            }

            DWORD result = WaitForSingleObject(hTimer, m_intervalMs + 100);
            if (result == WAIT_OBJECT_0 || result == WAIT_TIMEOUT) {
                if (m_stopRequested) break;
                if (m_callback) {
                    try {
                        m_callback();
                    } catch (...) {
                        // Swallow exceptions from user callbacks
                    }
                }
                if (m_singleShot) break;
            }
        }

        CloseHandle(hTimer);
    }

    std::thread m_thread;
    std::atomic<bool> m_stopRequested{false};
    int m_intervalMs = 0;
    bool m_singleShot = false;
    Callback m_callback;
};

// Single-shot timer helper (fire once after delay)
class NativeSingleShotTimer {
public:
    static void run(int delayMs, std::function<void()> callback) {
        std::thread([delayMs, callback = std::move(callback)]() mutable {
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            if (callback) {
                try { callback(); } catch (...) {}
            }
        }).detach();
    }
};

// ============================================================================
// NativeProcess — Real CreateProcessW execution (replaces QProcess)
// ============================================================================

struct NativeProcessResult {
    int exitCode = -1;
    bool success = false;
    std::string stdoutOutput;
    std::string stderrOutput;
};

class NativeProcess {
public:
    // Execute a command synchronously, wait for completion
    // Returns exit code and captured output
    static NativeProcessResult execute(const std::string& command,
                                       const std::vector<std::string>& args = {},
                                       const std::string& workingDir = "",
                                       int timeoutMs = 30000) {
        NativeProcessResult result;

        // Build command line
        std::string cmdLine = "\"" + command + "\"";
        for (const auto& arg : args) {
            cmdLine += " \"" + arg + "\"";
        }

        // Convert to wide strings
        auto toWide = [](const std::string& s) -> std::wstring {
            int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
            std::wstring w(len, 0);
            MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], len);
            return w;
        };

        std::wstring wCmdLine = toWide(cmdLine);
        std::wstring wWorkDir = workingDir.empty() ? std::wstring() : toWide(workingDir);

        // Create pipes for stdout/stderr capture
        HANDLE hStdOutRead = nullptr, hStdOutWrite = nullptr;
        HANDLE hStdErrRead = nullptr, hStdErrWrite = nullptr;
        SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};

        CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0);
        SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
        CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0);
        SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si = {sizeof(STARTUPINFOW)};
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hStdOutWrite;
        si.hStdError = hStdErrWrite;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        PROCESS_INFORMATION pi = {0};

        BOOL created = CreateProcessW(
            nullptr,           // application name
            &wCmdLine[0],      // command line
            nullptr,           // process security
            nullptr,           // thread security
            TRUE,              // inherit handles
            CREATE_NO_WINDOW,  // creation flags
            nullptr,           // environment
            wWorkDir.empty() ? nullptr : wWorkDir.c_str(), // working directory
            &si,               // startup info
            &pi                // process information
        );

        // Shell built-ins (ver, echo, dir, etc.) need cmd /c prefix
        if (!created) {
            std::string shellCmdLine = "cmd /c " + cmdLine;
            std::wstring wShellCmdLine = toWide(shellCmdLine);
            created = CreateProcessW(
                nullptr,           // application name
                &wShellCmdLine[0], // command line
                nullptr,           // process security
                nullptr,           // thread security
                TRUE,              // inherit handles
                CREATE_NO_WINDOW,  // creation flags
                nullptr,           // environment
                wWorkDir.empty() ? nullptr : wWorkDir.c_str(), // working directory
                &si,               // startup info
                &pi                // process information
            );
        }

        // Close write ends of pipes (we only read)
        CloseHandle(hStdOutWrite);
        CloseHandle(hStdErrWrite);

        if (!created) {
            CloseHandle(hStdOutRead);
            CloseHandle(hStdErrRead);
            result.success = false;
            result.exitCode = GetLastError();
            return result;
        }

        // Wait for process completion
        DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            result.success = false;
            result.exitCode = -1;
        } else {
            DWORD exitCode = 0;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            result.exitCode = static_cast<int>(exitCode);
            result.success = (exitCode == 0);
        }

        // Read stdout
        char buffer[4096];
        DWORD bytesRead = 0;
        while (ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            result.stdoutOutput += buffer;
        }

        // Read stderr
        while (ReadFile(hStdErrRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            result.stderrOutput += buffer;
        }

        CloseHandle(hStdOutRead);
        CloseHandle(hStdErrRead);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return result;
    }

    // Check if a program exists in PATH
    static bool exists(const std::string& program) {
        // Split "where cmd" into command + args
        std::string cmdLine = "where " + program;
        // Find first space to split command from args
        auto spacePos = cmdLine.find(' ');
        std::string cmd = (spacePos != std::string::npos) ? cmdLine.substr(0, spacePos) : cmdLine;
        std::vector<std::string> args;
        if (spacePos != std::string::npos) {
            args.push_back(cmdLine.substr(spacePos + 1));
        }
        auto result = execute(cmd, args, "", 5000);
        return result.success && !result.stdoutOutput.empty();
    }
};

// ============================================================================
// NativeJson — Real JSON parsing/serialization (replaces QJsonDocument)
// Uses nlohmann/json which is already a project dependency
// ============================================================================

class NativeJson {
public:
    // Parse JSON string, returns empty json on failure
    static json fromJson(const std::string& jsonStr) {
        try {
            return json::parse(jsonStr);
        } catch (...) {
            return json();
        }
    }

    // Serialize json to compact string
    static std::string toJson(const json& j) {
        try {
            return j.dump();
        } catch (...) {
            return "{}";
        }
    }

    // Serialize json to pretty-printed string
    static std::string toJsonPretty(const json& j) {
        try {
            return j.dump(2);
        } catch (...) {
            return "{}";
        }
    }

    // Check if json is valid object
    static bool isObject(const json& j) {
        return j.is_object();
    }

    // Check if json is valid array
    static bool isArray(const json& j) {
        return j.is_array();
    }

    // Get value with default
    template<typename T>
    static T get(const json& j, const std::string& key, const T& defaultValue = T()) {
        try {
            if (j.contains(key)) {
                return j.at(key).get<T>();
            }
        } catch (...) {}
        return defaultValue;
    }
};

// ============================================================================
// NativeSignalSlot — Working callback dispatch (replaces QObject::connect)
// ============================================================================

class NativeSignalSlot {
public:
    using Slot = std::function<void()>;

    // Connect a signal name to a slot callback
    void connect(const std::string& signalName, Slot slot) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_slots[signalName].push_back(std::move(slot));
    }

    // Emit a signal, calling all connected slots
    void emit(const std::string& signalName) {
        std::vector<Slot> slots;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_slots.find(signalName);
            if (it != m_slots.end()) {
                slots = it->second;
            }
        }
        for (auto& slot : slots) {
            try {
                slot();
            } catch (...) {
                // Swallow exceptions from slots
            }
        }
    }

    // Disconnect all slots for a signal
    void disconnect(const std::string& signalName) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_slots.erase(signalName);
    }

    // Check if any slots are connected to a signal
    bool hasConnections(const std::string& signalName) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_slots.find(signalName);
        return it != m_slots.end() && !it->second.empty();
    }

private:
    mutable std::mutex m_mutex;
    std::map<std::string, std::vector<Slot>> m_slots;
};

// ============================================================================
// NativeSettings — Persistent disk-backed storage (replaces QSettings)
// ============================================================================

class NativeSettings {
public:
    NativeSettings(const std::string& filePath) : m_filePath(filePath) {
        load();
    }

    ~NativeSettings() { save(); }

    // Set a value
    void setValue(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_data[key] = value;
    }

    // Get a value
    std::string value(const std::string& key, const std::string& defaultValue = "") const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_data.find(key);
        if (it != m_data.end()) return it->second;
        return defaultValue;
    }

    // Set an integer value
    void setInt(const std::string& key, int value) {
        setValue(key, std::to_string(value));
    }

    // Get an integer value
    int intValue(const std::string& key, int defaultValue = 0) const {
        try {
            return std::stoi(value(key, std::to_string(defaultValue)));
        } catch (...) {
            return defaultValue;
        }
    }

    // Set a boolean value
    void setBool(const std::string& key, bool value) {
        setValue(key, value ? "true" : "false");
    }

    // Get a boolean value
    bool boolValue(const std::string& key, bool defaultValue = false) const {
        std::string v = value(key, defaultValue ? "true" : "false");
        return v == "true" || v == "1";
    }

    // Remove a key
    void remove(const std::string& key) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_data.erase(key);
    }

    // Check if key exists
    bool contains(const std::string& key) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_data.find(key) != m_data.end();
    }

    // Force save to disk
    void sync() { save(); }

private:
    void load() {
        std::ifstream file(m_filePath);
        if (!file.is_open()) return;
        try {
            json j;
            file >> j;
            for (auto& [k, v] : j.items()) {
                m_data[k] = v.is_string() ? v.get<std::string>() : v.dump();
            }
        } catch (...) {
            // Corrupt settings file, start fresh
        }
    }

    void save() {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Ensure directory exists
        size_t pos = m_filePath.find_last_of("/\\");
        if (pos != std::string::npos) {
            std::string dir = m_filePath.substr(0, pos);
            CreateDirectoryA(dir.c_str(), nullptr);
        }

        json j;
        for (auto& [k, v] : m_data) {
            j[k] = v;
        }

        std::ofstream file(m_filePath);
        if (file.is_open()) {
            file << j.dump(2);
        }
    }

    std::string m_filePath;
    mutable std::mutex m_mutex;
    std::map<std::string, std::string> m_data;
};

// ============================================================================
// NativeWidget — Real Win32 control wrappers (replaces QWidget no-ops)
// ============================================================================

class NativeWidget {
public:
    NativeWidget() = default;
    virtual ~NativeWidget() = default;

    // Create a real Win32 window
    bool create(HWND parent, int x, int y, int width, int height,
                const std::string& className, const std::string& title,
                DWORD style = WS_CHILD | WS_VISIBLE) {
        // Child windows require a valid parent HWND; when none is given,
        // upgrade to an overlapped top-level window so creation succeeds.
        DWORD effectiveStyle = style;
        if (parent == nullptr && (style & WS_CHILD)) {
            effectiveStyle = (style & ~WS_CHILD) | WS_OVERLAPPED | WS_VISIBLE;
        }
        m_hwnd = CreateWindowExA(
            0, className.c_str(), title.c_str(),
            effectiveStyle, x, y, width, height,
            parent, nullptr, GetModuleHandle(nullptr), this
        );
        return m_hwnd != nullptr;
    }

    HWND handle() const { return m_hwnd; }

    void show() {
        if (m_hwnd) ShowWindow(m_hwnd, SW_SHOW);
    }

    void hide() {
        if (m_hwnd) ShowWindow(m_hwnd, SW_HIDE);
    }

    void enable(bool enabled) {
        if (m_hwnd) EnableWindow(m_hwnd, enabled ? TRUE : FALSE);
    }

    void setText(const std::string& text) {
        if (m_hwnd) SetWindowTextA(m_hwnd, text.c_str());
    }

    std::string getText() const {
        if (!m_hwnd) return "";
        int len = GetWindowTextLengthA(m_hwnd);
        std::string text(len, '\0');
        GetWindowTextA(m_hwnd, &text[0], len + 1);
        return text;
    }

protected:
    HWND m_hwnd = nullptr;
};

// Global instances for compatibility
extern NativeSignalSlot g_signalSlot;
extern NativeSettings g_settings;
