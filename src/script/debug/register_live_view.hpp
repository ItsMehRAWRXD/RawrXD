// ============================================================================
// register_live_view.hpp — RawrXD-Script VM Register Live View
// ============================================================================
// Real-time register state display for debugging
// Polls VM state and displays r0-r15 with value formatting
//
// Copyright (c) 2026 RawrXD Project — All rights reserved.
// ============================================================================

#pragma once

#include "script/masm/interpreter.hpp"
#include <string>
#include <array>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>

namespace RawrXD {
namespace Script {
namespace Debug {

// ============================================================================
// Register State
// ============================================================================

struct RegisterState {
    std::array<uint64_t, 16> values;      // r0-r15 NaN-boxed values
    std::array<std::string, 16> types;    // Inferred types
    std::array<bool, 16> modified;        // Changed since last poll
    uint64_t pc;                           // Program counter
    uint64_t sp;                           // Stack pointer
    uint32_t flags;                        // Status flags
    uint64_t timestamp;                    // Last update timestamp
};

// ============================================================================
// Register Live View
// ============================================================================

class RegisterLiveView {
public:
    using UpdateCallback = std::function<void(const RegisterState& state)>;

    RegisterLiveView();
    ~RegisterLiveView();

    // Initialize with interpreter
    bool Initialize(Script::Interpreter* interpreter);
    void Shutdown();

    // Start/stop polling
    void StartPolling(int intervalMs = 100);
    void StopPolling();

    // Manual refresh
    RegisterState Refresh();

    // Set callback for updates
    void SetUpdateCallback(UpdateCallback callback);

    // Formatting helpers
    static std::string FormatValue(uint64_t nanBoxedValue);
    static std::string FormatType(uint64_t nanBoxedValue);
    static std::string FormatHex(uint64_t value);
    static std::string FormatBinary(uint64_t value);

    // Get current state
    RegisterState GetCurrentState() const;

    // Watch specific register
    void WatchRegister(int regIndex, UpdateCallback callback);
    void UnwatchRegister(int regIndex);

private:
    Script::Interpreter* m_interpreter = nullptr;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_polling{false};
    std::thread m_pollThread;
    int m_pollIntervalMs = 100;

    RegisterState m_currentState;
    mutable std::mutex m_stateMutex;

    UpdateCallback m_updateCallback;
    std::array<UpdateCallback, 16> m_watchCallbacks;

    // Polling loop
    void PollLoop();

    // Read interpreter state
    RegisterState ReadInterpreterState();

    // Detect type from NaN-boxed value
    static std::string DetectType(uint64_t value);
};

// ============================================================================
// WebSocket Server for External Tools
// ============================================================================

class RegisterLiveViewServer {
public:
    RegisterLiveViewServer();
    ~RegisterLiveViewServer();

    bool Start(int port = 11436);
    void Stop();

    void BroadcastState(const RegisterState& state);

    bool IsRunning() const { return m_running; }

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    std::atomic<bool> m_running{false};
};

// ============================================================================
// Global Access
// ============================================================================

RegisterLiveView* GetRegisterLiveView();
bool InitializeRegisterLiveView(Script::Interpreter* interpreter);
void ShutdownRegisterLiveView();

} // namespace Debug
} // namespace Script
} // namespace RawrXD
