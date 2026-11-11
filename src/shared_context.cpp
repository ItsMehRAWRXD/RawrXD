// ============================================================================
// shared_context.cpp — GlobalContext singleton for Deep2 Engine integration
// ============================================================================
// Provides thread-safe shared state across the deep_iteration_engine pipeline,
// editor, and runtime. Tracks sessions, editor state, memory metrics, and
// request/error counters for convergence detection.
// ============================================================================

#include "shared_context.h"
#include <iostream>

// Static member initialization
std::atomic<uint64_t> GlobalContext::m_sessionCounter{0};

// ============================================================================
// Singleton Access
// ============================================================================

GlobalContext& GlobalContext::Get() {
    static GlobalContext instance;
    static std::once_flag initFlag;
    std::call_once(initFlag, [&]() {
        instance.memory = nullptr;
        instance.patcher = nullptr;
        instance.vsix_loader = nullptr;
        instance.requestCount.store(0);
        instance.errorCount.store(0);
        instance.engineRunning.store(false);
        instance.cancelRequested.store(false);
        instance.memoryMetrics.maxContextTokens = 16384;
    });
    return instance;
}

// ============================================================================
// Deep2 Engine Integration Helpers (C API)
// ============================================================================

extern "C" __declspec(dllexport)
void rawrxd_begin_deep_session(const char* targetPath) {
    GlobalContext& ctx = GlobalContext::Get();
    ctx.beginSession(targetPath ? targetPath : "");
}

extern "C" __declspec(dllexport)
void rawrxd_end_deep_session(int converged) {
    GlobalContext& ctx = GlobalContext::Get();
    ctx.endSession(converged != 0);
}

extern "C" __declspec(dllexport)
void rawrxd_update_deep_progress(uint64_t iterations, uint64_t findings, uint64_t changes) {
    GlobalContext& ctx = GlobalContext::Get();
    ctx.updateProgress(iterations, findings, changes);
}

extern "C" __declspec(dllexport)
void rawrxd_update_editor_state(const char* path, const char* content,
                                int line, int col, int modified) {
    GlobalContext& ctx = GlobalContext::Get();
    ctx.updateEditorState(
        path ? path : "",
        content ? content : "",
        line, col, modified != 0
    );
}

extern "C" __declspec(dllexport)
void rawrxd_request_cancel() {
    GlobalContext::Get().requestCancel();
}

extern "C" __declspec(dllexport)
const char* rawrxd_get_status_string() {
    static thread_local std::string statusStr;
    statusStr = GlobalContext::Get().getStatusString();
    return statusStr.c_str();
}
