// ============================================================================
// model_operations_bridge.hpp — Async Model Operations Bridge
// ============================================================================
// Bridge pattern for non-blocking model operations. Offloads heavy compute
// from the Win32 UI thread to the work-stealing ThreadPool, then posts
// results back via WM_APP messages.
//
// Architecture:
//   UI Thread → QueueInference() → ThreadPool::submit(HIGH) → Worker
//   Worker → GenerateStreaming() → PostMessage(WM_JOB_COMPLETE)
//   UI Thread → handleMessage() → callback dispatch
//
// Integration:
//   - ThreadPool::Global() for work-stealing execution
//   - CPUInferenceEngine::GetSharedInstance() for inference
//   - AgenticExecutor for tool orchestration
//   - Win32IDE message loop for callback dispatch
//
// Threading: All heavy operations run on ThreadPool workers.
// No exceptions. PatchResult-style error returns.
// ============================================================================

#pragma once

#include <functional>
#include <string>
#include <atomic>
#include <map>
#include <mutex>
#include <memory>
#include <windows.h>

// Forward declarations
class AgenticExecutor;
namespace RawrXD {
    class CPUInferenceEngine;
    namespace Threading {
        class ThreadPool;
    }
}

// ============================================================================
// Job Result — passed from worker thread to UI thread
// ============================================================================
struct ModelJobResult {
    uint64_t jobId;
    bool success;
    std::string output;
    std::string error;
    double durationMs;
    std::string metadata;  // JSON for additional info
};

// ============================================================================
// Model Operations Bridge — async wrapper for model operations
// ============================================================================
class ModelOperationsBridge {
public:
    // Callback types
    using InferenceCallback = std::function<void(const std::string& result, bool success, const std::string& error)>;
    using BenchmarkCallback = std::function<void(double tokensPerSecond, double latencyMs, bool success)>;
    using GenericCallback = std::function<void(const ModelJobResult& result)>;

    // Construction
    ModelOperationsBridge(HWND hwndMain, AgenticExecutor* executor = nullptr);
    ~ModelOperationsBridge();

    // ---- Initialization ----
    bool initialize();
    void shutdown();

    // ---- P0 Model Operations (Async) ----

    /**
     * Queue inference request for async execution.
     * Returns immediately; result delivered via callback on UI thread.
     * @param input The prompt text to process
     * @param maxTokens Maximum tokens to generate
     * @param callback Called on UI thread when complete
     * @return Job ID for tracking, or 0 on error
     */
    uint64_t QueueInference(const std::string& input,
                            int maxTokens,
                            InferenceCallback callback);

    /**
     * Queue model loading for async execution.
     * @param modelPath Path to GGUF model file
     * @param callback Called on UI thread when complete
     * @return Job ID for tracking, or 0 on error
     */
    uint64_t QueueLoadModel(const std::string& modelPath,
                            GenericCallback callback);

    /**
     * Queue benchmark for async execution.
     * @param warmupTokens Number of warmup tokens to generate
     * @param testTokens Number of test tokens to generate
     * @param callback Called on UI thread with benchmark results
     * @return Job ID for tracking, or 0 on error
     */
    uint64_t QueueBenchmark(int warmupTokens,
                            int testTokens,
                            BenchmarkCallback callback);

    /**
     * Queue tokenization for async execution.
     * @param text Text to tokenize
     * @param callback Called on UI thread with token IDs
     * @return Job ID for tracking, or 0 on error
     */
    uint64_t QueueTokenize(const std::string& text,
                           GenericCallback callback);

    /**
     * Queue detokenization for async execution.
     * @param tokens Token IDs to convert to text
     * @param callback Called on UI thread with decoded text
     * @return Job ID for tracking, or 0 on error
     */
    uint64_t QueueDetokenize(const std::vector<int32_t>& tokens,
                             GenericCallback callback);

    // ---- P0 Model Operations (Sync - Fast Operations) ----

    /**
     * Get model info (synchronous, fast).
     * @return JSON string with model metadata
     */
    std::string GetModelInfo() const;

    /**
     * Check if model is loaded (synchronous, fast).
     */
    bool IsModelLoaded() const;

    /**
     * Get context usage (synchronous, fast).
     * @return JSON string with context stats
     */
    std::string GetContextUsage() const;

    /**
     * List loaded models (synchronous, fast).
     * @return JSON array of loaded model paths
     */
    std::string ListLoadedModels() const;

    // ---- Job Management ----

    /**
     * Cancel a pending job.
     * @param jobId Job ID to cancel
     * @return true if job was cancelled
     */
    bool CancelJob(uint64_t jobId);

    /**
     * Check if a job is pending.
     */
    bool IsJobPending(uint64_t jobId) const;

    /**
     * Get number of pending jobs.
     */
    size_t PendingJobCount() const;

    // ---- Callback Dispatch (called from Win32 message loop) ----

    /**
     * Dispatch result to registered callback.
     * Called from WM_JOB_COMPLETE handler in Win32IDE.
     * @param jobId Job ID from wParam
     * @param result Heap-allocated result (caller owns, must delete)
     */
    void DispatchResult(uint64_t jobId, ModelJobResult* result);

    // ---- Statistics ----

    struct Stats {
        uint64_t totalJobsSubmitted;
        uint64_t totalJobsCompleted;
        uint64_t totalJobsFailed;
        uint64_t totalInferencesRun;
        uint64_t totalTokensGenerated;
        double totalInferenceMs;
        double avgInferenceMs;
        double avgTokensPerSecond;
    };

    Stats GetStats() const;
    void ResetStats();

private:
    // ---- Internal Helpers ----

    uint64_t allocateJobId();
    void recordJobStart(uint64_t jobId, const std::string& operation);
    void recordJobComplete(uint64_t jobId, bool success, double durationMs);
    void recordTokensGenerated(uint64_t count);

    // ---- Worker Thread Functions ----

    void executeInference(uint64_t jobId,
                          const std::string& input,
                          int maxTokens);

    void executeLoadModel(uint64_t jobId,
                          const std::string& modelPath);

    void executeBenchmark(uint64_t jobId,
                          int warmupTokens,
                          int testTokens);

    void executeTokenize(uint64_t jobId,
                         const std::string& text);

    void executeDetokenize(uint64_t jobId,
                           const std::vector<int32_t>& tokens);

    // ---- Member Variables ----

    HWND m_hwndMain;
    AgenticExecutor* m_executor;
    RawrXD::Threading::ThreadPool* m_threadPool;
    std::shared_ptr<RawrXD::CPUInferenceEngine> m_engine;

    // Job tracking
    std::atomic<uint64_t> m_jobCounter{0};
    std::map<uint64_t, GenericCallback> m_pendingCallbacks;
    mutable std::mutex m_callbackMutex;

    // Statistics
    std::atomic<uint64_t> m_totalJobsSubmitted{0};
    std::atomic<uint64_t> m_totalJobsCompleted{0};
    std::atomic<uint64_t> m_totalJobsFailed{0};
    std::atomic<uint64_t> m_totalInferencesRun{0};
    std::atomic<uint64_t> m_totalTokensGenerated{0};
    std::atomic<double> m_totalInferenceMs{0.0};

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shuttingDown{false};
};

// ============================================================================
// Win32 Message Definitions
// ============================================================================
#ifndef WM_JOB_COMPLETE
#define WM_JOB_COMPLETE (WM_APP + 0x100)
#endif

#ifndef WM_JOB_PROGRESS
#define WM_JOB_PROGRESS (WM_APP + 0x101)
#endif

#ifndef WM_JOB_ERROR
#define WM_JOB_ERROR (WM_APP + 0x102)
#endif