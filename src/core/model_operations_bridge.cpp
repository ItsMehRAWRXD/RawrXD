// ============================================================================
// model_operations_bridge.cpp — Async Model Operations Bridge Implementation
// ============================================================================
// Bridge pattern implementation for non-blocking model operations.
// Uses work-stealing ThreadPool for execution and Win32 PostMessage for
// thread-safe result delivery.
//
// Pattern: PatchResult-style, no exceptions.
// Rule:    NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include "model_operations_bridge.hpp"
#include "thread_pool.hpp"
#include "cpu_inference_engine.h"
#include "agentic_executor.h"
#include "IDELogger.h"

#include <chrono>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ============================================================================
// Construction / Destruction
// ============================================================================

ModelOperationsBridge::ModelOperationsBridge(HWND hwndMain, AgenticExecutor* executor)
    : m_hwndMain(hwndMain)
    , m_executor(executor)
    , m_threadPool(&RawrXD::Threading::ThreadPool::Global())
    , m_engine(RawrXD::CPUInferenceEngine::GetSharedInstance())
{
    LOG_INFO_FMT("[ModelOperationsBridge] Constructed with hwndMain=%p, executor=%p", hwndMain, executor);
}

ModelOperationsBridge::~ModelOperationsBridge()
{
    shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool ModelOperationsBridge::initialize()
{
    if (m_initialized.load(std::memory_order_acquire)) {
        LOG_WARN_FMT("[ModelOperationsBridge] Already initialized");
        return true;
    }

    if (!m_threadPool) {
        LOG_ERROR_FMT("[ModelOperationsBridge] ThreadPool not available");
        return false;
    }

    if (!m_engine) {
        LOG_ERROR_FMT("[ModelOperationsBridge] CPUInferenceEngine not available");
        return false;
    }

    m_shuttingDown.store(false, std::memory_order_release);
    m_initialized.store(true, std::memory_order_release);

    LOG_INFO_FMT("[ModelOperationsBridge] Initialized successfully");
    return true;
}

void ModelOperationsBridge::shutdown()
{
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_shuttingDown.store(true, std::memory_order_release);

    // Cancel all pending jobs
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks.clear();
    }

    m_initialized.store(false, std::memory_order_release);
    LOG_INFO_FMT("[ModelOperationsBridge] Shutdown complete");
}

// ============================================================================
// P0 Model Operations (Async)
// ============================================================================

uint64_t ModelOperationsBridge::QueueInference(const std::string& input,
                                                int maxTokens,
                                                InferenceCallback callback)
{
    if (!m_initialized.load(std::memory_order_acquire)) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Not initialized");
        return 0;
    }

    if (!m_engine || !m_engine->IsModelLoaded()) {
        LOG_ERROR_FMT("[ModelOperationsBridge] No model loaded for inference");
        if (callback) {
            callback("", false, "No model loaded");
        }
        return 0;
    }

    uint64_t jobId = allocateJobId();
    recordJobStart(jobId, "inference");

    // Wrap callback for generic dispatch
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks[jobId] = [callback](const ModelJobResult& result) {
            if (callback) {
                callback(result.output, result.success, result.error);
            }
        };
    }

    // Submit to ThreadPool with HIGH priority
    auto result = m_threadPool->submit(
        [this, jobId, input, maxTokens]() {
            executeInference(jobId, input, maxTokens);
        },
        RawrXD::Threading::TaskPriority::HIGH,
        "ModelInference"
    );

    if (!result.success) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Failed to submit inference job: %s", result.detail);
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks.erase(jobId);
        return 0;
    }

    LOG_INFO_FMT("[ModelOperationsBridge] Queued inference job %llu (%d tokens)", jobId, maxTokens);
    return jobId;
}

uint64_t ModelOperationsBridge::QueueLoadModel(const std::string& modelPath,
                                                GenericCallback callback)
{
    if (!m_initialized.load(std::memory_order_acquire)) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Not initialized");
        return 0;
    }

    uint64_t jobId = allocateJobId();
    recordJobStart(jobId, "load_model");

    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks[jobId] = callback;
    }

    auto result = m_threadPool->submit(
        [this, jobId, modelPath]() {
            executeLoadModel(jobId, modelPath);
        },
        RawrXD::Threading::TaskPriority::HIGH,
        "LoadModel"
    );

    if (!result.success) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Failed to submit load model job: %s", result.detail);
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks.erase(jobId);
        return 0;
    }

    LOG_INFO_FMT("[ModelOperationsBridge] Queued load model job %llu: %s", jobId, modelPath.c_str());
    return jobId;
}

uint64_t ModelOperationsBridge::QueueBenchmark(int warmupTokens,
                                                int testTokens,
                                                BenchmarkCallback callback)
{
    if (!m_initialized.load(std::memory_order_acquire)) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Not initialized");
        return 0;
    }

    if (!m_engine || !m_engine->IsModelLoaded()) {
        LOG_ERROR_FMT("[ModelOperationsBridge] No model loaded for benchmark");
        if (callback) {
            callback(0.0, 0.0, false);
        }
        return 0;
    }

    uint64_t jobId = allocateJobId();
    recordJobStart(jobId, "benchmark");

    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks[jobId] = [callback](const ModelJobResult& result) {
            if (callback) {
                // Parse benchmark results from metadata JSON
                try {
                    auto meta = json::parse(result.metadata);
                    double tps = meta.value("tokens_per_second", 0.0);
                    double latency = meta.value("latency_ms", 0.0);
                    callback(tps, latency, result.success);
                } catch (...) {
                    callback(0.0, 0.0, false);
                }
            }
        };
    }

    auto result = m_threadPool->submit(
        [this, jobId, warmupTokens, testTokens]() {
            executeBenchmark(jobId, warmupTokens, testTokens);
        },
        RawrXD::Threading::TaskPriority::NORMAL,
        "Benchmark"
    );

    if (!result.success) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Failed to submit benchmark job: %s", result.detail);
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks.erase(jobId);
        return 0;
    }

    LOG_INFO_FMT("[ModelOperationsBridge] Queued benchmark job %llu", jobId);
    return jobId;
}

uint64_t ModelOperationsBridge::QueueTokenize(const std::string& text,
                                               GenericCallback callback)
{
    if (!m_initialized.load(std::memory_order_acquire)) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Not initialized");
        return 0;
    }

    if (!m_engine) {
        LOG_ERROR_FMT("[ModelOperationsBridge] No engine for tokenization");
        return 0;
    }

    uint64_t jobId = allocateJobId();
    recordJobStart(jobId, "tokenize");

    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks[jobId] = callback;
    }

    auto result = m_threadPool->submit(
        [this, jobId, text]() {
            executeTokenize(jobId, text);
        },
        RawrXD::Threading::TaskPriority::HIGH,
        "Tokenize"
    );

    if (!result.success) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Failed to submit tokenize job: %s", result.detail);
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks.erase(jobId);
        return 0;
    }

    return jobId;
}

uint64_t ModelOperationsBridge::QueueDetokenize(const std::vector<int32_t>& tokens,
                                                 GenericCallback callback)
{
    if (!m_initialized.load(std::memory_order_acquire)) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Not initialized");
        return 0;
    }

    if (!m_engine) {
        LOG_ERROR_FMT("[ModelOperationsBridge] No engine for detokenization");
        return 0;
    }

    uint64_t jobId = allocateJobId();
    recordJobStart(jobId, "detokenize");

    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks[jobId] = callback;
    }

    auto result = m_threadPool->submit(
        [this, jobId, tokens]() {
            executeDetokenize(jobId, tokens);
        },
        RawrXD::Threading::TaskPriority::HIGH,
        "Detokenize"
    );

    if (!result.success) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Failed to submit detokenize job: %s", result.detail);
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_pendingCallbacks.erase(jobId);
        return 0;
    }

    return jobId;
}

// ============================================================================
// P0 Model Operations (Sync - Fast Operations)
// ============================================================================

std::string ModelOperationsBridge::GetModelInfo() const
{
    if (!m_engine || !m_engine->IsModelLoaded()) {
        return R"({"error": "No model loaded"})";
    }

    json info;
    info["loaded"] = true;
    info["context_limit"] = static_cast<int64_t>(m_engine->GetContextLimit());
    // Add more model info as needed

    return info.dump();
}

bool ModelOperationsBridge::IsModelLoaded() const
{
    return m_engine && m_engine->IsModelLoaded();
}

std::string ModelOperationsBridge::GetContextUsage() const
{
    if (!m_engine || !m_engine->IsModelLoaded()) {
        return R"({"error": "No model loaded"})";
    }

    json usage;
    usage["context_limit"] = static_cast<int64_t>(m_engine->GetContextLimit());
    // Add context usage stats as needed

    return usage.dump();
}

std::string ModelOperationsBridge::ListLoadedModels() const
{
    json models = json::array();
    if (m_engine && m_engine->IsModelLoaded()) {
        models.push_back("current_model");
    }
    return models.dump();
}

// ============================================================================
// Job Management
// ============================================================================

bool ModelOperationsBridge::CancelJob(uint64_t jobId)
{
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    auto it = m_pendingCallbacks.find(jobId);
    if (it != m_pendingCallbacks.end()) {
        m_pendingCallbacks.erase(it);
        LOG_INFO_FMT("[ModelOperationsBridge] Cancelled job %llu", jobId);
        return true;
    }
    return false;
}

bool ModelOperationsBridge::IsJobPending(uint64_t jobId) const
{
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_callbackMutex));
    return m_pendingCallbacks.find(jobId) != m_pendingCallbacks.end();
}

size_t ModelOperationsBridge::PendingJobCount() const
{
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(m_callbackMutex));
    return m_pendingCallbacks.size();
}

// ============================================================================
// Callback Dispatch
// ============================================================================

void ModelOperationsBridge::DispatchResult(uint64_t jobId, ModelJobResult* result)
{
    if (!result) {
        LOG_ERROR_FMT("[ModelOperationsBridge] DispatchResult called with null result");
        return;
    }

    // Validate jobId matches the result
    if (result->jobId != jobId) {
        LOG_ERROR_FMT("[ModelOperationsBridge] Job ID mismatch: expected %llu, got %llu", jobId, result->jobId);
        delete result;
        return;
    }

    GenericCallback callback;
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        auto it = m_pendingCallbacks.find(jobId);
        if (it != m_pendingCallbacks.end()) {
            callback = it->second;
            m_pendingCallbacks.erase(it);
        } else {
            // Job was cancelled or bridge was shutdown - clean up result
            LOG_WARN_FMT("[ModelOperationsBridge] Job %llu not found in pending callbacks (cancelled or shutdown)", jobId);
            recordJobComplete(jobId, result->success, result->durationMs);
            delete result;
            return;
        }
    }

    if (callback) {
        callback(*result);
    }

    recordJobComplete(jobId, result->success, result->durationMs);
    delete result;
}

// ============================================================================
// Statistics
// ============================================================================

ModelOperationsBridge::Stats ModelOperationsBridge::GetStats() const
{
    Stats stats;
    stats.totalJobsSubmitted = m_totalJobsSubmitted.load(std::memory_order_relaxed);
    stats.totalJobsCompleted = m_totalJobsCompleted.load(std::memory_order_relaxed);
    stats.totalJobsFailed = m_totalJobsFailed.load(std::memory_order_relaxed);
    stats.totalInferencesRun = m_totalInferencesRun.load(std::memory_order_relaxed);
    stats.totalTokensGenerated = m_totalTokensGenerated.load(std::memory_order_relaxed);
    stats.totalInferenceMs = m_totalInferenceMs.load(std::memory_order_relaxed);

    if (stats.totalInferencesRun > 0) {
        stats.avgInferenceMs = stats.totalInferenceMs / stats.totalInferencesRun;
        double totalSeconds = stats.totalInferenceMs / 1000.0;
        if (totalSeconds > 0) {
            stats.avgTokensPerSecond = stats.totalTokensGenerated / totalSeconds;
        }
    }

    return stats;
}

void ModelOperationsBridge::ResetStats()
{
    m_totalJobsSubmitted.store(0, std::memory_order_relaxed);
    m_totalJobsCompleted.store(0, std::memory_order_relaxed);
    m_totalJobsFailed.store(0, std::memory_order_relaxed);
    m_totalInferencesRun.store(0, std::memory_order_relaxed);
    m_totalTokensGenerated.store(0, std::memory_order_relaxed);
    m_totalInferenceMs.store(0.0, std::memory_order_relaxed);
}

// ============================================================================
// Internal Helpers
// ============================================================================

uint64_t ModelOperationsBridge::allocateJobId()
{
    return ++m_jobCounter;
}

void ModelOperationsBridge::recordJobStart(uint64_t jobId, const std::string& operation)
{
    m_totalJobsSubmitted.fetch_add(1, std::memory_order_relaxed);
    LOG_DEBUG_FMT("[ModelOperationsBridge] Job %llu started: %s", jobId, operation.c_str());
}

void ModelOperationsBridge::recordJobComplete(uint64_t jobId, bool success, double durationMs)
{
    if (success) {
        m_totalJobsCompleted.fetch_add(1, std::memory_order_relaxed);
    } else {
        m_totalJobsFailed.fetch_add(1, std::memory_order_relaxed);
    }
    LOG_DEBUG_FMT("[ModelOperationsBridge] Job %llu completed: success=%d, duration=%.2fms",
              jobId, success, durationMs);
}

void ModelOperationsBridge::recordTokensGenerated(uint64_t count)
{
    m_totalTokensGenerated.fetch_add(count, std::memory_order_relaxed);
}

// ============================================================================
// Worker Thread Functions
// ============================================================================

void ModelOperationsBridge::executeInference(uint64_t jobId,
                                              const std::string& input,
                                              int maxTokens)
{
    auto startTime = std::chrono::high_resolution_clock::now();

    ModelJobResult* result = new ModelJobResult();
    result->jobId = jobId;

    try {
        if (!m_engine || !m_engine->IsModelLoaded()) {
            result->success = false;
            result->error = "No model loaded";
        } else {
            std::string fullOutput;
            uint64_t tokenCount = 0;

            m_engine->GenerateStreaming(
                m_engine->Tokenize(input),
                maxTokens,
                [&fullOutput, &tokenCount](const std::string& token) {
                    fullOutput += token;
                    tokenCount++;
                },
                []() {},
                nullptr
            );

            result->success = true;
            result->output = fullOutput;
            recordTokensGenerated(tokenCount);
            m_totalInferencesRun.fetch_add(1, std::memory_order_relaxed);
        }
    } catch (const std::exception& e) {
        result->success = false;
        result->error = e.what();
        LOG_ERROR_FMT("[ModelOperationsBridge] Inference exception: %s", e.what());
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    result->durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    m_totalInferenceMs.fetch_add(result->durationMs, std::memory_order_relaxed);

    // Post result to UI thread
    PostMessage(m_hwndMain, WM_JOB_COMPLETE, (WPARAM)jobId, (LPARAM)result);
}

void ModelOperationsBridge::executeLoadModel(uint64_t jobId,
                                             const std::string& modelPath)
{
    auto startTime = std::chrono::high_resolution_clock::now();

    ModelJobResult* result = new ModelJobResult();
    result->jobId = jobId;

    try {
        if (!m_engine) {
            result->success = false;
            result->error = "No inference engine available";
        } else {
            bool loaded = m_engine->LoadModel(modelPath);
            if (loaded) {
                result->success = true;
                result->output = modelPath;
                result->metadata = json{{"model_path", modelPath}}.dump();
            } else {
                result->success = false;
                result->error = "Failed to load model: " + modelPath;
            }
        }
    } catch (const std::exception& e) {
        result->success = false;
        result->error = e.what();
        LOG_ERROR_FMT("[ModelOperationsBridge] Load model exception: %s", e.what());
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    result->durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    PostMessage(m_hwndMain, WM_JOB_COMPLETE, (WPARAM)jobId, (LPARAM)result);
}

void ModelOperationsBridge::executeBenchmark(uint64_t jobId,
                                              int warmupTokens,
                                              int testTokens)
{
    auto startTime = std::chrono::high_resolution_clock::now();

    ModelJobResult* result = new ModelJobResult();
    result->jobId = jobId;

    try {
        if (!m_engine || !m_engine->IsModelLoaded()) {
            result->success = false;
            result->error = "No model loaded for benchmark";
        } else {
            // Multi-iteration warmup for AVX-512 kernel frequency boost
            // Stage 1: Cold cache warmup (fills L3 cache)
            std::string warmupOutput1;
            m_engine->GenerateStreaming(
                m_engine->Tokenize("Warmup iteration 1"),
                warmupTokens,
                [&warmupOutput1](const std::string& token) { warmupOutput1 += token; },
                []() {},
                nullptr
            );

            // Stage 2: Hot cache warmup (triggers AVX-512 frequency boost)
            std::string warmupOutput2;
            m_engine->GenerateStreaming(
                m_engine->Tokenize("Warmup iteration 2"),
                warmupTokens,
                [&warmupOutput2](const std::string& token) { warmupOutput2 += token; },
                []() {},
                nullptr
            );

            // Stage 3: Frequency stabilization warmup
            std::string warmupOutput3;
            m_engine->GenerateStreaming(
                m_engine->Tokenize("Warmup iteration 3"),
                warmupTokens,
                [&warmupOutput3](const std::string& token) { warmupOutput3 += token; },
                []() {},
                nullptr
            );

            // Benchmark: Measured run
            auto benchStart = std::chrono::high_resolution_clock::now();
            std::string benchOutput;
            uint64_t actualTokens = 0;
            m_engine->GenerateStreaming(
                m_engine->Tokenize("Benchmark test"),
                testTokens,
                [&benchOutput, &actualTokens](const std::string& token) {
                    benchOutput += token;
                    actualTokens++;
                },
                []() {},
                nullptr
            );
            auto benchEnd = std::chrono::high_resolution_clock::now();

            double benchMs = std::chrono::duration<double, std::milli>(benchEnd - benchStart).count();
            double tps = (actualTokens * 1000.0) / benchMs;  // Use actual tokens for accuracy

            result->success = true;
            result->output = benchOutput;
            result->metadata = json{
                {"tokens_per_second", tps},
                {"latency_ms", benchMs},
                {"warmup_tokens", warmupTokens},
                {"warmup_iterations", 3},
                {"test_tokens", testTokens},
                {"actual_tokens", actualTokens}
            }.dump();

            recordTokensGenerated((warmupTokens * 3) + actualTokens);
            m_totalInferencesRun.fetch_add(4, std::memory_order_relaxed);  // 3 warmup + 1 benchmark
        }
    } catch (const std::exception& e) {
        result->success = false;
        result->error = e.what();
        LOG_ERROR_FMT("[ModelOperationsBridge] Benchmark exception: %s", e.what());
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    result->durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    m_totalInferenceMs.fetch_add(result->durationMs, std::memory_order_relaxed);

    PostMessage(m_hwndMain, WM_JOB_COMPLETE, (WPARAM)jobId, (LPARAM)result);
}

void ModelOperationsBridge::executeTokenize(uint64_t jobId,
                                            const std::string& text)
{
    auto startTime = std::chrono::high_resolution_clock::now();

    ModelJobResult* result = new ModelJobResult();
    result->jobId = jobId;

    try {
        if (!m_engine) {
            result->success = false;
            result->error = "No inference engine available";
        } else {
            auto tokens = m_engine->Tokenize(text);
            json tokenArray = json::array();
            for (int32_t token : tokens) {
                tokenArray.push_back(token);
            }
            result->success = true;
            result->output = tokenArray.dump();
        }
    } catch (const std::exception& e) {
        result->success = false;
        result->error = e.what();
        LOG_ERROR_FMT("[ModelOperationsBridge] Tokenize exception: %s", e.what());
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    result->durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    PostMessage(m_hwndMain, WM_JOB_COMPLETE, (WPARAM)jobId, (LPARAM)result);
}

void ModelOperationsBridge::executeDetokenize(uint64_t jobId,
                                               const std::vector<int32_t>& tokens)
{
    auto startTime = std::chrono::high_resolution_clock::now();

    ModelJobResult* result = new ModelJobResult();
    result->jobId = jobId;

    try {
        if (!m_engine) {
            result->success = false;
            result->error = "No inference engine available";
        } else {
            std::string text = m_engine->Detokenize(tokens);
            result->success = true;
            result->output = text;
        }
    } catch (const std::exception& e) {
        result->success = false;
        result->error = e.what();
        LOG_ERROR_FMT("[ModelOperationsBridge] Detokenize exception: %s", e.what());
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    result->durationMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    PostMessage(m_hwndMain, WM_JOB_COMPLETE, (WPARAM)jobId, (LPARAM)result);
}
