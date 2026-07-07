// ============================================================================
// Win32IDE_ModelBridge_Integration.cpp — Win32 Message Loop Integration
// ============================================================================
// Integration snippet for Win32IDE_Core.cpp showing how to wire the
// ModelOperationsBridge into the Win32 message loop.
//
// This file should be merged into Win32IDE_Core.cpp or Win32IDE.cpp
// ============================================================================

// ============================================================================
// STEP 1: Add to Win32IDE class definition (Win32IDE.h)
// ============================================================================

/*
// In Win32IDE.h, add to private members:
private:
    std::unique_ptr<ModelOperationsBridge> m_modelBridge;

// In Win32IDE.h, add to public methods:
public:
    ModelOperationsBridge* GetModelBridge() { return m_modelBridge.get(); }
*/

// ============================================================================
// STEP 2: Initialize in Win32IDE::onCreate() or Win32IDE::Initialize()
// ============================================================================

/*
// In Win32IDE.cpp or Win32IDE_Core.cpp, after m_hwndMain is created:

#include "core/model_operations_bridge.hpp"

void Win32IDE::InitializeModelBridge()
{
    // Create the bridge with the main window handle
    m_modelBridge = std::make_unique<ModelOperationsBridge>(m_hwndMain, nullptr);
    
    if (!m_modelBridge->initialize()) {
        LOG_ERROR("[Win32IDE] Failed to initialize ModelOperationsBridge");
        return;
    }
    
    LOG_INFO("[Win32IDE] ModelOperationsBridge initialized successfully");
}
*/

// ============================================================================
// STEP 3: Handle WM_JOB_COMPLETE in message handler
// ============================================================================

/*
// In Win32IDE::handleMessage() or WindowProc():

#include "core/model_operations_bridge.hpp"

// Add case for WM_JOB_COMPLETE
LRESULT Win32IDE::handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
        case WM_JOB_COMPLETE: {
            uint64_t jobId = static_cast<uint64_t>(wParam);
            ModelJobResult* result = reinterpret_cast<ModelJobResult*>(lParam);
            
            if (result == nullptr) {
                LOG_ERROR("[Win32IDE] WM_JOB_COMPLETE received null result");
                return 0;
            }
            
            // Dispatch to registered callback
            if (m_modelBridge) {
                m_modelBridge->DispatchResult(jobId, result);
            } else {
                // Bridge not available, clean up
                LOG_ERROR("[Win32IDE] ModelBridge not available for job %llu", jobId);
                delete result;
            }
            
            return 0;
        }
        
        case WM_JOB_PROGRESS: {
            // Optional: Handle progress updates during long operations
            uint64_t jobId = static_cast<uint64_t>(wParam);
            double progress = static_cast<double>(lParam);
            
            // Update progress bar or status
            char buf[128];
            snprintf(buf, sizeof(buf), "Job %llu: %.1f%% complete", jobId, progress * 100.0);
            appendToOutput(buf, "Output", OutputSeverity::Info);
            
            return 0;
        }
        
        case WM_JOB_ERROR: {
            // Handle job errors
            uint64_t jobId = static_cast<uint64_t>(wParam);
            const char* error = reinterpret_cast<const char*>(lParam);
            
            char buf[256];
            snprintf(buf, sizeof(buf), "[ERROR] Job %llu failed: %s", jobId, error);
            appendToOutput(buf, "Output", OutputSeverity::Error);
            
            // Free the error string (allocated on worker thread)
            delete[] error;
            
            return 0;
        }
        
        // ... existing message handlers ...
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}
*/

// ============================================================================
// STEP 4: Cleanup in Win32IDE::onDestroy()
// ============================================================================

/*
void Win32IDE::onDestroy()
{
    // Shutdown the bridge first to cancel pending jobs
    if (m_modelBridge) {
        m_modelBridge->shutdown();
        m_modelBridge.reset();
    }
    
    // ... existing cleanup ...
    
    PostQuitMessage(0);
}
*/

// ============================================================================
// STEP 5: Example Usage in Context Visualizer or Chat Panel
// ============================================================================

/*
// Example: Wire a "Run Inference" button to async inference

void Win32IDE::OnRunInferenceClicked()
{
    if (!m_modelBridge || !m_modelBridge->IsModelLoaded()) {
        MessageBoxA(m_hwndMain, "No model loaded. Please load a model first.",
                    "Inference Error", MB_ICONERROR | MB_OK);
        return;
    }
    
    // Get input text from editor
    std::string input = getWindowText(m_hwndInputEdit);
    if (input.empty()) {
        MessageBoxA(m_hwndMain, "Please enter some text to process.",
                    "Inference Error", MB_ICONERROR | MB_OK);
        return;
    }
    
    // Queue async inference
    uint64_t jobId = m_modelBridge->QueueInference(
        input,
        512,  // max_tokens
        [this](const std::string& result, bool success, const std::string& error) {
            // This callback runs on the UI thread via WM_JOB_COMPLETE
            if (success) {
                // Display result in output panel
                appendToOutput(result, "Output", OutputSeverity::Info);
            } else {
                // Display error
                std::string errMsg = "[ERROR] " + error;
                appendToOutput(errMsg, "Output", OutputSeverity::Error);
            }
        }
    );
    
    if (jobId == 0) {
        appendToOutput("[ERROR] Failed to queue inference job", "Output", OutputSeverity::Error);
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "[INFO] Inference job %llu queued...", jobId);
        appendToOutput(buf, "Output", OutputSeverity::Info);
    }
}

// Example: Wire a "Benchmark Model" button

void Win32IDE::OnBenchmarkClicked()
{
    if (!m_modelBridge || !m_modelBridge->IsModelLoaded()) {
        MessageBoxA(m_hwndMain, "No model loaded. Please load a model first.",
                    "Benchmark Error", MB_ICONERROR | MB_OK);
        return;
    }
    
    // Queue async benchmark
    uint64_t jobId = m_modelBridge->QueueBenchmark(
        10,   // warmup_tokens
        100,  // test_tokens
        [this](double tokensPerSecond, double latencyMs, bool success) {
            // This callback runs on the UI thread
            if (success) {
                char buf[256];
                snprintf(buf, sizeof(buf), 
                         "[BENCHMARK] %.2f tokens/sec, latency: %.2f ms",
                         tokensPerSecond, latencyMs);
                appendToOutput(buf, "Output", OutputSeverity::Info);
            } else {
                appendToOutput("[ERROR] Benchmark failed", "Output", OutputSeverity::Error);
            }
        }
    );
    
    if (jobId == 0) {
        appendToOutput("[ERROR] Failed to queue benchmark job", "Output", OutputSeverity::Error);
    } else {
        appendToOutput("[INFO] Benchmark started...", "Output", OutputSeverity::Info);
    }
}

// Example: Wire a "Load Model" button

void Win32IDE::OnLoadModelClicked()
{
    // Show file open dialog
    char filePath[MAX_PATH] = {0};
    OPENFILENAMEA ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFilter = "GGUF Model Files (*.gguf)\0*.gguf\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    
    if (!GetOpenFileNameA(&ofn)) {
        return;  // User cancelled
    }
    
    // Queue async model load
    uint64_t jobId = m_modelBridge->QueueLoadModel(
        filePath,
        [this, filePath](const ModelJobResult& result) {
            // This callback runs on the UI thread
            if (result.success) {
                char buf[512];
                snprintf(buf, sizeof(buf), 
                         "[SUCCESS] Model loaded: %s (%.2f ms)",
                         filePath, result.durationMs);
                appendToOutput(buf, "Output", OutputSeverity::Info);
                
                // Update UI to show model is loaded
                UpdateModelStatus();
            } else {
                char buf[512];
                snprintf(buf, sizeof(buf), 
                         "[ERROR] Failed to load model: %s",
                         result.error.c_str());
                appendToOutput(buf, "Output", OutputSeverity::Error);
            }
        }
    );
    
    if (jobId == 0) {
        appendToOutput("[ERROR] Failed to queue load model job", "Output", OutputSeverity::Error);
    } else {
        char buf[256];
        snprintf(buf, sizeof(buf), "[INFO] Loading model: %s", filePath);
        appendToOutput(buf, "Output", OutputSeverity::Info);
    }
}
*/

// ============================================================================
// STEP 6: Wire to ToolRegistry for P0 Tools
// ============================================================================

/*
// In Win32IDE::InitializeToolRegistry() or similar:

void Win32IDE::WireP0ModelTools()
{
    // Get or create ToolRegistry
    auto registry = ToolRegistry::instance();
    
    // Wire RUN_INFERENCE tool
    ToolDefinition runInference;
    runInference.metadata.name = "RUN_INFERENCE";
    runInference.metadata.description = "Run inference on loaded model";
    runInference.metadata.category = "Model Operations";
    runInference.metadata.arguments = {
        {"input", "Input text to process", true, ToolArgType::STRING},
        {"max_tokens", "Maximum tokens to generate", false, ToolArgType::INTEGER}
    };
    
    runInference.executor = [this](const std::map<std::string, std::string>& args, 
                                    const ToolContext& ctx) -> ToolResult {
        std::string input = args.count("input") ? args.at("input") : "";
        int maxTokens = args.count("max_tokens") ? std::stoi(args.at("max_tokens")) : 512;
        
        // Use synchronous wrapper for tool execution
        std::promise<ToolResult> promise;
        auto future = promise.get_future();
        
        uint64_t jobId = m_modelBridge->QueueInference(
            input, maxTokens,
            [&promise](const std::string& result, bool success, const std::string& error) {
                ToolResult tr;
                tr.success = success;
                tr.output = result;
                tr.error = error;
                promise.set_value(std::move(tr));
            }
        );
        
        if (jobId == 0) {
            ToolResult tr;
            tr.success = false;
            tr.error = "Failed to queue inference job";
            return tr;
        }
        
        // Wait for completion (with timeout)
        auto status = future.wait_for(std::chrono::seconds(60));
        if (status == std::future_status::timeout) {
            m_modelBridge->CancelJob(jobId);
            ToolResult tr;
            tr.success = false;
            tr.error = "Inference timed out";
            return tr;
        }
        
        return future.get();
    };
    
    registry->registerTool(runInference);
    
    // Wire BENCHMARK_MODEL tool
    ToolDefinition benchmark;
    benchmark.metadata.name = "BENCHMARK_MODEL";
    benchmark.metadata.description = "Benchmark loaded model performance";
    benchmark.metadata.category = "Model Operations";
    
    benchmark.executor = [this](const std::map<std::string, std::string>& args,
                                 const ToolContext& ctx) -> ToolResult {
        std::promise<ToolResult> promise;
        auto future = promise.get_future();
        
        uint64_t jobId = m_modelBridge->QueueBenchmark(
            10, 100,
            [&promise](double tps, double latency, bool success) {
                ToolResult tr;
                tr.success = success;
                if (success) {
                    json result;
                    result["tokens_per_second"] = tps;
                    result["latency_ms"] = latency;
                    tr.output = result.dump();
                } else {
                    tr.error = "Benchmark failed";
                }
                promise.set_value(std::move(tr));
            }
        );
        
        if (jobId == 0) {
            ToolResult tr;
            tr.success = false;
            tr.error = "Failed to queue benchmark job";
            return tr;
        }
        
        auto status = future.wait_for(std::chrono::seconds(30));
        if (status == std::future_status::timeout) {
            m_modelBridge->CancelJob(jobId);
            ToolResult tr;
            tr.success = false;
            tr.error = "Benchmark timed out";
            return tr;
        }
        
        return future.get();
    };
    
    registry->registerTool(benchmark);
    
    // Wire remaining P0 tools similarly...
}
*/

// ============================================================================
// VALIDATION CHECKLIST
// ============================================================================

/*
✅ 1. ModelOperationsBridge created with ThreadPool integration
✅ 2. WM_JOB_COMPLETE message defined
✅ 3. handleMessage() dispatches to bridge callbacks
✅ 4. Bridge initialized in Win32IDE::Initialize()
✅ 5. Bridge shutdown in Win32IDE::onDestroy()
✅ 6. Example button handlers for inference/benchmark/load
✅ 7. ToolRegistry wiring for P0 tools
✅ 8. Memory safety: heap-allocated results deleted in DispatchResult()
✅ 9. Thread safety: callbacks protected by mutex
✅ 10. Statistics tracking for performance monitoring

NEXT STEPS:
1. Merge this integration into Win32IDE_Core.cpp
2. Add menu items for "Run Inference", "Benchmark Model", "Load Model"
3. Wire remaining P0 tools (TOKENIZE_TEXT, DETOKENIZE_TOKENS, etc.)
4. Add progress indicators for long-running operations
5. Implement cancellation UI for pending jobs
*/