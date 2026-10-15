#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include "agent_esp.hpp"
#ifdef HAVE_DEEP2_ENGINE
#include "Deep2Engine.h"
#endif

// Forward declarations
class Win32IDE;
namespace Deep2 { class Deep2Engine; }

// Deep2 Bridge response types
enum class Deep2ResponseType {
    TOKEN,
    TOOL_CALL,
    ANSWER,
    DEEP2_ERROR,
    COMPLETE
};

struct Deep2Response {
    Deep2ResponseType type;
    std::string content;
    std::string toolName;
    std::string toolArgs;
    bool finished = false;
    bool error = false;
    std::string errorMessage;
};

// Deep2 Inference Bridge for Win32IDE
// Connects IDE directly to Deep2Engine for GPU-accelerated inference
class Deep2Bridge {
public:
    Deep2Bridge(Win32IDE* ide);
    ~Deep2Bridge();

    // Core operations
    bool Initialize(const std::string& modelPath = "");
    bool IsInitialized() const { return m_initialized; }
    bool IsModelLoaded() const;

    // Execute inference with streaming callback
    // callback(token, isComplete) - return false to cancel
    bool GenerateStream(const std::string& prompt,
                        std::function<bool(const std::string& token, bool isComplete)> callback,
                        int maxTokens = 2048,
                        float temperature = 0.7f,
                        float topP = 0.9f,
                        int topK = 40);

    // Synchronous generation (blocking)
    std::string GenerateSync(const std::string& prompt, int maxTokens = 512);

    // Control
    void Cancel();
    void Stop();

    // Model management
    bool LoadModel(const std::string& modelPath);
    void UnloadModel();
    std::string GetCurrentModel() const { return m_modelPath; }
    std::string GetModelInfo() const;

    // Configuration
    void SetGenerationConfig(int maxTokens, float temperature, float topP, int topK);
    
    // Output callback
    using OutputCallback = std::function<void(const std::string&, const std::string&)>;
    void SetOutputCallback(OutputCallback callback);
    
    // ESP Telemetry
    void SetESPBus(rawrxd::esp::Bus* bus, uint64_t requestId);
    
    // Status
    std::string GetStatus() const;
    double GetTokensPerSecond() const;
    size_t GetContextLength() const;

private:
    // Generation worker thread
    void GenerationWorker(const std::string& prompt, int maxTokens);
    
    // Token callback from Deep2Engine
    bool OnTokenCallback(int32_t tokenId, const std::string& token);
    
    // Completion callback
    void OnGenerationComplete(bool cancelled = false);

    Win32IDE* m_ide = nullptr;
#ifdef HAVE_DEEP2_ENGINE
    Deep2::Deep2Engine* m_engine = nullptr;
#else
    RawrXD::CPUInferenceEngine* m_cpuEngine = nullptr;
#endif
    
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_generating{false};
    std::atomic<bool> m_cancelRequested{false};
    std::atomic<bool> m_stopRequested{false};
    
    std::string m_modelPath;
    std::thread m_generationThread;
    std::mutex m_callbackMutex;
    
    std::function<bool(const std::string&, bool)> m_tokenCallback;
    OutputCallback m_outputCallback;
    
    // Generation config
    int m_maxTokens = 2048;
    float m_temperature = 0.7f;
    float m_topP = 0.9f;
    int m_topK = 40;
    
    // Streaming state
    std::string m_accumulatedResponse;
    bool m_generationComplete = false;
    
    // ESP Telemetry
    rawrxd::esp::Bus* m_espBus = nullptr;
    uint64_t m_espRequestId = 0;
};