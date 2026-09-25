#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd::deep2 {

// ───────────────────────────────────────────────────────────────
// Model runtime state
// ───────────────────────────────────────────────────────────────
enum class RuntimeState {
    Uninitialized,
    Loading,
    Ready,
    Running,
    Paused,
    Error
};

struct RuntimeConfig {
    uint32_t batch_size = 1;
    uint32_t max_seq_len = 4096;
    uint32_t device_id = 0;
    bool use_fp16 = false;
    bool use_quantization = false;
    std::string quantization_mode = "none";
    float temperature = 0.8f;
    float top_p = 0.95f;
    uint32_t top_k = 50;
};

struct InferenceStats {
    float prefill_ms = 0.0f;
    float generation_ms = 0.0f;
    float tokens_per_second = 0.0f;
    uint64_t total_tokens = 0;
    uint64_t prompt_tokens = 0;
    uint64_t completion_tokens = 0;
};

// ───────────────────────────────────────────────────────────────
// Model runtime — loads and executes inference on a model
// ───────────────────────────────────────────────────────────────
class Deep2ModelRuntime {
public:
    using TokenCallback = std::function<void(uint32_t token_id, const std::string& token_text)>;
    using CompletionCallback = std::function<void(const std::string& full_text)>;

    Deep2ModelRuntime();
    ~Deep2ModelRuntime();

    // Lifecycle
    bool Initialize(const RuntimeConfig& config);
    void Shutdown();
    RuntimeState GetState() const;

    // Model loading
    bool LoadModel(const std::string& model_path);
    bool LoadModelFromBuffer(std::span<const uint8_t> data);
    bool IsModelLoaded() const;
    std::string GetModelInfo() const;

    // Inference
    std::string Generate(const std::string& prompt, size_t max_new_tokens = 256);
    std::vector<float> GenerateLogits(const std::string& prompt);
    bool GenerateAsync(const std::string& prompt, size_t max_new_tokens,
                       TokenCallback on_token, CompletionCallback on_done);

    // Streaming
    void SetTokenCallback(TokenCallback cb);
    void SetCompletionCallback(CompletionCallback cb);

    // Control
    bool Pause();
    bool Resume();
    bool Abort();

    // Stats
    InferenceStats GetLastStats() const;
    float GetAvgLatencyMs() const;
    float GetMemoryUsageMB() const;

    // KV cache
    void ClearKVCache();
    size_t GetKVCacheSizeBytes() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::deep2
