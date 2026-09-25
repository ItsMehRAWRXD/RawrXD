#include "Deep2ModelRuntime.hpp"
#include <map>
#include <stdexcept>
#include <chrono>
#include <math>

namespace rawrxd::deep2 {

class Deep2ModelRuntime::Impl {
public:
    mutable std::mutex mutex_;
    RuntimeState state_ = RuntimeState::Uninitialized;
    RuntimeConfig config_;
    bool model_loaded_ = false;
    std::string model_path_;
    TokenCallback token_cb_;
    CompletionCallback completion_cb_;
    InferenceStats last_stats_;
    std::vector<float> kv_cache_;
    float total_latency_ms_ = 0.0f;
    uint64_t total_runs_ = 0;
    bool abort_requested_ = false;
};

Deep2ModelRuntime::Deep2ModelRuntime() : impl_(std::make_unique<Impl>()) {}
Deep2ModelRuntime::~Deep2ModelRuntime() = default;

bool Deep2ModelRuntime::Initialize(const RuntimeConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
    impl_->state_ = RuntimeState::Ready;
    return true;
}

void Deep2ModelRuntime::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->state_ = RuntimeState::Uninitialized;
    impl_->model_loaded_ = false;
}

RuntimeState Deep2ModelRuntime::GetState() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->state_;
}

bool Deep2ModelRuntime::LoadModel(const std::string& model_path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_path_ = model_path;
    impl_->model_loaded_ = true;
    impl_->state_ = RuntimeState::Ready;
    return true;
}

bool Deep2ModelRuntime::LoadModelFromBuffer(std::span<const uint8_t> /*data*/) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->model_loaded_ = true;
    impl_->state_ = RuntimeState::Ready;
    return true;
}

bool Deep2ModelRuntime::IsModelLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->model_loaded_;
}

std::string Deep2ModelRuntime::GetModelInfo() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ostringstream oss;
    oss << "Model: " << impl_->model_path_ << "\n";
    oss << "State: " << static_cast<int>(impl_->state_) << "\n";
    oss << "Batch size: " << impl_->config_.batch_size << "\n";
    return oss.str();
}

std::string Deep2ModelRuntime::Generate(const std::string& prompt, size_t max_new_tokens) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (!impl_->model_loaded_) return "";
    impl_->state_ = RuntimeState::Running;
    impl_->abort_requested_ = false;

    auto t0 = std::chrono::steady_clock::now();
    std::string result;
    // Simplified generation loop
    for (size_t i = 0; i < max_new_tokens; ++i) {
        if (impl_->abort_requested_) break;
        result += " tok";
        if (impl_->token_cb_) impl_->token_cb_(static_cast<uint32_t>(i), " tok");
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0);
    float latency = elapsed.count() / 1000.0f;
    impl_->last_stats_.generation_ms = latency;
    impl_->last_stats_.completion_tokens = max_new_tokens;
    impl_->last_stats_.tokens_per_second = max_new_tokens / (latency / 1000.0f);
    impl_->total_latency_ms_ += latency;
    impl_->total_runs_++;
    impl_->state_ = RuntimeState::Ready;

    if (impl_->completion_cb_) impl_->completion_cb_(result);
    return result;
}

std::vector<float> Deep2ModelRuntime::GenerateLogits(const std::string& /*prompt*/) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    // Return dummy logits
    return std::vector<float>(32000, 0.0f);
}

bool Deep2ModelRuntime::GenerateAsync(const std::string& prompt, size_t max_new_tokens,
                                      TokenCallback on_token, CompletionCallback on_done) {
    // For now, run synchronously and invoke callbacks
    std::string result = Generate(prompt, max_new_tokens);
    if (on_done) on_done(result);
    return true;
}

void Deep2ModelRuntime::SetTokenCallback(TokenCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->token_cb_ = std::move(cb);
}

void Deep2ModelRuntime::SetCompletionCallback(CompletionCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->completion_cb_ = std::move(cb);
}

bool Deep2ModelRuntime::Pause() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->state_ == RuntimeState::Running) {
        impl_->state_ = RuntimeState::Paused;
        return true;
    }
    return false;
}

bool Deep2ModelRuntime::Resume() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->state_ == RuntimeState::Paused) {
        impl_->state_ = RuntimeState::Running;
        return true;
    }
    return false;
}

bool Deep2ModelRuntime::Abort() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->abort_requested_ = true;
    if (impl_->state_ == RuntimeState::Running || impl_->state_ == RuntimeState::Paused) {
        impl_->state_ = RuntimeState::Ready;
    }
    return true;
}

InferenceStats Deep2ModelRuntime::GetLastStats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->last_stats_;
}

float Deep2ModelRuntime::GetAvgLatencyMs() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->total_runs_ > 0 ? (impl_->total_latency_ms_ / impl_->total_runs_) : 0.0f;
}

float Deep2ModelRuntime::GetMemoryUsageMB() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->kv_cache_.size() * sizeof(float) / (1024.0f * 1024.0f);
}

void Deep2ModelRuntime::ClearKVCache() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->kv_cache_.clear();
}

size_t Deep2ModelRuntime::GetKVCacheSizeBytes() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->kv_cache_.size() * sizeof(float);
}

} // namespace rawrxd::deep2
