#include "deep_iteration_engine.hpp"
#include <thread>
#include <mutex>
#include <queue>
#include <deque>
#include <algorithm>
#include <fstream>

namespace rawrxd::training {

class DeepIterationEngine::Impl {
public:
    mutable std::mutex mutex_;
    std::atomic<bool> training_{false};
    std::atomic<bool> paused_{false};
    IterationConfig config_;
    IterationState state_;
    std::deque<StepMetrics> history_;
    std::vector<std::vector<float>> batch_inputs_;
    std::vector<std::vector<float>> batch_labels_;
    size_t current_batch_idx_ = 0;
    DeepIterationEngine::StepCallback step_cb_;
    DeepIterationEngine::EvalCallback eval_cb_;
    DeepIterationEngine::CheckpointCallback checkpoint_cb_;
    float best_loss_ = std::numeric_limits<float>::max();
};

DeepIterationEngine::DeepIterationEngine() : impl_(std::make_unique<Impl>()) {}
DeepIterationEngine::~DeepIterationEngine() = default;

bool DeepIterationEngine::Configure(const IterationConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
    return true;
}

IterationConfig DeepIterationEngine::GetConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

bool DeepIterationEngine::Initialize() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->state_ = {};
    impl_->history_.clear();
    impl_->best_loss_ = std::numeric_limits<float>::max();
    return true;
}

bool DeepIterationEngine::LoadCheckpoint(const std::string& /*path*/) {
    return true;
}

bool DeepIterationEngine::SaveCheckpoint(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(&impl_->state_.current_step), sizeof(impl_->state_.current_step));
    ofs.write(reinterpret_cast<const char*>(&impl_->state_.current_epoch), sizeof(impl_->state_.current_epoch));
    ofs.write(reinterpret_cast<const char*>(&impl_->best_loss_), sizeof(impl_->best_loss_));
    return ofs.good();
}

void DeepIterationEngine::StartTraining() {
    impl_->training_.store(true);
    impl_->paused_.store(false);
}

void DeepIterationEngine::PauseTraining() {
    impl_->paused_.store(true);
}

void DeepIterationEngine::ResumeTraining() {
    impl_->paused_.store(false);
}

void DeepIterationEngine::StopTraining() {
    impl_->training_.store(false);
}

bool DeepIterationEngine::IsTraining() const {
    return impl_->training_.load();
}

bool DeepIterationEngine::IsPaused() const {
    return impl_->paused_.load();
}

IterationState DeepIterationEngine::GetState() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->state_;
}

void DeepIterationEngine::SetState(const IterationState& state) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->state_ = state;
}

bool DeepIterationEngine::RunSingleStep() {
    // RAWRXD_UNSIMULATE_001
    //
    // This previously reported a training step without performing one:
    //
    //     metrics.loss       = best_loss_ * 0.99f + 0.01f;   // "synthetic decay"
    //     metrics.perplexity = std::exp(metrics.loss);
    //     metrics.accuracy   = min(1.0f, step / max_steps);  // a progress-bar ratio
    //     metrics.grad_norm  = max_grad_norm * 0.5f;         // half a constant
    //     metrics.forward_time  = 10ms;                      // a literal
    //     metrics.backward_time = 20ms;                      // a literal
    //
    // No forward pass, no backward pass, no gradient. The loss decayed by
    // construction, so the one number a training loop exists to produce was
    // guaranteed to improve, and the timings were constants. Anything reading
    // this history was reading a curve drawn by arithmetic.
    //
    // There is no trainer wired to this engine, so a step cannot be performed.
    // The honest result is refusal plus a stated reason, and a step counter
    // that does not advance -- not a fabricated improvement.
    {
        std::lock_guard<std::mutex> lock(impl_->mutex_);
        std::fprintf(stderr,
            "[DEEP_ITER] RunSingleStep REFUSED: no forward/backward is "
            "implemented. Loss, perplexity, accuracy, grad_norm and step "
            "timings are NOT measured and are not reported. "
            "RAWRXD_UNSIMULATE_001\n");
        std::fflush(stderr);
    }
    return false;
}


StepMetrics DeepIterationEngine::GetLastStepMetrics() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->history_.empty()) return {};
    return impl_->history_.back();
}

bool DeepIterationEngine::SetBatchData(const std::vector<std::vector<float>>& inputs,
                                          const std::vector<std::vector<float>>& labels) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->batch_inputs_ = inputs;
    impl_->batch_labels_ = labels;
    impl_->current_batch_idx_ = 0;
    return true;
}

bool DeepIterationEngine::AdvanceBatch() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->batch_inputs_.empty()) return false;
    impl_->current_batch_idx_ = (impl_->current_batch_idx_ + 1) % impl_->batch_inputs_.size();
    return true;
}

size_t DeepIterationEngine::GetTotalBatches() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->batch_inputs_.size();
}

size_t DeepIterationEngine::GetCurrentBatchIndex() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->current_batch_idx_;
}

void DeepIterationEngine::SetStepCallback(StepCallback cb) {
    impl_->step_cb_ = std::move(cb);
}

void DeepIterationEngine::SetEvalCallback(EvalCallback cb) {
    impl_->eval_cb_ = std::move(cb);
}

void DeepIterationEngine::SetCheckpointCallback(CheckpointCallback cb) {
    impl_->checkpoint_cb_ = std::move(cb);
}

std::vector<StepMetrics> DeepIterationEngine::GetRecentMetrics(size_t count) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    size_t n = std::min(count, impl_->history_.size());
    return std::vector<StepMetrics>(impl_->history_.end() - n, impl_->history_.end());
}

float DeepIterationEngine::GetAverageLoss(size_t last_n_steps) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    if (impl_->history_.empty()) return 0.0f;
    size_t n = std::min(last_n_steps, impl_->history_.size());
    float sum = 0.0f;
    auto it = impl_->history_.end() - n;
    for (; it != impl_->history_.end(); ++it) sum += it->loss;
    return sum / n;
}

float DeepIterationEngine::GetBestLoss() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->best_loss_;
}

} // namespace rawrxd::training
