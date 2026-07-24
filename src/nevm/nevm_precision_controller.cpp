//============================================================================
// nevm_precision_controller.cpp
// RawrXD N-EVM Precision Controller - Implementation
//============================================================================

#include "nevm_precision_controller.hpp"
#include <limits>

namespace RawrXD {
namespace NEVM {

//============================================================================
// PrecisionController Implementation
//============================================================================

PrecisionController::Config PrecisionController::DefaultConfig() {
    Config config;
    config.target_decode_latency = 0.1f;      // 100us
    config.target_compute_latency = 1.0f;     // 1ms
    config.max_reconstruction_error = 0.01f;  // 1%
    config.min_acceptance_rate = 0.8f;        // 80%
    config.critical_memory_pressure = 0.95f;
    config.high_memory_pressure = 0.75f;
    config.low_memory_pressure = 0.5f;
    config.latency_weight = 1.0f;
    config.quality_weight = 2.0f;
    config.memory_weight = 1.0f;
    return config;
}

PrecisionController::PrecisionController(const Config& config) 
    : config_(config) {}

PrecisionController::~PrecisionController() {}

void PrecisionController::RecordDecode(const TelemetrySample& sample) {
    std::lock_guard<std::mutex> lock(mutex_);
    decode_history_.push_back(sample);
    TrimHistory();
}

void PrecisionController::RecordCompute(const TelemetrySample& sample) {
    std::lock_guard<std::mutex> lock(mutex_);
    compute_history_.push_back(sample);
    TrimHistory();
}

void PrecisionController::RecordAcceptance(float acceptance_rate) {
    std::lock_guard<std::mutex> lock(mutex_);
    acceptance_history_.push_back(acceptance_rate);
    TrimHistory();
}

PrecisionMode PrecisionController::SelectRepresentation(
    VirtualTensorAddress vta,
    const BlockState& current_state,
    float predicted_importance
) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Get current system state
    float memory_pressure = 0.0f;
    if (!decode_history_.empty()) {
        memory_pressure = decode_history_.back().memory_pressure;
    }
    
    float acceptance_rate = GetAverageAcceptance();
    
    // Determine candidate formats based on available representations
    std::vector<PrecisionMode> candidates;
    
    if (current_state.available_formats & (1 << static_cast<int>(PrecisionMode::FP32))) {
        candidates.push_back(PrecisionMode::FP32);
    }
    if (current_state.available_formats & (1 << static_cast<int>(PrecisionMode::FP16))) {
        candidates.push_back(PrecisionMode::FP16);
    }
    if (current_state.available_formats & (1 << static_cast<int>(PrecisionMode::Q8))) {
        candidates.push_back(PrecisionMode::Q8);
    }
    if (current_state.available_formats & (1 << static_cast<Int>(PrecisionMode::Q4))) {
        candidates.push_back(PrecisionMode::Q4);
    }
    if (current_state.available_formats & (1 << static_cast<int>(PrecisionMode::NANO_2BIT))) {
        candidates.push_back(PrecisionMode::NANO_2BIT);
    }
    if (current_state.available_formats & (1 << static_cast<int>(PrecisionMode::NANO_1BIT))) {
        candidates.push_back(PrecisionMode::NANO_1BIT);
    }
    
    // Always include current format
    if (std::find(candidates.begin(), candidates.end(), current_state.current_format) 
        == candidates.end()) {
        candidates.push_back(current_state.current_format);
    }
    
    // Score each candidate
    PrecisionMode best_format = current_state.current_format;
    float best_score = std::numeric_limits<float>::max();
    
    for (auto format : candidates) {
        float score = CalculateScore(format, current_state, predicted_importance);
        
        // Adjust based on memory pressure
        if (memory_pressure > config_.critical_memory_pressure) {
            // Prefer compressed formats
            if (format == PrecisionMode::NANO_1BIT || format == PrecisionMode::NANO_2BIT) {
                score *= 0.5f;
            } else if (format == PrecisionMode::FP32) {
                score *= 2.0f;
            }
        }
        
        // Adjust based on acceptance rate
        if (acceptance_rate < config_.min_acceptance_rate) {
            // Need higher precision
            if (format == PrecisionMode::FP32 || format == PrecisionMode::FP16) {
                score *= 0.7f;
            } else if (format == PrecisionMode::NANO_1BIT) {
                score *= 1.5f;
            }
        }
        
        if (score < best_score) {
            best_score = score;
            best_format = format;
        }
    }
    
    return best_format;
}

float PrecisionController::CalculateScore(
    PrecisionMode format,
    const BlockState& state,
    float importance
) const {
    float latency = EstimateLatency(format);
    float quality = EstimateQuality(format);
    float memory = EstimateMemory(format);
    
    // Weighted sum
    float score = 
        config_.latency_weight * latency +
        config_.quality_weight * (1.0f / (quality + 0.001f)) +
        config_.memory_weight * memory;
    
    // Adjust for importance
    if (importance > 0.8f) {
        // High importance: penalize quality loss more
        score *= (2.0f - quality);
    } else if (importance < 0.3f) {
        // Low importance: can tolerate more compression
        score *= 0.7f;
    }
    
    return score;
}

float PrecisionController::EstimateLatency(PrecisionMode format) const {
    switch (format) {
        case PrecisionMode::FP32: return 0.05f;
        case PrecisionMode::FP16: return 0.08f;
        case PrecisionMode::Q8: return 0.15f;
        case PrecisionMode::Q4: return 0.25f;
        case PrecisionMode::NANO_2BIT: return 0.35f;
        case PrecisionMode::NANO_1BIT: return 0.40f;
        default: return 0.5f;
    }
}

float PrecisionController::EstimateQuality(PrecisionMode format) const {
    switch (format) {
        case PrecisionMode::FP32: return 1.0f;
        case PrecisionMode::FP16: return 0.999f;
        case PrecisionMode::Q8: return 0.995f;
        case PrecisionMode::Q4: return 0.98f;
        case PrecisionMode::NANO_2BIT: return 0.92f;
        case PrecisionMode::NANO_1BIT: return 0.85f;
        default: return 0.8f;
    }
}

float PrecisionController::EstimateMemory(PrecisionMode format) const {
    switch (format) {
        case PrecisionMode::FP32: return 1.0f;
        case PrecisionMode::FP16: return 0.5f;
        case PrecisionMode::Q8: return 0.25f;
        case PrecisionMode::Q4: return 0.125f;
        case PrecisionMode::NANO_2BIT: return 0.0625f;
        case PrecisionMode::NANO_1BIT: return 0.03125f;
        default: return 1.0f;
    }
}

void PrecisionController::TrimHistory() {
    while (decode_history_.size() > MAX_HISTORY) {
        decode_history_.pop_front();
    }
    while (compute_history_.size() > MAX_HISTORY) {
        compute_history_.pop_front();
    }
    while (acceptance_history_.size() > MAX_HISTORY) {
        acceptance_history_.pop_front();
    }
}

float PrecisionController::GetAverageAcceptance() const {
    if (acceptance_history_.empty()) {
        return 1.0f;
    }
    
    float sum = 0.0f;
    for (float rate : acceptance_history_) {
        sum += rate;
    }
    return sum / acceptance_history_.size();
}

PrecisionController::SystemState PrecisionController::GetSystemState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    SystemState state = {};
    
    // Calculate averages
    if (!decode_history_.empty()) {
        float total_latency = 0.0f;
        float total_error = 0.0f;
        float total_memory = 0.0f;
        
        for (const auto& sample : decode_history_) {
            total_latency += sample.decode_latency_ms;
            total_error += sample.reconstruction_error;
            total_memory += sample.memory_pressure;
        }
        
        state.avg_decode_latency = total_latency / decode_history_.size();
        state.avg_reconstruction_error = total_error / decode_history_.size();
        state.memory_pressure = total_memory / decode_history_.size();
    }
    
    if (!compute_history_.empty()) {
        float total_compute = 0.0f;
        for (const auto& sample : compute_history_) {
            total_compute += sample.compute_latency_ms;
        }
        state.avg_compute_latency = total_compute / compute_history_.size();
    }
    
    state.recent_acceptance_rate = GetAverageAcceptance();
    state.samples_collected = decode_history_.size() + compute_history_.size();
    
    return state;
}

void PrecisionController::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    decode_history_.clear();
    compute_history_.clear();
    acceptance_history_.clear();
}

//============================================================================
// MultiStateBlock Implementation
//============================================================================

MultiStateBlock::MultiStateBlock(VirtualTensorAddress vta) : vta_(vta) {}

MultiStateBlock::~MultiStateBlock() {}

bool MultiStateBlock::AddState(PrecisionMode format, std::vector<uint8_t>&& data,
                                  float error, float latency) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    State state;
    state.format = format;
    state.data = std::move(data);
    state.reconstruction_error = error;
    state.decode_latency_ms = latency;
    state.memory_size = state.data.size();
    state.last_used = GetTickCount64();
    
    states_[format] = std::move(state);
    return true;
}

const MultiStateBlock::State* MultiStateBlock::SelectState(
    float max_error, float max_latency, size_t max_memory) const {
    
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    const State* best = nullptr;
    float best_score = std::numeric_limits<float>::max();
    
    for (const auto& [format, state] : states_) {
        // Check constraints
        if (state.reconstruction_error > max_error) continue;
        if (state.decode_latency_ms > max_latency) continue;
        if (state.memory_size > max_memory) continue;
        
        // Score: prefer lower memory, lower error
        float score = state.memory_size * 0.5f + state.reconstruction_error * 100.0f;
        
        if (score < best_score) {
            best_score = score;
            best = &state;
        }
    }
    
    return best;
}

const MultiStateBlock::State* MultiStateBlock::GetState(PrecisionMode format) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = states_.find(format);
    if (it != states_.end()) {
        return &it->second;
    }
    return nullptr;
}

size_t MultiStateBlock::EvictOldStates(uint64_t min_age) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    uint64_t current_tick = GetTickCount64();
    size_t freed = 0;
    
    for (auto it = states_.begin(); it != states_.end();) {
        if (current_tick - it->second.last_used > min_age) {
            freed += it->second.memory_size;
            it = states_.erase(it);
        } else {
            ++it;
        }
    }
    
    return freed;
}

size_t MultiStateBlock::GetTotalMemory() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& [format, state] : states_) {
        total += state.memory_size;
    }
    return total;
}

int MultiStateBlock::GetStateCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return static_cast<int>(states_.size());
}

} // namespace NEVM
} // namespace RawrXD
