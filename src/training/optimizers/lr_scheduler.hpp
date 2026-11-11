#pragma once

#include "../training_config.hpp"
#include <math>

namespace rawrxd::training {

// Base LR scheduler
class LRScheduler {
public:
    explicit LRScheduler(float initial_lr) : initial_lr_(initial_lr), current_lr_(initial_lr) {}
    virtual ~LRScheduler() = default;

    virtual float getLR(uint64_t step) = 0;
    float getCurrentLR() const { return current_lr_; }

protected:
    float initial_lr_;
    float current_lr_;
};

// Constant scheduler
class ConstantScheduler : public LRScheduler {
public:
    explicit ConstantScheduler(float initial_lr) : LRScheduler(initial_lr) {}

    float getLR(uint64_t step) override {
        current_lr_ = initial_lr_;
        return current_lr_;
    }
};

// Linear decay scheduler
class LinearScheduler : public LRScheduler {
public:
    LinearScheduler(float initial_lr, uint64_t total_steps, float min_lr = 0.0f)
        : LRScheduler(initial_lr), total_steps_(total_steps), min_lr_(min_lr) {}

    float getLR(uint64_t step) override {
        if (step >= total_steps_) {
            current_lr_ = min_lr_;
        } else {
            float decay = static_cast<float>(step) / total_steps_;
            current_lr_ = initial_lr_ - (initial_lr_ - min_lr_) * decay;
        }
        return current_lr_;
    }

private:
    uint64_t total_steps_;
    float min_lr_;
};

// Cosine annealing scheduler
class CosineScheduler : public LRScheduler {
public:
    CosineScheduler(float initial_lr, uint64_t total_steps, float min_lr = 0.0f)
        : LRScheduler(initial_lr), total_steps_(total_steps), min_lr_(min_lr) {}

    float getLR(uint64_t step) override {
        if (step >= total_steps_) {
            current_lr_ = min_lr_;
        } else {
            float progress = static_cast<float>(step) / total_steps_;
            current_lr_ = min_lr_ + (initial_lr_ - min_lr_) *
                         0.5f * (1.0f + std::cos(progress * M_PI));
        }
        return current_lr_;
    }

private:
    uint64_t total_steps_;
    float min_lr_;
};

// Cosine with restarts
class CosineWithRestartsScheduler : public LRScheduler {
public:
    CosineWithRestartsScheduler(float initial_lr, uint64_t period, int num_cycles = 1)
        : LRScheduler(initial_lr), period_(period), num_cycles_(num_cycles) {}

    float getLR(uint64_t step) override {
        int cycle = static_cast<int>(step / period_);
        if (cycle >= num_cycles_) {
            current_lr_ = 0.0f;
        } else {
            float progress = static_cast<float>(step % period_) / period_;
            current_lr_ = initial_lr_ * 0.5f * (1.0f + std::cos(progress * M_PI));
        }
        return current_lr_;
    }

private:
    uint64_t period_;
    int num_cycles_;
};

// Polynomial decay
class PolynomialScheduler : public LRScheduler {
public:
    PolynomialScheduler(float initial_lr, uint64_t total_steps, float power = 1.0f)
        : LRScheduler(initial_lr), total_steps_(total_steps), power_(power) {}

    float getLR(uint64_t step) override {
        if (step >= total_steps_) {
            current_lr_ = 0.0f;
        } else {
            float progress = static_cast<float>(step) / total_steps_;
            current_lr_ = initial_lr_ * std::pow(1.0f - progress, power_);
        }
        return current_lr_;
    }

private:
    uint64_t total_steps_;
    float power_;
};

// Inverse square root
class InverseSqrtScheduler : public LRScheduler {
public:
    InverseSqrtScheduler(float initial_lr, uint64_t warmup_steps)
        : LRScheduler(initial_lr), warmup_steps_(warmup_steps) {}

    float getLR(uint64_t step) override {
        if (step < warmup_steps_) {
            current_lr_ = initial_lr_ * static_cast<float>(step) / warmup_steps_;
        } else {
            float decay = std::sqrt(static_cast<float>(warmup_steps_) / step);
            current_lr_ = initial_lr_ * decay;
        }
        return current_lr_;
    }

private:
    uint64_t warmup_steps_;
};

// Warmup + Linear
class WarmupLinearScheduler : public LRScheduler {
public:
    WarmupLinearScheduler(float initial_lr, uint64_t warmup_steps, uint64_t total_steps)
        : LRScheduler(initial_lr), warmup_steps_(warmup_steps), total_steps_(total_steps) {}

    float getLR(uint64_t step) override {
        if (step < warmup_steps_) {
            current_lr_ = initial_lr_ * static_cast<float>(step) / warmup_steps_;
        } else if (step >= total_steps_) {
            current_lr_ = 0.0f;
        } else {
            float progress = static_cast<float>(step - warmup_steps_) /
                            (total_steps_ - warmup_steps_);
            current_lr_ = initial_lr_ * (1.0f - progress);
        }
        return current_lr_;
    }

private:
    uint64_t warmup_steps_;
    uint64_t total_steps_;
};

// Warmup + Cosine
class WarmupCosineScheduler : public LRScheduler {
public:
    WarmupCosineScheduler(float initial_lr, uint64_t warmup_steps, uint64_t total_steps)
        : LRScheduler(initial_lr), warmup_steps_(warmup_steps), total_steps_(total_steps) {}

    float getLR(uint64_t step) override {
        if (step < warmup_steps_) {
            current_lr_ = initial_lr_ * static_cast<float>(step) / warmup_steps_;
        } else if (step >= total_steps_) {
            current_lr_ = 0.0f;
        } else {
            float progress = static_cast<float>(step - warmup_steps_) /
                            (total_steps_ - warmup_steps_);
            current_lr_ = initial_lr_ * 0.5f * (1.0f + std::cos(progress * M_PI));
        }
        return current_lr_;
    }

private:
    uint64_t warmup_steps_;
    uint64_t total_steps_;
};

// Factory
inline std::unique_ptr<LRScheduler> createScheduler(LRSchedulerType type,
                                                       float initial_lr,
                                                       uint64_t warmup_steps = 0,
                                                       uint64_t total_steps = 0) {
    switch (type) {
        case LRSchedulerType::CONSTANT:
            return std::make_unique<ConstantScheduler>(initial_lr);
        case LRSchedulerType::LINEAR:
            return std::make_unique<LinearScheduler>(initial_lr, total_steps);
        case LRSchedulerType::COSINE:
            return std::make_unique<CosineScheduler>(initial_lr, total_steps);
        case LRSchedulerType::COSINE_WITH_RESTARTS:
            return std::make_unique<CosineWithRestartsScheduler>(initial_lr, total_steps / 4);
        case LRSchedulerType::POLYNOMIAL:
            return std::make_unique<PolynomialScheduler>(initial_lr, total_steps);
        case LRSchedulerType::INVERSE_SQRT:
            return std::make_unique<InverseSqrtScheduler>(initial_lr, warmup_steps);
        case LRSchedulerType::WARMUP_LINEAR:
            return std::make_unique<WarmupLinearScheduler>(initial_lr, warmup_steps, total_steps);
        case LRSchedulerType::WARMUP_COSINE:
            return std::make_unique<WarmupCosineScheduler>(initial_lr, warmup_steps, total_steps);
        default:
            return std::make_unique<ConstantScheduler>(initial_lr);
    }
}

} // namespace rawrxd::training
