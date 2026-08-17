#pragma once
#include <chrono>
#include <cstdint>
#include <mutex>
namespace RawrXD::Governance {enum class EnsembleResult:uint8_t{Continue,Deadline,TokenBudget,Cancelled};class Ensemble58Governor{public:static constexpr std::chrono::milliseconds kDeadline{5800};explicit Ensemble58Governor(uint32_t max_submodels=4,uint64_t max_tokens=4096);void begin();EnsembleResult checkpoint(uint64_t);void cancel();bool active()const noexcept;uint32_t max_submodels()const noexcept;private:mutable std::mutex mu_;std::chrono::steady_clock::time_point start_{};uint64_t max_tokens_;uint32_t max_submodels_;bool active_=false,cancelled_=false;};}
