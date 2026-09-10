#pragma once
// ReadbackBoundaryPolicy — host may observe only when host owns next step.
#include <cstdint>

namespace rawrxd::runtime {

enum class NextConsumer : uint8_t {
    Device = 0,
    HostRequiredMath = 1,
    Logging = 2,
    Metrics = 3,
    Unknown = 4
};

enum class ReadbackDecision : uint8_t {
    Allow = 0,
    AllowMinimal = 1,
    Block = 2,
    FailClosed = 3
};

inline ReadbackDecision DecideReadback(NextConsumer next) noexcept {
    switch (next) {
    case NextConsumer::HostRequiredMath: return ReadbackDecision::AllowMinimal;
    case NextConsumer::Logging:
    case NextConsumer::Metrics: return ReadbackDecision::Block;
    case NextConsumer::Device: return ReadbackDecision::Block;
    default: return ReadbackDecision::FailClosed;
    }
}

inline bool D2hLegalForHostMath(NextConsumer next) noexcept {
    return DecideReadback(next) == ReadbackDecision::AllowMinimal;
}

} // namespace rawrxd::runtime
