// AggregateDecodeMultiSession.hpp — N concurrent decode streams (not serial).
#pragma once
#include "IAggregateDecodeBackend.hpp"
#include <vector>

namespace rawr::aggdec {

class AggregateDecodeMultiSession {
public:
    AggregateDecodeMultiSession(IAggregateDecodeBackend* backend, uint32_t streams);

    // True concurrent wall: aggregate_tps = sum(tokens) / shared_wall.
    AggregateResult run(const std::string& prompt, uint32_t max_tokens);

private:
    IAggregateDecodeBackend* backend_ = nullptr;
    uint32_t streams_ = 0;
};

} // namespace rawr::aggdec
