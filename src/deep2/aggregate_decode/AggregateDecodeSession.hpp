// AggregateDecodeSession.hpp — single InferenceSession-style aggregate decode.
#pragma once
#include "IAggregateDecodeBackend.hpp"

namespace rawr::aggdec {

class AggregateDecodeSession {
public:
    explicit AggregateDecodeSession(IAggregateDecodeBackend* backend);
    AggregateDecodeSession(const AggregateDecodeSession&) = delete;
    AggregateDecodeSession& operator=(const AggregateDecodeSession&) = delete;

    bool open();
    void close();

    // Cold then optional warm; aggregate_tps = tokens/wall for this session.
    AggregateResult run(const DecodeRequest& req, bool do_warm = true);

private:
    IAggregateDecodeBackend* backend_ = nullptr;
    bool open_ = false;
};

} // namespace rawr::aggdec
