#include "AggregateDecodeSession.hpp"
#include <chrono>

namespace rawr::aggdec {
namespace {
uint64_t now_ns() {
    using clock = std::chrono::steady_clock;
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               clock::now().time_since_epoch())
        .count();
}
} // namespace

AggregateDecodeSession::AggregateDecodeSession(IAggregateDecodeBackend* backend)
    : backend_(backend) {}

bool AggregateDecodeSession::open() {
    if (!backend_) return false;
    open_ = backend_->open();
    return open_;
}

void AggregateDecodeSession::close() {
    if (backend_ && open_) backend_->close();
    open_ = false;
}

AggregateResult AggregateDecodeSession::run(const DecodeRequest& req, bool do_warm) {
    AggregateResult out{};
    out.num_streams = 1;
    out.concurrent = false;
    if (!backend_ || !open_) return out;
    out.backend = backend_->kind();
    out.backend_label = backend_->label();
    out.model = backend_->model();

    if (do_warm) {
        DecodeRequest w = req;
        w.warm = true;
        w.max_tokens = (req.max_tokens > 4) ? 4u : req.max_tokens;
        (void)backend_->decode(w, [](uint32_t) { return true; });
    }

    const uint64_t t0 = now_ns();
    DecodeRequest cold = req;
    cold.warm = false;
    SessionMetrics m = backend_->decode(cold, [](uint32_t) { return true; });
    const uint64_t t1 = now_ns();

    out.total_tokens = m.generated_tokens;
    out.wall_ns = (m.wall_ns > 0) ? m.wall_ns : ((t1 > t0) ? (t1 - t0) : 0);
    out.aggregate_tps =
        (out.wall_ns > 0)
            ? (double)out.total_tokens / ((double)out.wall_ns / 1e9)
            : 0.0;
    out.avg_stream_tps = out.aggregate_tps;
    out.worst_stream_tps = out.aggregate_tps;
    out.best_stream_tps = out.aggregate_tps;
    out.fairness_ratio = 1.0;
    out.worst_first_token_ms = (double)m.first_token_ns / 1e6;
    out.all_sessions_worked = m.ok && out.total_tokens > 0;
    return out;
}

} // namespace rawr::aggdec
