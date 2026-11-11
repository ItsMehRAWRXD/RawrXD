#include "AggregateDecodeMultiSession.hpp"
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

namespace rawr::aggdec {
namespace {
uint64_t now_ns() {
    using clock = std::chrono::steady_clock;
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               clock::now().time_since_epoch())
        .count();
}
} // namespace

AggregateDecodeMultiSession::AggregateDecodeMultiSession(
    IAggregateDecodeBackend* backend, uint32_t streams)
    : backend_(backend), streams_(streams ? streams : 1) {}

AggregateResult AggregateDecodeMultiSession::run(const std::string& prompt,
                                                 uint32_t max_tokens) {
    AggregateResult out{};
    out.num_streams = streams_;
    out.concurrent = true;
    if (!backend_) return out;
    if (!backend_->open()) return out;
    out.backend = backend_->kind();
    out.backend_label = backend_->label();
    out.model = backend_->model();

    std::vector<SessionMetrics> per(streams_);
    std::atomic<uint32_t> launched{0};
    std::atomic<uint32_t> gate{0};

    // Barrier: all threads start decode after N are ready → true overlap.
    std::vector<std::thread> threads;
    threads.reserve(streams_);
    for (uint32_t i = 0; i < streams_; ++i) {
        threads.emplace_back([&, i]() {
            launched.fetch_add(1, std::memory_order_acq_rel);
            while (launched.load(std::memory_order_acquire) < streams_)
                std::this_thread::yield();
            gate.fetch_add(1, std::memory_order_acq_rel);
            DecodeRequest req;
            req.session_id = i;
            req.prompt = prompt + " [stream " + std::to_string(i) + "]";
            req.max_tokens = max_tokens;
            per[i] = backend_->decode(req, [](uint32_t) { return true; });
        });
    }

    const uint64_t t0 = now_ns();
    for (auto& t : threads) t.join();
    const uint64_t t1 = now_ns();
    out.wall_ns = (t1 > t0) ? (t1 - t0) : 0;

    uint64_t sum_tok = 0;
    double sum_tps = 0.0;
    double best = 0.0;
    double worst = 1e300;
    double worst_ttft = 0.0;
    uint32_t ok_n = 0;
    for (const auto& m : per) {
        sum_tok += m.generated_tokens;
        const double tps = m.tps;
        sum_tps += tps;
        if (tps > best) best = tps;
        if (tps < worst) worst = tps;
        const double ttft = (double)m.first_token_ns / 1e6;
        if (ttft > worst_ttft) worst_ttft = ttft;
        if (m.ok && m.generated_tokens > 0) ++ok_n;
    }
    out.total_tokens = sum_tok;
    out.aggregate_tps =
        (out.wall_ns > 0) ? (double)sum_tok / ((double)out.wall_ns / 1e9) : 0.0;
    out.avg_stream_tps = (streams_ > 0) ? (sum_tps / (double)streams_) : 0.0;
    out.best_stream_tps = best;
    out.worst_stream_tps = (worst < 1e300) ? worst : 0.0;
    out.fairness_ratio = (best > 0.0) ? (out.worst_stream_tps / best) : 0.0;
    out.worst_first_token_ms = worst_ttft;
    out.all_sessions_worked = (ok_n == streams_);
    backend_->close();
    return out;
}

} // namespace rawr::aggdec
