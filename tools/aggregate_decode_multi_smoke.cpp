// aggregate_decode_multi_smoke — >=2 concurrent sessions; true aggregate TPS.
#include "aggregate_decode/AggregateDecodeMultiSession.hpp"
#include "aggregate_decode/AggregateDecodeOllamaBackend.hpp"
#include "aggregate_decode/AggregateDecodeDeep2Backend.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

using namespace rawr::aggdec;

static const char* env_or(const char* k, const char* d) {
    const char* v = std::getenv(k);
    return (v && v[0]) ? v : d;
}

static bool env_truthy(const char* k) {
    const char* v = std::getenv(k);
    return v && v[0] && v[0] != '0';
}

int main(int argc, char** argv) {
    const char* host = env_or("AGGREGATE_DECODE_OLLAMA_HOST",
                              "http://127.0.0.1:11434");
    const char* model = env_or("AGGREGATE_DECODE_MODEL",
                               "n4-tiny-oracle:latest");
    const char* gguf = env_or("AGGREGATE_DECODE_GGUF", "");
    bool require_deep2 =
        env_truthy("AGGREGATE_DECODE_REQUIRE_DEEP2") ||
        env_truthy("AGGREGATE_DECODE_USE_DEEP2");
    uint32_t streams = 4;
    uint32_t max_tok = 12;
    for (int i = 1; i < argc; ++i) {
        if (!std::strcmp(argv[i], "--model") && i + 1 < argc) model = argv[++i];
        else if (!std::strcmp(argv[i], "--gguf") && i + 1 < argc) gguf = argv[++i];
        else if (!std::strcmp(argv[i], "--streams") && i + 1 < argc)
            streams = (uint32_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--tokens") && i + 1 < argc)
            max_tok = (uint32_t)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--require-deep2")) require_deep2 = true;
    }
    if (streams < 2) streams = 2;

    std::unique_ptr<IAggregateDecodeBackend> be;
    int deep2_runtime_reached = 0;
    if (gguf && gguf[0]) {
        auto* d2 = new AggregateDecodeDeep2Backend(gguf);
        std::printf("DEEP2_LINKED=%d\n", d2->linked() ? 1 : 0);
        if (d2->linked() && d2->open()) {
            be.reset(d2);
            std::printf("BACKEND=DEEP2\nBACKEND_LABEL=DEEP2_ENGINE\nMODEL=%s\n",
                        gguf);
        } else {
            const bool linked = d2->linked();
            delete d2;
            std::printf("DEEP2_OPEN_FAILED=1 LINKED=%d\n", linked ? 1 : 0);
            if (require_deep2 || linked) {
                std::printf("FALLBACK=REFUSED\n");
                std::printf("SOURCE_WIRED=1\nRUNTIME_REACHED=0\n");
                std::printf("deep2_runtime_reached=0\n");
                std::printf("GENERATED_TOKENS=0\nCERTIFIED=0\nPROMOTE=0\n");
                return 3;
            }
            std::printf("FALLBACK=OLLAMA_HTTP\n");
        }
    } else if (require_deep2) {
        std::printf("DEEP2_REQUIRED=1 GGUF_MISSING=1\n");
        std::printf("SOURCE_WIRED=1\nRUNTIME_REACHED=0\ndeep2_runtime_reached=0\n");
        std::printf("GENERATED_TOKENS=0\nCERTIFIED=0\nPROMOTE=0\n");
        return 3;
    }
    if (!be) {
        be.reset(new AggregateDecodeOllamaBackend(host, model));
        std::printf("BACKEND=OLLAMA_HTTP\nMODEL=%s\nHOST=%s\n", model, host);
    }

    AggregateDecodeMultiSession multi(be.get(), streams);
    AggregateResult r = multi.run(
        "Write one short production sentence about concurrent decode.",
        max_tok);

    if (r.backend == BackendKind::Deep2Engine && r.all_sessions_worked &&
        r.total_tokens > 0)
        deep2_runtime_reached = 1;

    std::printf("STREAMS=%u\n", r.num_streams);
    std::printf("CONCURRENT=%d\n", r.concurrent ? 1 : 0);
    std::printf("GENERATED_TOKENS=%llu\n",
                (unsigned long long)r.total_tokens);
    std::printf("WALL_NS=%llu\n", (unsigned long long)r.wall_ns);
    std::printf("AGGREGATE_DECODE_TPS_MULTI=%.6f\n", r.aggregate_tps);
    std::printf("AVG_STREAM_TPS=%.6f\n", r.avg_stream_tps);
    std::printf("WORST_STREAM_TPS=%.6f\n", r.worst_stream_tps);
    std::printf("BEST_STREAM_TPS=%.6f\n", r.best_stream_tps);
    std::printf("FAIRNESS_RATIO=%.6f\n", r.fairness_ratio);
    std::printf("WORST_FIRST_TOKEN_MS=%.3f\n", r.worst_first_token_ms);
    std::printf("ALL_SESSIONS_WORKED=%d\n", r.all_sessions_worked ? 1 : 0);
    std::printf("BOTH_LANES=%d\n",
                (r.num_streams >= 2 && r.all_sessions_worked) ? 1 : 0);
    const double max_per = r.best_stream_tps;
    std::printf("AGGREGATE_GE_MAX_STREAM=%d\n",
                (r.aggregate_tps + 1e-9 >= max_per) ? 1 : 0);
    if (r.aggregate_tps + 1e-9 < max_per) {
        std::printf("NOTE=aggregate_tps_uses_shared_wall_per_stream_tps_uses_own_wall\n");
    }
    std::printf("BACKEND_LABEL=%s\n", r.backend_label.c_str());
    std::printf("SOURCE_WIRED=1\n");
    std::printf("RUNTIME_REACHED=%d\n", r.all_sessions_worked ? 1 : 0);
    std::printf("deep2_runtime_reached=%d\n", deep2_runtime_reached);
    std::printf("CERTIFIED=0\nPROMOTE=0\nTIP_CLIMB=HOLD\n");
    if (require_deep2 && !deep2_runtime_reached) return 4;
    return r.all_sessions_worked ? 0 : 1;
}
