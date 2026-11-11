// AggregateDecodeTypes.hpp — reverse-engineered from Deep2 SaturationResult /
// finished-token TPS contract (Deep2Benchmark.h AGGREGATE_DECODE_TPS).
#pragma once
#include <cstdint>
#include <string>

namespace rawr::aggdec {

enum class BackendKind : uint32_t {
    None = 0,
    Deep2Engine = 1,
    OllamaHttp = 2,
    CpuHonest = 3
};

struct SessionMetrics {
    uint32_t session_id = 0;
    uint64_t generated_tokens = 0;
    uint64_t wall_ns = 0;
    uint64_t first_token_ns = 0;
    double   tps = 0.0;
    bool     ok = false;
    BackendKind backend = BackendKind::None;
};

struct AggregateResult {
    uint32_t num_streams = 0;
    uint64_t total_tokens = 0;
    uint64_t wall_ns = 0;          // shared wall (concurrent) or session wall
    double   aggregate_tps = 0.0;  // total_tokens / wall_sec
    double   avg_stream_tps = 0.0;
    double   worst_stream_tps = 0.0;
    double   best_stream_tps = 0.0;
    double   fairness_ratio = 0.0; // worst/best
    double   worst_first_token_ms = 0.0;
    bool     all_sessions_worked = false;
    bool     concurrent = false;
    BackendKind backend = BackendKind::None;
    std::string model;
    std::string backend_label;
};

inline const char* BackendLabel(BackendKind k) {
    switch (k) {
    case BackendKind::Deep2Engine: return "DEEP2_ENGINE";
    case BackendKind::OllamaHttp:  return "OLLAMA_HTTP";
    case BackendKind::CpuHonest:   return "CPU_HONEST";
    default:                       return "NONE";
    }
}

} // namespace rawr::aggdec
