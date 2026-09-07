// RKCCompiler.cpp — reverse goal compile (Deep2 local-exec + generic)
#include "RKCCompiler.hpp"
#include <algorithm>
#include <cctype>

namespace RawrXD {
namespace RKC {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

} // namespace

CompiledGoal CompileGoal(const std::string& query) {
    CompiledGoal g;
    const std::string q = lower(query);
    g.task = query;

    const bool localExec =
        (has(q, "deep2") || has(q, "local") || has(q, "gguf") || has(q, "model")) &&
        (has(q, "execut") || has(q, "run") || has(q, "generat") || has(q, "local") ||
         has(q, "can "));

    if (localExec || has(q, "entirely locally") || has(q, "model entirely")) {
        g.goalKey = "model_executable_locally";
        g.requiredKeys = {
            "model_exists",
            "model_format_supported",
            "all_required_shards_exist",
            "tokenizer_supported",
            "memory_plan_exists",
            "compute_backend_exists",
            "no_remote_dependency",
            "live_generation_path_exists",
            "model_complete",
            "local_generation_proven",
            "gpu_fit",
        };
        g.constraints = {
            "No globals for cancellation authority.",
            "Existing Deep2 ABI preserved.",
            "SYNTHETIC must not become REAL.",
        };
        return g;
    }

    if (has(q, "cancel")) {
        g.goalKey = "cancellation_path";
        g.requiredKeys = {
            "generate_stream_owns_request",
            "worker_owns_decode_loop",
            "worker_stop_exists",
            "edge_request_to_worker",
        };
        g.constraints = {"No process-wide cancellation.", "No globals."};
        return g;
    }

    // Generic: require only what world can already answer + task echo
    g.goalKey = "generic_query";
    g.requiredKeys = {"compute_backend_exists", "no_remote_dependency"};
    g.constraints = {"Prefer proof state over retrieved prose."};
    return g;
}

} // namespace RKC
} // namespace RawrXD
