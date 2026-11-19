// LTT tensor invocation: direct in-process Deep2 graph execution.
// No HTTP server, Qt, or Ollama dependency.  This is intentionally a thin
// adapter over the production Universal ingest and RuntimeGraph Executor.
#include "deep2/modelgenie/universal_gguf.hpp"
#include "deep2/runtime_graph_executor.hpp"
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::RuntimeGraph::ExecutionContext;
using RawrXD::Deep2::RuntimeGraph::Executor;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: ltt_tensor_invoke <model.gguf> <token> [token...] [--position=N] [--device=N] [--repeat=N] [--cancel-before]\n";
        return 2;
    }
    char* end = nullptr;
    size_t position = 0;
    uint32_t device = 0;
    size_t repeat = 1;
    bool cancel_before = false;
    std::vector<uint32_t> tokens;
    for (int i = 2; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg.rfind("--position=", 0) == 0) {
            position = std::strtoull(arg.c_str() + 11, &end, 10);
            if (!end || *end != '\0') return 2;
        } else if (arg.rfind("--device=", 0) == 0) {
            const auto v = std::strtoul(arg.c_str() + 9, &end, 10);
            if (!end || *end != '\0' || v > UINT32_MAX) return 2;
            device = static_cast<uint32_t>(v);
        } else if (arg.rfind("--repeat=", 0) == 0) {
            repeat = std::strtoull(arg.c_str() + 9, &end, 10);
            if (!end || *end != '\0' || repeat == 0 || repeat > 1000) return 2;
        } else if (arg == "--cancel-before") {
            cancel_before = true;
        } else {
            const auto v = std::strtoul(arg.c_str(), &end, 10);
            if (!end || *end != '\0' || v > UINT32_MAX) return 2;
            tokens.push_back(static_cast<uint32_t>(v));
        }
    }
    if (tokens.empty()) return 2;

    const auto& report = Ingest(argv[1], false);
    if (!report.ok) {
        std::cerr << "LTT_INGEST_FAIL " << report.error << '\n';
        return 3;
    }
    Executor executor;
    if (!executor.Bind(report)) {
        std::cerr << "LTT_BIND_FAIL " << executor.Stats().error << '\n';
        if (!executor.FailureReceiptJson().empty())
            std::cerr << executor.FailureReceiptJson() << '\n';
        return 4;
    }

    auto cancel = std::make_shared<std::atomic_bool>(false);
    auto reserved = std::make_shared<std::atomic_size_t>(0);
    auto context = std::make_shared<ExecutionContext>();
    context->request_id = "ltt-direct";
    context->model_id = report.spec.model_name;
    context->device_index = static_cast<uint32_t>(device);
    context->cancel = cancel;
    context->reserved_memory_bytes = reserved;
    context->synchronization_ready = [] { return true; };
    context->memory_admission = [](size_t) { return true; };
    if (cancel_before) cancel->store(true, std::memory_order_release);

    for (size_t r = 0; r < repeat; ++r) {
      for (size_t i = 0; i < tokens.size(); ++i) {
        const size_t logical_position = position + r * tokens.size() + i;
        if (!executor.ExecuteToken(tokens[i], logical_position, context)) {
            std::cerr << "LTT_EXECUTE_FAIL token=" << tokens[i]
                      << " position=" << logical_position << ' '
                      << executor.LastError() << '\n';
            return cancel_before ? 6 : 5;
        }
        const auto& logits = executor.Logits();
        size_t top = 0;
        for (size_t j = 1; j < logits.size(); ++j)
            if (logits[j] > logits[top]) top = j;
        bool finite = true;
        for (float v : logits) finite = finite && std::isfinite(v);
        std::cout << "LTT_TOKEN_PASS index=" << i
                  << " repeat=" << r
                  << " position=" << logical_position
                  << " finite_logits=" << (finite ? 1 : 0)
                  << " top1=" << top
                  << " gpu_calls=" << executor.Stats().gpu_calls
                  << " cpu_calls=" << executor.Stats().cpu_calls << '\n';
      }
    }
    std::cout << "LTT_EXECUTE_PASS model=" << report.spec.model_name
              << " arch=" << report.spec.architecture
              << " device=" << device
              << " tokens=" << tokens.size() * repeat
              << " gpu_calls=" << executor.Stats().gpu_calls
              << " cpu_calls=" << executor.Stats().cpu_calls << '\n';
    return 0;
}
