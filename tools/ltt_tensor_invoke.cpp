// LTT tensor invocation: direct in-process Deep2 graph execution.
// No HTTP server, Qt, or Ollama dependency.  This is intentionally a thin
// adapter over the production Universal ingest and RuntimeGraph Executor.
#include "deep2/modelgenie/universal_gguf.hpp"
#include "deep2/runtime_graph_executor.hpp"
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::RuntimeGraph::ExecutionContext;
using RawrXD::Deep2::RuntimeGraph::Executor;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: ltt_tensor_invoke <model.gguf> <token> [position] [device]\n";
        return 2;
    }
    char* end = nullptr;
    const auto token = std::strtoul(argv[2], &end, 10);
    if (!end || *end != '\0' || token > UINT32_MAX) return 2;
    const auto position = argc > 3 ? std::strtoull(argv[3], &end, 10) : 0;
    if (!end || *end != '\0') return 2;
    const auto device = argc > 4 ? std::strtoul(argv[4], &end, 10) : 0;
    if (!end || *end != '\0' || device > UINT32_MAX) return 2;

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

    if (!executor.ExecuteToken(static_cast<uint32_t>(token),
                               static_cast<size_t>(position), context)) {
        std::cerr << "LTT_EXECUTE_FAIL " << executor.LastError() << '\n';
        return 5;
    }
    std::cout << "LTT_EXECUTE_PASS model=" << report.spec.model_name
              << " arch=" << report.spec.architecture
              << " device=" << device
              << " position=" << position
              << " gpu_calls=" << executor.Stats().gpu_calls
              << " cpu_calls=" << executor.Stats().cpu_calls << '\n';
    return 0;
}
