#include "seg_runtime.hpp"
#include "../runtime/streaming_gguf_loader.hpp"

namespace seg {

bool Runtime::Initialize(const RuntimeConfig& cfg) {
    RawrXD::Runtime::StreamingGGUFLoader loader;
    if (!loader.Open(cfg.model_path)) return false;
    if (!m_backend.Initialize(loader)) return false;

    // Bind logits buffer
    m_memory.Bind(MemoryRegion::kLogits,
                  m_backend.GetLogitsBuffer(),
                  m_backend.GetLogitsBytes());

    // Simple forward graph: input -> logits
    auto n_input  = m_graph.AddNode(NodeKind::kInputToken, "input_token");
    auto n_logits = m_graph.AddNode(NodeKind::kLogits, "logits");
    m_graph.AddEdge(n_input, n_logits);

    m_scheduler.SetMode(ScheduleMode::kSequential);

    AgentConfig acfg;
    acfg.enable_telemetry = true;
    m_agent.Initialize(acfg);

    return true;
}

bool Runtime::Generate(const std::vector<int>& tokens_in,
                       std::vector<int>& tokens_out,
                       uint32_t max_new_tokens) {
    Executor exec(m_memory, m_backend);

    uint32_t pos = static_cast<uint32_t>(tokens_in.size());
    uint32_t last = tokens_in.empty() ? 0 : tokens_in.back();

    // Prime KV cache with prompt
    for (size_t i = 0; i < tokens_in.size(); ++i) {
        exec.Run(m_graph, tokens_in[i], static_cast<uint32_t>(i));
    }

    for (uint32_t i = 0; i < max_new_tokens; ++i) {
        exec.Run(m_graph, last, pos);

        auto logitsBuf = m_memory.Get(MemoryRegion::kLogits);
        float* logits = static_cast<float*>(logitsBuf.ptr);

        // TODO: call your sampling function here
        uint32_t next_token = /*SampleFromLogits*/ 0;

        tokens_out.push_back(next_token);
        last = next_token;
        ++pos;

        // TODO: EOS handling
    }

    return true;
}

} // namespace seg
