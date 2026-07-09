#pragma once
#include "seg_graph.hpp"
#include "seg_scheduler.hpp"
#include "seg_memory.hpp"
#include "seg_executor.hpp"
#include "seg_agent.hpp"

// Forward declaration - adjust path as needed
namespace RawrXD { namespace Runtime {
    class StreamingMultiLayerBackend;
}}

namespace seg {

struct RuntimeConfig {
    std::string model_path;
    uint32_t max_seq_len = 2048;
};

class Runtime {
public:
    bool Initialize(const RuntimeConfig& cfg);

    bool Generate(const std::vector<int>& tokens_in,
                  std::vector<int>& tokens_out,
                  uint32_t max_new_tokens);

    Memory& MemoryLayer() { return m_memory; }
    Graph& GraphLayer() { return m_graph; }

private:
    Graph m_graph;
    Scheduler m_scheduler;
    Memory m_memory;
    Agent m_agent;
    // RawrXD::Runtime::StreamingMultiLayerBackend m_backend;
};

} // namespace seg
