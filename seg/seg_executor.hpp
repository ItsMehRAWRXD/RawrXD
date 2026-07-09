#pragma once
#include "seg_graph.hpp"
#include "seg_memory.hpp"

// Forward declaration - adjust path as needed for your project
namespace RawrXD { namespace Runtime {
    class StreamingMultiLayerBackend;
}}

namespace seg {

class Executor {
public:
    Executor(Memory& mem,
             RawrXD::Runtime::StreamingMultiLayerBackend& backend)
        : m_mem(mem), m_backend(backend) {}

    void Run(const Graph& graph, uint32_t token_id, uint32_t position);

private:
    Memory& m_mem;
    RawrXD::Runtime::StreamingMultiLayerBackend& m_backend;
};

} // namespace seg
