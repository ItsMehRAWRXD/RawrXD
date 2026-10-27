#include "render_graph.hpp"

void RenderGraph::add(const char* name, std::function<void()> record) {
    passes_.push_back(Pass{name, std::move(record)});
}

void RenderGraph::execute() {
    for (const Pass& pass : passes_) {
        pass.record();
    }
}
