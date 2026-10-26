#include "render_graph.hpp"
#include <iostream>

void RenderGraph::add(const char* name, std::function<void()> record) {
    passes_.push_back(Pass{name, std::move(record)});
}

void RenderGraph::execute() {
    for (const Pass& pass : passes_) {
        std::cout << "[AAA] RenderGraph pass=" << pass.name << std::endl;
        pass.record();
    }
}
