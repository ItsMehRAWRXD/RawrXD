#include "deep2/special_graph/FleetSpecialGraphExecutor.hpp"
#include <iostream>

using namespace Deep2::SpecialGraph;

static bool executeNode(void*, const Node&) { return true; }

int main() {
    auto gpt = execute(build(Family::GptOss120B), {nullptr, &executeNode});
    if (!gpt.pass() || gpt.layersCompleted != 36) return 1;
    std::cout << gpt.text();

    auto lag = execute(build(Family::LagunaS21), {nullptr, &executeNode});
    if (!lag.pass() || lag.layersCompleted != 48) return 2;
    std::cout << lag.text();

    RuntimeMeta admitted{};
    admitted.layerCount = 3; // synthetic admitted-meta fixture
    admitted.expertCount = 8;
    admitted.expertsPerToken = 2;
    admitted.sharedExperts = 1;
    admitted.contextLength = 1000000;
    admitted.usesMla = true;
    auto ds = execute(build(Family::DeepSeekV4Flash, admitted), {nullptr, &executeNode});
    if (!ds.pass() || ds.layersCompleted != 3) return 3;
    std::cout << ds.text();
    return 0;
}
