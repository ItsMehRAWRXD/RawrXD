#include "deep2/special_graph/FleetSpecialGraph.hpp"
#include <iostream>

using namespace Deep2::SpecialGraph;

int main() {
    const auto gpt = build(Family::GptOss120B);
    const auto gptv = validate(gpt);
    if (!gptv.ok || gpt.meta.layerCount != 36 || gpt.meta.expertCount != 128 || gpt.meta.expertsPerToken != 4) return 1;

    const auto laguna = build(Family::LagunaS21);
    const auto lagv = validate(laguna);
    if (!lagv.ok || laguna.meta.layerCount != 48 || laguna.meta.sharedExperts != 1 || laguna.meta.kvHeads != 8 || laguna.meta.headDim != 128) return 2;

    const auto dsUnknown = build(Family::DeepSeekV4Flash);
    if (validate(dsUnknown).ok) return 3; // unknown geometry must fail closed.

    RuntimeMeta admitted{};
    admitted.layerCount = 4;          // synthetic admitted-meta fixture only
    admitted.expertCount = 16;
    admitted.expertsPerToken = 2;
    admitted.sharedExperts = 1;
    admitted.contextLength = 1000000;
    admitted.usesMla = true;
    const auto ds = build(Family::DeepSeekV4Flash, admitted);
    const auto dsv = validate(ds);
    if (!dsv.ok) return 4;

    std::cout << "RAWRXD_SPECIAL_GRAPH_FLEET_001\n";
    std::cout << "GPT_OSS_GRAPH=PASS\n";
    std::cout << "LAGUNA_GRAPH=PASS\n";
    std::cout << "DEEPSEEK_UNKNOWN_GEOMETRY_FAIL_CLOSED=PASS\n";
    std::cout << "DEEPSEEK_RUNTIME_META_GRAPH=PASS\n";
    std::cout << "VERDICT=PASS\n";
    return 0;
}
