#include "seg_runtime.hpp"
#include "seg_models.hpp"
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>\n";
        return 1;
    }

    seg::RuntimeConfig cfg;
    cfg.model_path = argv[1];

    seg::Runtime rt;
    if (!rt.Initialize(cfg)) {
        std::cerr << "Failed to initialize runtime\n";
        return 1;
    }

    // Build Llama forward graph
    seg::LlamaGraphConfig llama_cfg;
    llama_cfg.num_layers = 32;

    auto graph = seg::BuildLlamaForwardGraph(llama_cfg);
    std::cout << "Built Llama graph with " << graph.Nodes().size() << " nodes\n";

    // Example generation
    std::vector<int> prompt_tokens = { 1, 2, 3 }; // BOS, "Hello", ","
    std::vector<int> out_tokens;

    if (!rt.Generate(prompt_tokens, out_tokens, 32)) {
        std::cerr << "Generation failed\n";
        return 1;
    }

    std::cout << "Generated " << out_tokens.size() << " tokens\n";

    return 0;
}
