// ============================================================================
// C6: Autoregressive Generation Test
// Tests the full generation loop
// ============================================================================

#include <iostream>
#include <memory>
#include "src/inference/autoregressive_generator.hpp"
#include "src/model/model_context.h"
#include "src/gateway/seg_gateway.hpp"

using namespace rawrxd;

int main(int argc, char* argv[]) {
    std::cout << "\n=== C6: Autoregressive Generation Test ===\n\n";
    
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <model.gguf> [prompt]\n";
        return 1;
    }
    
    std::string model_path = argv[1];
    std::string prompt = (argc > 2) ? argv[2] : "Hello";
    
    // [1/5] Load model
    std::cout << "[1/5] Loading model...\n";
    auto model = std::make_shared<ModelContext>();
    if (!model->LoadFromGGUF(model_path)) {
        std::cout << "      FAILED: Could not load model\n";
        return 1;
    }
    std::cout << "      ✓ Model loaded\n";
    
    auto arch = model->GetArchitectureInfo();
    std::cout << "      Architecture: " << arch.type << "\n";
    std::cout << "      Vocab size: " << arch.vocab_size << "\n";
    
    // [2/5] Initialize SEG gateway
    std::cout << "\n[2/5] Initializing SEG gateway...\n";
    auto gateway = std::make_shared<SegGateway>();
    if (!gateway->Initialize()) {
        std::cout << "      FAILED: Could not initialize SEG gateway\n";
        return 1;
    }
    std::cout << "      ✓ SEG gateway initialized\n";
    
    // [3/5] Initialize generator
    std::cout << "\n[3/5] Initializing autoregressive generator...\n";
    AutoregressiveGenerator generator;
    if (!generator.Initialize(model, gateway)) {
        std::cout << "      FAILED: Could not initialize generator\n";
        return 1;
    }
    std::cout << "      ✓ Generator initialized\n";
    
    // [4/5] Configure generation
    std::cout << "\n[4/5] Configuring generation...\n";
    GenerationConfig config;
    config.max_tokens = 10;  // Short generation for test
    config.sampling.temperature = 0.8f;
    config.sampling.top_k = 40;
    config.sampling.top_p = 0.95f;
    config.eos_token_id = 128001;  // Llama EOS token
    
    std::cout << "      Prompt: \"" << prompt << "\"\n";
    std::cout << "      Max tokens: " << config.max_tokens << "\n";
    std::cout << "      Temperature: " << config.sampling.temperature << "\n";
    std::cout << "      ✓ Configuration ready\n";
    
    // [5/5] Generate
    std::cout << "\n[5/5] Generating...\n";
    std::cout << "      Output: \"";
    std::cout.flush();
    
    // Set up streaming callback
    config.stream_output = true;
    config.on_token = [](uint32_t token_id, const std::string& text) {
        std::cout << text;
        std::cout.flush();
    };
    
    auto result = generator.Generate(prompt, config);
    
    std::cout << "\"\n\n";
    
    // Validate results
    std::cout << "      Tokens generated: " << result.tokens_generated << "\n";
    std::cout << "      Prompt tokens: " << result.prompt_tokens << "\n";
    std::cout << "      Finish reason: " << result.finish_reason << "\n";
    std::cout << "      Time to first token: " << result.time_to_first_token_ms << " ms\n";
    std::cout << "      Total time: " << result.total_time_ms << " ms\n";
    std::cout << "      Tokens/sec: " << result.tokens_per_second << "\n";
    
    if (result.tokens_generated == 0) {
        std::cout << "\n      FAILED: No tokens generated\n";
        return 1;
    }
    
    std::cout << "\n============================================================\n";
    std::cout << "✓ C6 AUTOREGRESSIVE GENERATION SUCCESS\n";
    std::cout << "  Prompt → Tokenize → Embed → Transform → Sample → Token\n";
    std::cout << "  Full loop working end-to-end\n";
    std::cout << "============================================================\n\n";
    
    return 0;
}
