// test_inference.cpp — Real GGUF model inference test
// Compile: g++ -std=c++20 -O2 -m64 -I src\engine test_inference.cpp -o test_inference.exe -lkernel32
// Or: cl /nologo /O2 /EHsc /std:c++20 /I src\engine test_inference.cpp /Fe:test_inference.exe

#include "RawrXD_InferenceCore.hpp"
#include <iostream>
#include <iomanip>

int main(int argc, char* argv[]) {
    printf("============================================\n");
    printf("  RawrXD Sovereign Inference Test\n");
    printf("============================================\n\n");

    // Determine model path
    const char* model_path = argc > 1 ? argv[1] : "D:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    const char* prompt = argc > 2 ? argv[2] : "Hello, what is machine learning?";

    // Convert to wide
    wchar_t wpath[1024];
    MultiByteToWideChar(CP_UTF8, 0, model_path, -1, wpath, 1024);

    printf("Loading model: %s\n", model_path);
    printf("Prompt: %s\n\n", prompt);

    InferenceEngine engine;

    // Load model
    auto t0 = std::chrono::high_resolution_clock::now();
    if (!engine.LoadModel(wpath)) {
        printf("FAILED to load model\n");
        return 1;
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double load_ms = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0;

    // Print model info
    auto& reader = engine.reader;
    printf("Model loaded in %.0f ms\n", load_ms);
    printf("Architecture: %s\n", engine.arch_name.c_str());
    reader.PrintInfo();
    printf("\n");

    // Print tokenizer info
    printf("Tokenizer: %zu tokens loaded\n", engine.tokenizer.vocab.size());
    printf("BOS: %d, EOS: %d\n", engine.tokenizer.bos_id, engine.tokenizer.eos_id);
    printf("\n");

    // Run inference
    printf("Generating...\n");
    printf("--------------------------------------------\n");

    auto t_gen0 = std::chrono::high_resolution_clock::now();
    std::string result = engine.Generate(prompt, 128, 0.8f, 0.9f, 40);
    auto t_gen1 = std::chrono::high_resolution_clock::now();
    double gen_ms = std::chrono::duration_cast<std::chrono::microseconds>(t_gen1 - t_gen0).count() / 1000.0;

    printf("\n--------------------------------------------\n");
    printf("Result:\n%s\n", result.c_str());
    printf("\n--------------------------------------------\n");

    // Performance stats
    printf("\nPerformance:\n");
    printf("  Load time:      %.0f ms\n", load_ms);
    printf("  First token:    %.0f ms\n", engine.stats.first_token_us / 1000.0);
    printf("  Total time:     %.0f ms\n", gen_ms);
    printf("  Tokens:         %u\n", engine.stats.tokens_generated);
    if (engine.stats.tokens_generated > 0) {
        printf("  Throughput:     %.1f tokens/sec\n", engine.stats.tokens_per_sec);
        printf("  ms per token:   %.1f\n", gen_ms / engine.stats.tokens_generated);
    }

    printf("\n============================================\n");
    printf("  Inference Complete\n");
    printf("============================================\n");

    return 0;
}
