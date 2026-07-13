// RawrXD Hello Runtime Example
// Minimal example demonstrating basic RawrXD usage

#include <rawrxd/RawrXD.hpp>
#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    std::cout << "=== RawrXD Hello Runtime Example ===" << std::endl;
    
    // Check command line arguments
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model_path> [prompt]" << std::endl;
        std::cerr << "Example: " << argv[0] << " models/llama-7b.gguf 'Hello, world!'" << std::endl;
        return 1;
    }
    
    std::string model_path = argv[1];
    std::string prompt = (argc > 2) ? argv[2] : "Explain quantum computing in simple terms:";
    
    // Initialize RawrXD
    std::cout << "Initializing RawrXD..." << std::endl;
    
    RawrXD::Config config;
    config.model_path = model_path;
    config.thread_count = 0;  // Auto-detect
    config.context_length = 4096;
    config.enable_gpu = true;
    config.device = "auto";
    
    if (!RawrXD::Initialize(config)) {
        std::cerr << "Failed to initialize RawrXD" << std::endl;
        return 1;
    }
    
    std::cout << "RawrXD initialized successfully!" << std::endl;
    std::cout << "Version: " << RawrXD::GetVersion() << std::endl;
    std::cout << "Build: " << RawrXD::GetBuildHash() << std::endl;
    
    // Create inference session
    std::cout << "\nLoading model: " << model_path << std::endl;
    auto session = RawrXD::CreateSession(model_path);
    
    if (!session) {
        std::cerr << "Failed to create session" << std::endl;
        RawrXD::Shutdown();
        return 1;
    }
    
    std::cout << "Model loaded successfully!" << std::endl;
    
    // Configure generation
    RawrXD::GenerationParams params;
    params.max_tokens = 256;
    params.temperature = 0.7f;
    params.top_p = 0.9f;
    params.top_k = 40;
    params.repeat_penalty = 1.1f;
    
    // Generate response
    std::cout << "\nPrompt: " << prompt << std::endl;
    std::cout << "\nGenerating response..." << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    auto result = session->Generate(prompt, params);
    
    std::cout << result.text << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    // Print statistics
    std::cout << "\nStatistics:" << std::endl;
    std::cout << "  Tokens generated: " << result.tokens_generated << std::endl;
    std::cout << "  Tokens/second: " << result.tokens_per_second << std::endl;
    std::cout << "  Duration: " << result.duration.count() << "ms" << std::endl;
    std::cout << "  Truncated: " << (result.truncated ? "Yes" : "No") << std::endl;
    
    // Cleanup
    std::cout << "\nShutting down..." << std::endl;
    RawrXD::Shutdown();
    
    std::cout << "Done!" << std::endl;
    return 0;
}
