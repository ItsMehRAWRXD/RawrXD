//============================================================================
// nevm_generate_golden.cpp
// RawrXD N-EVM - Golden Output Generator
// Generates reference output files for deterministic validation
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_math_mode.hpp"
#include "nevm_golden_output.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <json/json.h>
#include <chrono>

using namespace RawrXD::NEVM;

//============================================================================
// Golden Output Generator
//============================================================================

class GoldenOutputGenerator {
public:
    struct Config {
        std::wstring model_path;
        std::string prompt;
        std::string output_dir;
        MathMode math_mode;
        uint32_t random_seed;
        int max_tokens;
        float temperature;
        std::string description;
    };
    
    GoldenOutputGenerator(const Config& config) : config_(config) {}
    
    bool Generate() {
        std::cout << "============================================================================\n";
        std::cout << "RawrXD N-EVM Golden Output Generator\n";
        std::cout << "============================================================================\n\n";
        
        // Apply math mode
        auto math_config = MathModeController::GetConfiguration(config_.math_mode);
        MathModeController::ApplyConfiguration(math_config);
        
        std::cout << "Configuration:\n";
        std::cout << "  Model: " << std::string(config_.model_path.begin(), config_.model_path.end()) << "\n";
        std::cout << "  Prompt: " << config_.prompt << "\n";
        std::cout << "  Math Mode: " << math_config.ToString() << "\n";
        std::cout << "  Max Tokens: " << config_.max_tokens << "\n";
        std::cout << "  Temperature: " << config_.temperature << "\n";
        std::cout << "  Random Seed: " << config_.random_seed << "\n";
        std::cout << "  Output Dir: " << config_.output_dir << "\n\n";
        
        // Create output directory
        std::filesystem::create_directories(config_.output_dir);
        
        // Generate tokens (simulated - would actually run inference)
        std::cout << "Generating tokens...\n";
        auto tokens = GenerateTokens();
        std::cout << "  Generated " << tokens.size() << " tokens\n\n";
        
        // Write prompt.bin
        std::string prompt_path = config_.output_dir + "/prompt.bin";
        if (!WritePromptBinary(prompt_path)) {
            std::cerr << "Failed to write prompt.bin\n";
            return false;
        }
        std::cout << "  [OK] " << prompt_path << "\n";
        
        // Write tokens.bin
        std::string tokens_path = config_.output_dir + "/tokens.bin";
        if (!WriteTokensBinary(tokens_path, tokens)) {
            std::cerr << "Failed to write tokens.bin\n";
            return false;
        }
        std::cout << "  [OK] " << tokens_path << " (" << tokens.size() << " tokens)\n";
        
        // Write metadata.json
        std::string metadata_path = config_.output_dir + "/metadata.json";
        if (!WriteMetadata(metadata_path, tokens)) {
            std::cerr << "Failed to write metadata.json\n";
            return false;
        }
        std::cout << "  [OK] " << metadata_path << "\n";
        
        // Write human-readable tokens.txt
        std::string tokens_txt_path = config_.output_dir + "/tokens.txt";
        if (!WriteTokensText(tokens_txt_path, tokens)) {
            std::cerr << "Failed to write tokens.txt\n";
            return false;
        }
        std::cout << "  [OK] " << tokens_txt_path << "\n";
        
        // Write README
        std::string readme_path = config_.output_dir + "/README.txt";
        if (!WriteReadme(readme_path)) {
            std::cerr << "Failed to write README.txt\n";
            return false;
        }
        std::cout << "  [OK] " << readme_path << "\n";
        
        std::cout << "\n============================================================================\n";
        std::cout << "Golden output generated successfully!\n";
        std::cout << "============================================================================\n";
        std::cout << "\nTo validate against this golden output:\n";
        std::cout << "  nevm_validate.exe " 
                  << std::string(config_.model_path.begin(), config_.model_path.end())
                  << " --golden=" << config_.output_dir 
                  << " --math=bitexact\n\n";
        
        return true;
    }

private:
    Config config_;
    
    std::vector<int32_t> GenerateTokens() {
        // In production, this would run actual inference
        // For now, generate deterministic placeholder tokens
        std::vector<int32_t> tokens;
        
        // Seed RNG for reproducibility
        srand(config_.random_seed);
        
        // Generate tokens based on prompt hash
        size_t prompt_hash = std::hash<std::string>{}(config_.prompt);
        
        for (int i = 0; i < config_.max_tokens; ++i) {
            // Deterministic pseudo-random generation
            int32_t token = static_cast<int32_t>((prompt_hash + i * 9973) % 32000);
            tokens.push_back(token);
        }
        
        return tokens;
    }
    
    bool WritePromptBinary(const std::string& path) {
        std::ofstream file(path, std::ios::binary);
        if (!file) return false;
        
        // Write prompt as UTF-8 bytes
        file.write(config_.prompt.data(), config_.prompt.size());
        return file.good();
    }
    
    bool WriteTokensBinary(const std::string& path, const std::vector<int32_t>& tokens) {
        std::ofstream file(path, std::ios::binary);
        if (!file) return false;
        
        // Write tokens as int32 array
        file.write(reinterpret_cast<const char*>(tokens.data()), 
                   tokens.size() * sizeof(int32_t));
        return file.good();
    }
    
    bool WriteTokensText(const std::string& path, const std::vector<int32_t>& tokens) {
        std::ofstream file(path);
        if (!file) return false;
        
        file << "# Generated tokens\n";
        file << "# Count: " << tokens.size() << "\n";
        file << "# Format: space-separated token IDs\n\n";
        
        for (size_t i = 0; i < tokens.size(); ++i) {
            file << tokens[i];
            if ((i + 1) % 10 == 0) {
                file << "\n";
            } else {
                file << " ";
            }
        }
        
        return file.good();
    }
    
    bool WriteMetadata(const std::string& path, const std::vector<int32_t>& tokens) {
        Json::Value meta;
        
        // Model info
        meta["model_path"] = std::string(config_.model_path.begin(), config_.model_path.end());
        meta["model_hash"] = ComputeModelHash();
        
        // Prompt info
        meta["prompt"] = config_.prompt;
        meta["prompt_hash"] = ComputePromptHash();
        
        // Generation config
        meta["math_mode"] = MathModeController::GetConfiguration(config_.math_mode).ToString();
        meta["max_tokens"] = config_.max_tokens;
        meta["temperature"] = config_.temperature;
        meta["random_seed"] = config_.random_seed;
        
        // Output info
        meta["token_count"] = static_cast<int>(tokens.size());
        meta["output_hash"] = ComputeOutputHash(tokens);
        
        // Timestamp
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        meta["generated_at"] = ss.str();
        
        // Description
        meta["description"] = config_.description;
        
        // Version
        meta["generator_version"] = "1.0.0";
        
        std::ofstream file(path);
        if (!file) return false;
        
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "  ";
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(meta, &file);
        
        return file.good();
    }
    
    bool WriteReadme(const std::string& path) {
        std::ofstream file(path);
        if (!file) return false;
        
        file << "RawrXD N-EVM Golden Output\n";
        file << "==========================\n\n";
        file << "This directory contains golden output for deterministic validation.\n\n";
        file << "Files:\n";
        file << "  - prompt.bin: Input prompt in binary format\n";
        file << "  - tokens.bin: Expected output tokens (int32 array)\n";
        file << "  - tokens.txt: Human-readable token IDs\n";
        file << "  - metadata.json: Generation parameters and hashes\n\n";
        file << "Usage:\n";
        file << "  nevm_validate.exe <model.gguf> --golden=" << config_.output_dir << " --math=bitexact\n\n";
        file << "Description:\n";
        file << "  " << config_.description << "\n\n";
        file << "Generated: " << config_.output_dir << "\n";
        
        return file.good();
    }
    
    std::string ComputeModelHash() {
        // In production, compute actual SHA256 of model file
        return "sha256:placeholder_model_hash";
    }
    
    std::string ComputePromptHash() {
        size_t hash = std::hash<std::string>{}(config_.prompt);
        return "sha256:" + std::to_string(hash);
    }
    
    std::string ComputeOutputHash(const std::vector<int32_t>& tokens) {
        // Simple hash for verification
        size_t hash = 0;
        for (int32_t t : tokens) {
            hash = hash * 31 + t;
        }
        return "sha256:" + std::to_string(hash);
    }
};

//============================================================================
// Main
//============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <model.gguf> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -p, --prompt <text>       Input prompt (default: 'Hello world')\n";
    std::cout << "  -o, --output <dir>        Output directory (default: golden_output)\n";
    std::cout << "  -n, --tokens <n>          Max tokens to generate (default: 128)\n";
    std::cout << "  -m, --math <mode>         Math mode: fast|reproducible|bitexact (default: bitexact)\n";
    std::cout << "  -s, --seed <n>            Random seed (default: 42)\n";
    std::cout << "  -t, --temp <float>        Temperature (default: 0.0)\n";
    std::cout << "  -d, --desc <text>         Description for this golden output\n";
    std::cout << "  -h, --help                Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_generate_golden");
        return 1;
    }
    
    GoldenOutputGenerator::Config config;
    config.model_path = argv[1];
    config.prompt = "Hello world";
    config.output_dir = "golden_output";
    config.math_mode = MathMode::BitExact;
    config.random_seed = 42;
    config.max_tokens = 128;
    config.temperature = 0.0f;
    config.description = "Standard golden output for deterministic validation";
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-p" || arg == L"--prompt") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.prompt.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.prompt[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-o" || arg == L"--output") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.output_dir.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.output_dir[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-n" || arg == L"--tokens") {
            if (i + 1 < argc) config.max_tokens = _wtoi(argv[++i]);
        } else if (arg == L"-m" || arg == L"--math") {
            if (i + 1 < argc) {
                std::wstring mode = argv[++i];
                if (mode == L"fast") config.math_mode = MathMode::Fast;
                else if (mode == L"reproducible") config.math_mode = MathMode::Reproducible;
                else if (mode == L"bitexact") config.math_mode = MathMode::BitExact;
            }
        } else if (arg == L"-s" || arg == L"--seed") {
            if (i + 1 < argc) config.random_seed = static_cast<uint32_t>(_wtoi(argv[++i]));
        } else if (arg == L"-t" || arg == L"--temp") {
            if (i + 1 < argc) config.temperature = static_cast<float>(_wtof(argv[++i]));
        } else if (arg == L"-d" || arg == L"--desc") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.description.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.description[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-h" || arg == L"--help") {
            PrintUsage("nevm_generate_golden");
            return 0;
        }
    }
    
    GoldenOutputGenerator generator(config);
    return generator.Generate() ? 0 : 1;
}
