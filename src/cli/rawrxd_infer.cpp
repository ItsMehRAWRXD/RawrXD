// ============================================================================
// RawrXD Inference CLI Tool
// ============================================================================
// Command-line interface for the no-dependencies inference engine
// ============================================================================

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>

#include "../core/streaming_loader.hpp"
#include "../core/model_downloader.hpp"
#include "../inference/unified_inference.hpp"

using namespace RawrXD::Core;
using namespace RawrXD::Inference;

// ============================================================================
// Command Line Arguments
// ============================================================================

struct CLIArgs {
    std::string model_path;
    std::string prompt;
    std::string prompt_file;
    std::string output_file;
    std::string system_prompt;
    
    uint32_t max_tokens = 256;
    float temperature = 0.8f;
    float top_p = 0.95f;
    float top_k = 40;
    uint32_t seed = 0;
    bool stream = true;
    bool verbose = false;
    bool benchmark = false;
    bool interactive = false;
    
    // Download mode
    bool download_mode = false;
    std::string download_repo;
    std::string download_file;
    std::string download_dir = "models/";
    bool list_models = false;
    
    // Chat mode
    bool chat_mode = false;
    std::vector<Message> chat_history;
};

// ============================================================================
// Help Text
// ============================================================================

void PrintHelp(const char* program_name) {
    std::cout << "RawrXD Inference CLI - Zero Dependencies\n";
    std::cout << "==========================================\n\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Inference Options:\n";
    std::cout << "  -m, --model <path>       Path to GGUF model file\n";
    std::cout << "  -p, --prompt <text>      Prompt text\n";
    std::cout << "  -f, --file <path>        Read prompt from file\n";
    std::cout << "  -o, --output <path>      Write output to file\n";
    std::cout << "  --system <text>          System prompt\n";
    std::cout << "  -n, --tokens <n>         Max tokens to generate (default: 256)\n";
    std::cout << "  -t, --temp <float>       Temperature (default: 0.8)\n";
    std::cout << "  --top-p <float>          Top-p sampling (default: 0.95)\n";
    std::cout << "  --top-k <int>            Top-k sampling (default: 40)\n";
    std::cout << "  --seed <int>             Random seed (default: 0)\n";
    std::cout << "  --no-stream              Disable streaming output\n";
    std::cout << "  -v, --verbose            Verbose output\n";
    std::cout << "  -b, --benchmark          Run benchmark mode\n";
    std::cout << "  -i, --interactive        Interactive chat mode\n";
    std::cout << "\nDownload Options:\n";
    std::cout << "  --download <repo>        Download model from Hugging Face\n";
    std::cout << "  --file <name>            Specific file to download\n";
    std::cout << "  --dir <path>             Download directory (default: models/)\n";
    std::cout << "  --list-models            List recommended models\n";
    std::cout << "\nOther Options:\n";
    std::cout << "  -h, --help               Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " -m model.gguf -p \"Hello world\"\n";
    std::cout << "  " << program_name << " -m model.gguf --interactive\n";
    std::cout << "  " << program_name << " --download TheBloke/Llama-2-7B-GGUF --file llama-2-7b.Q4_K_M.gguf\n";
    std::cout << "  " << program_name << " --list-models\n";
}

// ============================================================================
// Argument Parsing
// ============================================================================

CLIArgs ParseArgs(int argc, char* argv[]) {
    CLIArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if ((arg == "-m" || arg == "--model") && i + 1 < argc) {
            args.model_path = argv[++i];
        }
        else if ((arg == "-p" || arg == "--prompt") && i + 1 < argc) {
            args.prompt = argv[++i];
        }
        else if ((arg == "-f" || arg == "--file") && i + 1 < argc) {
            args.prompt_file = argv[++i];
        }
        else if ((arg == "-o" || arg == "--output") && i + 1 < argc) {
            args.output_file = argv[++i];
        }
        else if (arg == "--system" && i + 1 < argc) {
            args.system_prompt = argv[++i];
        }
        else if ((arg == "-n" || arg == "--tokens") && i + 1 < argc) {
            args.max_tokens = static_cast<uint32_t>(std::atoi(argv[++i]));
        }
        else if ((arg == "-t" || arg == "--temp") && i + 1 < argc) {
            args.temperature = static_cast<float>(std::atof(argv[++i]));
        }
        else if (arg == "--top-p" && i + 1 < argc) {
            args.top_p = static_cast<float>(std::atof(argv[++i]));
        }
        else if (arg == "--top-k" && i + 1 < argc) {
            args.top_k = static_cast<float>(std::atof(argv[++i]));
        }
        else if (arg == "--seed" && i + 1 < argc) {
            args.seed = static_cast<uint32_t>(std::atoi(argv[++i]));
        }
        else if (arg == "--no-stream") {
            args.stream = false;
        }
        else if (arg == "-v" || arg == "--verbose") {
            args.verbose = true;
        }
        else if (arg == "-b" || arg == "--benchmark") {
            args.benchmark = true;
        }
        else if (arg == "-i" || arg == "--interactive") {
            args.interactive = true;
        }
        else if (arg == "--download" && i + 1 < argc) {
            args.download_mode = true;
            args.download_repo = argv[++i];
        }
        else if (arg == "--model-file" && i + 1 < argc) {
            args.download_file = argv[++i];
        }
        else if (arg == "--dir" && i + 1 < argc) {
            args.download_dir = argv[++i];
        }
        else if (arg == "--list-models") {
            args.list_models = true;
        }
        else if (arg == "-h" || arg == "--help") {
            PrintHelp(argv[0]);
            std::exit(0);
        }
    }
    
    // Read prompt from file if specified
    if (!args.prompt_file.empty()) {
        std::ifstream file(args.prompt_file);
        if (file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            args.prompt = buffer.str();
        }
    }
    
    return args;
}

// ============================================================================
// Benchmark Mode
// ============================================================================

void RunBenchmark(UnifiedInferenceEngine& engine, const CLIArgs& args) {
    std::cout << "Running benchmark...\n";
    std::cout << "===================\n\n";
    
    const char* test_prompts[] = {
        "The quick brown fox",
        "In the year 2050, artificial intelligence",
        "Once upon a time in a distant galaxy",
        "The future of computing is",
        "To be or not to be"
    };
    
    GenerationConfig config;
    config.max_tokens = args.max_tokens;
    config.temperature = args.temperature;
    config.top_p = args.top_p;
    config.top_k = args.top_k;
    config.seed = args.seed;
    
    double total_time = 0.0;
    uint32_t total_tokens = 0;
    
    for (const auto& prompt : test_prompts) {
        auto start = std::chrono::high_resolution_clock::now();
        
        GenerationResult result = engine.Generate(prompt, config);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration<double>(end - start).count();
        
        total_time += duration;
        total_tokens += result.tokens_generated;
        
        std::cout << "Prompt: \"" << prompt << "\"\n";
        std::cout << "  Tokens: " << result.tokens_generated << "\n";
        std::cout << "  Time: " << std::fixed << std::setprecision(2) << duration << "s\n";
        std::cout << "  Speed: " << std::setprecision(1) << result.tokens_per_second << " tok/s\n\n";
    }
    
    double avg_speed = total_tokens / total_time;
    std::cout << "===================\n";
    std::cout << "Average: " << std::fixed << std::setprecision(1) << avg_speed << " tok/s\n";
    std::cout << "Total tokens: " << total_tokens << "\n";
    std::cout << "Total time: " << std::setprecision(2) << total_time << "s\n";
}

// ============================================================================
// Interactive Mode
// ============================================================================

void RunInteractive(UnifiedInferenceEngine& engine, const CLIArgs& args) {
    std::cout << "RawrXD Interactive Chat\n";
    std::cout << "======================\n";
    std::cout << "Type 'exit' or 'quit' to end the session.\n";
    std::cout << "Type 'clear' to clear chat history.\n\n";
    
    GenerationConfig config;
    config.max_tokens = args.max_tokens;
    config.temperature = args.temperature;
    config.top_p = args.top_p;
    config.top_k = args.top_k;
    config.seed = args.seed;
    
    std::vector<Message> history;
    
    if (!args.system_prompt.empty()) {
        history.push_back({"system", args.system_prompt});
    }
    
    while (true) {
        std::cout << "\nYou: ";
        std::string user_input;
        std::getline(std::cin, user_input);
        
        if (user_input == "exit" || user_input == "quit") {
            break;
        }
        
        if (user_input == "clear") {
            history.clear();
            if (!args.system_prompt.empty()) {
                history.push_back({"system", args.system_prompt});
            }
            std::cout << "Chat history cleared.\n";
            continue;
        }
        
        if (user_input.empty()) {
            continue;
        }
        
        history.push_back({"user", user_input});
        
        // Format chat history
        std::string prompt = FormatChat(history, "llama");
        
        std::cout << "\nAssistant: ";
        
        std::string response;
        engine.GenerateStream(prompt, config,
            [&response](const std::string& token, uint32_t token_id, bool is_last) {
                std::cout << token << std::flush;
                response += token;
            });
        
        std::cout << "\n";
        
        history.push_back({"assistant", response});
    }
    
    std::cout << "\nGoodbye!\n";
}

// ============================================================================
// Main
// ============================================================================

// ============================================================================
// Download Mode
// ============================================================================

void RunDownloadMode(const CLIArgs& args) {
    using namespace RawrXD::Core;
    
    if (args.list_models) {
        std::cout << "Recommended Models:\n";
        std::cout << "==================\n\n";
        
        auto models = GetRecommendedModels();
        for (size_t i = 0; i < models.size(); ++i) {
            const auto& m = models[i];
            std::cout << i + 1 << ". " << m.description << "\n";
            std::cout << "   Repo: " << m.repo_id << "\n";
            std::cout << "   File: " << m.filename << "\n";
            std::cout << "   Quantization: " << m.quantization << "\n";
            std::cout << "   Parameters: " << m.num_params << "B\n\n";
        }
        
        std::cout << "Download with:\n";
        std::cout << "  rawrxd-infer --download <repo> --model-file <filename>\n";
        return;
    }
    
    if (args.download_repo.empty()) {
        std::cerr << "Error: --download requires a repository ID\n";
        return;
    }
    
    if (args.download_file.empty()) {
        std::cerr << "Error: --model-file required for download\n";
        return;
    }
    
    std::cout << "Downloading model...\n";
    std::cout << "Repository: " << args.download_repo << "\n";
    std::cout << "File: " << args.download_file << "\n";
    std::cout << "Destination: " << args.download_dir << "\n\n";
    
    ModelDownloader downloader;
    ModelDownloader::SetCacheDirectory(args.download_dir);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    bool success = downloader.DownloadFromHuggingFace(
        args.download_repo,
        args.download_file,
        "",
        [](const DownloadProgress& progress) {
            std::cout << "\r[" << std::fixed << std::setprecision(1) << progress.percent_complete << "%] "
                      << FormatBytes(progress.bytes_downloaded) << " / " << FormatBytes(progress.total_bytes)
                      << " @ " << std::setprecision(2) << progress.bytes_per_second / (1024.0 * 1024.0) << " MB/s"
                      << std::flush;
        });
    
    std::cout << "\n\n";
    
    if (success) {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration<double>(end_time - start_time).count();
        std::cout << "Download complete!\n";
        std::cout << "Time: " << std::fixed << std::setprecision(2) << duration << "s\n";
    } else {
        std::cerr << "Download failed: " << downloader.GetProgress().error_message << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    CLIArgs args = ParseArgs(argc, argv);
    
    // Handle download/list modes first
    if (args.download_mode || args.list_models) {
        RunDownloadMode(args);
        return 0;
    }
    
    // Validate arguments
    if (args.model_path.empty()) {
        std::cerr << "Error: Model path is required. Use -m or --model\n\n";
        PrintHelp(argv[0]);
        return 1;
    }
    
    if (!args.interactive && args.prompt.empty() && !args.benchmark) {
        std::cerr << "Error: Prompt is required (use -p or -f) or use --benchmark or --interactive\n\n";
        PrintHelp(argv[0]);
        return 1;
    }
    
    // Initialize engine
    if (args.verbose) {
        std::cout << "Loading model: " << args.model_path << "\n";
    }
    
    UnifiedInferenceEngine engine;
    auto load_start = std::chrono::high_resolution_clock::now();
    
    if (!engine.Initialize(args.model_path.c_str())) {
        std::cerr << "Error: Failed to load model from " << args.model_path << "\n";
        return 1;
    }
    
    auto load_end = std::chrono::high_resolution_clock::now();
    auto load_time = std::chrono::duration<double>(load_end - load_start).count();
    
    if (args.verbose) {
        std::cout << "Model loaded in " << std::fixed << std::setprecision(2) << load_time << "s\n";
        std::cout << "Model size: " << std::setprecision(2) << engine.GetModelSizeGB() << " GB\n";
        std::cout << "Architecture: " << engine.GetArchitecture().arch << "\n";
        std::cout << "Layers: " << engine.GetArchitecture().num_layers << "\n";
        std::cout << "Hidden size: " << engine.GetArchitecture().hidden_size << "\n\n";
    }
    
    // Run in appropriate mode
    if (args.benchmark) {
        RunBenchmark(engine, args);
    }
    else if (args.interactive) {
        RunInteractive(engine, args);
    }
    else {
        // Single generation mode
        GenerationConfig config;
        config.max_tokens = args.max_tokens;
        config.temperature = args.temperature;
        config.top_p = args.top_p;
        config.top_k = args.top_k;
        config.seed = args.seed;
        config.stream = args.stream;
        
        // Add system prompt if provided
        std::string full_prompt = args.prompt;
        if (!args.system_prompt.empty()) {
            full_prompt = "<<SYS>>\n" + args.system_prompt + "\n<</SYS>>\n\n" + args.prompt;
        }
        
        if (args.stream) {
            // Streaming output
            std::string output;
            engine.GenerateStream(full_prompt, config,
                [&output](const std::string& token, uint32_t token_id, bool is_last) {
                    std::cout << token << std::flush;
                    output += token;
                });
            std::cout << "\n";
            
            // Write to file if specified
            if (!args.output_file.empty()) {
                std::ofstream out(args.output_file);
                if (out) {
                    out << output;
                }
            }
        }
        else {
            // Non-streaming
            GenerationResult result = engine.Generate(full_prompt, config);
            std::cout << result.text << "\n";
            
            if (args.verbose) {
                std::cout << "\nTokens generated: " << result.tokens_generated << "\n";
                std::cout << "Tokens/sec: " << std::fixed << std::setprecision(1) 
                          << result.tokens_per_second << "\n";
            }
            
            // Write to file if specified
            if (!args.output_file.empty()) {
                std::ofstream out(args.output_file);
                if (out) {
                    out << result.text;
                }
            }
        }
    }
    
    return 0;
}
