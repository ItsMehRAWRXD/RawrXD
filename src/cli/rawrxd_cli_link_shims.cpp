// rawrxd_cli_link_shims.cpp - Link compatibility shims for CLI build
// This file provides link compatibility implementations for CLI build

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <functional>#include <string>

// Include the Hotpatch Engine header (we created this)
#include "hotpatch/Engine.hpp"
// Forward declaration to avoid including full header
namespace RawrXD {
    class CommandRegistry {
    public:
        static CommandRegistry& Instance();
        void Initialize();
        void Shutdown();
    };
}

// Link compatibility implementations for CLI
extern "C" {
    // Add any missing symbol implementations here
    // These provide link-time compatibility
}

// CLI entry point shim
namespace RawrXD {
namespace CLI {

    // Initialize CLI subsystem
    int InitializeCLI() {
        // Set up console output
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut != INVALID_HANDLE_VALUE) {
            // Enable ANSI escape codes
            DWORD mode = 0;
            if (GetConsoleMode(hOut, &mode)) {
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
                SetConsoleMode(hOut, mode);
            }
        }
        
        // Initialize command registry
        CommandRegistry::Instance().Initialize();
        
        return 0;
    }

    // Shutdown CLI subsystem
    void ShutdownCLI() {
        // Flush output
        fflush(stdout);
        fflush(stderr);
        
        // Cleanup command registry
        CommandRegistry::Instance().Shutdown();
    }

} // namespace CLI
} // namespace RawrXD

// ============================================================================
// Hotpatch::Engine stub (used by AgentOllamaClient)
// ============================================================================
namespace RawrXD {
namespace Agentic {
namespace Hotpatch {

Engine& Engine::instance() {
    static Engine s_instance;
    return s_instance;
}

bool Engine::setModelTemperature(double temp) {
    m_temperature = temp;
    return true;
}

bool Engine::loadModel(const std::string& path) {
    m_ready = !path.empty();
    return m_ready;
}

bool Engine::isReady() const {
    return m_ready;
}

std::string Engine::generate(const std::string& prompt) {
    return "[STUB] " + prompt;
}

void Engine::shutdown() {
    m_ready = false;
}

} // namespace Hotpatch
} // namespace Agentic
} // namespace RawrXD

// ============================================================================
// Deep2::Deep2Engine stub (used by Deep2IDEIntegration.cpp)
// ============================================================================
namespace Deep2 {

// Forward declaration
class Deep2Engine;

struct EngineConfig {
    std::string modelPath;
    uint32_t maxContextLength = 4096;
    uint32_t gpuDevice = 0;
};

struct InferenceStats {
    uint64_t tokensGenerated = 0;
    double tokensPerSecond = 0.0;
    double latencyMs = 0.0;
};

class Deep2Engine {
public:
    Deep2Engine();
    ~Deep2Engine();
    bool initialize(const EngineConfig& config);
    std::vector<int> tokenize(const std::string& text);
    std::string detokenize(const std::vector<int>& tokens);
    uint64_t generate(const int* inputTokens, uint64_t inputCount,
                      int* outputTokens, uint64_t outputCapacity,
                      InferenceStats* stats,
                      std::function<bool(int)> stopCallback);
};

Deep2Engine::Deep2Engine() = default;
Deep2Engine::~Deep2Engine() = default;

bool Deep2Engine::initialize(const EngineConfig& config) {
    (void)config;
    return true;
}

std::vector<int> Deep2Engine::tokenize(const std::string& text) {
    std::vector<int> tokens;
    // Simple word-based tokenization stub
    size_t start = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == ' ') {
            if (i > start) {
                tokens.push_back(static_cast<int>(tokens.size() + 1));
            }
            start = i + 1;
        }
    }
    if (tokens.empty() && !text.empty()) {
        tokens.push_back(1);
    }
    return tokens;
}

std::string Deep2Engine::detokenize(const std::vector<int>& tokens) {
    std::string result;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0) result += " ";
        result += "tok" + std::to_string(tokens[i]);
    }
    return result;
}

uint64_t Deep2Engine::generate(const int* inputTokens, uint64_t inputCount,
                                int* outputTokens, uint64_t outputCapacity,
                                InferenceStats* stats,
                                std::function<bool(int)> stopCallback) {
    uint64_t generated = 0;
    for (uint64_t i = 0; i < outputCapacity; ++i) {
        outputTokens[i] = static_cast<int>(i + 1);
        generated++;
        if (stopCallback && stopCallback(outputTokens[i])) {
            break;
        }
    }
    if (stats) {
        stats->tokensGenerated = generated;
        stats->tokensPerSecond = 1.0;
        stats->latencyMs = static_cast<double>(generated);
    }
    return generated;
}

} // namespace Deep2

// Link compatibility exports
#ifdef _WIN32
#pragma comment(linker, "/EXPORT:RawrXD_CLI_Initialize")
#pragma comment(linker, "/EXPORT:RawrXD_CLI_Shutdown")
#endif
