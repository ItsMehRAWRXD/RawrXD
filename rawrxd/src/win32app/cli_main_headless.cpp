// cli_main_headless.cpp — RawrXD headless CLI entry point with model router
//
// RAWRXD_MODEL_ROUTER_001:
//   --model <path.gguf>   -> DEEP2_GGUF route (local file via Deep2Engine)
//   --model <ollama:name> -> OLLAMA_PROXY route (POST to http://127.0.0.1:11434)
//   no model              -> print usage + exit nonzero
//
// Usage:
//   rawrxd --model F:\path\model.gguf --prompt "Hello" --tokens 8
//   rawrxd --model glm-5.3:cloud --prompt "Reply READY only." --tokens 8

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

#include "deep2/Deep2Engine.h"

// ----------------------------------------------------------------------------
// Model route classification
// ----------------------------------------------------------------------------
enum class ModelRoute {
    DEEP2_GGUF,
    OLLAMA_PROXY,
    FAIL_CLOSED
};

static ModelRoute classifyModel(const std::string& modelSpec) {
    if (modelSpec.empty()) return ModelRoute::FAIL_CLOSED;

    // Local file path (exists on disk)
    if (std::filesystem::exists(modelSpec)) return ModelRoute::DEEP2_GGUF;

    // .gguf extension (even if file doesn't exist yet, treat as local path)
    if (modelSpec.size() >= 5) {
        auto ext = modelSpec.substr(modelSpec.size() - 5);
        for (auto& c : ext) c = static_cast<char>(tolower(c));
        if (ext == ".gguf") return ModelRoute::DEEP2_GGUF;
    }

    // Ollama model names contain ':' (e.g., glm-5.3:cloud, qwen2.5-coder:1.5b)
    if (modelSpec.find(':') != std::string::npos) return ModelRoute::OLLAMA_PROXY;

    // Could also be an Ollama model without a tag (e.g., "llama3")
    // Try to check if Ollama is running and has this model
    // For now, treat unknown names as FAIL_CLOSED
    return ModelRoute::FAIL_CLOSED;
}

// ----------------------------------------------------------------------------
// Ollama proxy: POST to http://127.0.0.1:11434/api/generate
// ----------------------------------------------------------------------------
static std::string ollamaGenerate(const std::string& model, const std::string& prompt, int maxTokens) {
    // Build JSON body manually (no JSON library dependency)
    std::ostringstream json;
    json << "{\"model\":\"" << model << "\",\"prompt\":\"" << prompt
         << "\",\"stream\":false,\"options\":{\"num_predict\":" << maxTokens << "}}";

    std::string bodyStr = json.str();

#ifdef _WIN32
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 11434, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

    // Convert body to wide string for WinHttpSendRequest
    std::wstring wBody(bodyStr.begin(), bodyStr.end());
    BOOL bResult = WinHttpSendRequest(hRequest,
        L"Content-Type: application/json\r\n",
        -1, (LPVOID)bodyStr.data(), (DWORD)bodyStr.size(), (DWORD)bodyStr.size(), 0);

    if (!bResult) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    bResult = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResult) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Read response
    std::string response;
    DWORD dwSize = 0;
    do {
        DWORD dwDownloaded = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        std::vector<char> buffer(dwSize + 1, 0);
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) break;
        response.append(buffer.data(), dwDownloaded);
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    // Parse "response" field from JSON (simple string extraction)
    // Look for "response":"..."
    size_t pos = response.find("\"response\":\"");
    if (pos == std::string::npos) return "";
    pos += 12; // skip "response":"
    std::string result;
    while (pos < response.size() && response[pos] != '"') {
        if (response[pos] == '\\' && pos + 1 < response.size()) {
            pos++;
            switch (response[pos]) {
                case 'n': result += '\n'; break;
                case 't': result += '\t'; break;
                case 'r': result += '\r'; break;
                case '\\': result += '\\'; break;
                case '"': result += '"'; break;
                default: result += response[pos]; break;
            }
        } else {
            result += response[pos];
        }
        pos++;
    }
    return result;
#else
    return ""; // Non-Windows not supported in this CLI
#endif
}

// ----------------------------------------------------------------------------
// Deep2 GGUF route: load model via Deep2Engine and generate
// ----------------------------------------------------------------------------
static std::string deep2Generate(const std::string& modelPath, const std::string& prompt, int maxTokens) {
    // Use the Deep2Engine via the same API as the Win32IDE chat path
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig config;
    config.maxSeqLen = 4096;
    config.numThreads = 0; // auto

    if (!engine.initialize(config)) {
        return "[DEEP2_INIT_FAILED]";
    }
    engine.enableVulkan(false);

    Deep2::ModelLoadDiag diag{};
    if (!engine.loadModel(modelPath, &diag)) {
        return "[DEEP2_LOAD_FAILED]";
    }

    Deep2::GenerationOptions opts;
    opts.maxTokens = maxTokens;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.topP = 1.0f;
    opts.seed = 1;

    std::string generatedText;
    auto callback = [&generatedText](int32_t, const std::string& token) -> bool {
        generatedText += token;
        return true;
    };

    Deep2::GenerationResult result = engine.generateStream(prompt, opts, callback);

    if (result.completed) return generatedText;
    return "[DEEP2_GENERATION_FAILED]";
}

// ----------------------------------------------------------------------------
// Receipt writer
// ----------------------------------------------------------------------------
static void writeReceipt(const std::string& modelSpec, ModelRoute route,
                         const std::string& output, int exitCode) {
    std::ofstream f("rawrxd_model_router_receipt.txt");
    if (!f.is_open()) return;

    const char* routeName = "FAIL_CLOSED";
    int deep2Used = 0, ollamaUsed = 0, isLocalGguf = 0;

    switch (route) {
        case ModelRoute::DEEP2_GGUF:
            routeName = "DEEP2_GGUF";
            deep2Used = 1;
            isLocalGguf = 1;
            break;
        case ModelRoute::OLLAMA_PROXY:
            routeName = "OLLAMA_PROXY";
            ollamaUsed = 1;
            break;
        default:
            break;
    }

    f << "GATE=RAWRXD_MODEL_ROUTER_001\n";
    f << "MODEL_SPEC=" << modelSpec << "\n";
    f << "ROUTE=" << routeName << "\n";
    f << "DEEP2_USED=" << deep2Used << "\n";
    f << "OLLAMA_USED=" << ollamaUsed << "\n";
    f << "MODEL_IS_LOCAL_GGUF=" << isLocalGguf << "\n";
    f << "MODEL_LOAD=" << (output.empty() || output[0] == '[' ? "FAIL" : "PASS") << "\n";
    f << "GENERATION_COMPLETED=" << (!output.empty() && output[0] != '[' ? 1 : 0) << "\n";
    f << "STDOUT_NONEMPTY=" << (!output.empty() ? 1 : 0) << "\n";
    f << "EXIT_CODE=" << exitCode << "\n";
    f << "VERDICT=" << (exitCode == 0 && !output.empty() && output[0] != '[' ? "PASS" : "FAIL") << "\n";
    f.close();
}

// ----------------------------------------------------------------------------
// Usage
// ----------------------------------------------------------------------------
static void printUsage() {
    std::fprintf(stderr,
        "rawrxd — RawrXD headless CLI with model router\n\n"
        "Usage:\n"
        "  rawrxd --model <path.gguf> --prompt \"<text>\" [--tokens N]\n"
        "  rawrxd --model <ollama:model> --prompt \"<text>\" [--tokens N]\n\n"
        "Model routing:\n"
        "  Local .gguf file     -> DEEP2_GGUF (Deep2Engine native inference)\n"
        "  Ollama model name    -> OLLAMA_PROXY (POST to http://127.0.0.1:11434)\n"
        "  Unknown              -> FAIL_CLOSED (exit nonzero)\n\n"
        "Options:\n"
        "  --model <spec>    Model path or Ollama model name (required)\n"
        "  --prompt <text>   Generation prompt (required)\n"
        "  --tokens N        Max tokens to generate (default: 8)\n"
        "  --help            Show this help\n");
}

// ----------------------------------------------------------------------------
// Main entry point
// ----------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    std::string modelSpec;
    std::string prompt;
    int maxTokens = 8;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
        else if (arg == "--model" && i + 1 < argc) {
            modelSpec = argv[++i];
        }
        else if (arg == "--prompt" && i + 1 < argc) {
            prompt = argv[++i];
        }
        else if (arg == "--tokens" && i + 1 < argc) {
            maxTokens = std::atoi(argv[++i]);
            if (maxTokens <= 0) maxTokens = 8;
        }
    }

    // No model -> print usage + exit nonzero
    if (modelSpec.empty()) {
        printUsage();
        writeReceipt("", ModelRoute::FAIL_CLOSED, "", 1);
        return 1;
    }

    // No prompt -> fail closed
    if (prompt.empty()) {
        std::fprintf(stderr, "Error: --prompt is required\n");
        writeReceipt(modelSpec, ModelRoute::FAIL_CLOSED, "", 1);
        return 1;
    }

    // Classify model route
    ModelRoute route = classifyModel(modelSpec);

    std::string output;
    int exitCode = 0;

    switch (route) {
        case ModelRoute::DEEP2_GGUF:
            std::fprintf(stderr, "ROUTE=DEEP2_GGUF MODEL=%s\n", modelSpec.c_str());
            output = deep2Generate(modelSpec, prompt, maxTokens);
            if (output.empty() || output[0] == '[') exitCode = 1;
            break;

        case ModelRoute::OLLAMA_PROXY:
            std::fprintf(stderr, "ROUTE=OLLAMA_PROXY MODEL=%s\n", modelSpec.c_str());
            output = ollamaGenerate(modelSpec, prompt, maxTokens);
            if (output.empty()) exitCode = 1;
            break;

        case ModelRoute::FAIL_CLOSED:
        default:
            std::fprintf(stderr, "ROUTE=FAIL_CLOSED MODEL=%s\n"
                "Error: cannot classify model '%s'.\n"
                "Use a local .gguf file path or an Ollama model name (with ':').\n",
                modelSpec.c_str(), modelSpec.c_str());
            writeReceipt(modelSpec, ModelRoute::FAIL_CLOSED, "", 1);
            return 1;
    }

    // Print generated text to stdout
    if (!output.empty()) {
        std::printf("%s\n", output.c_str());
    }

    // Write receipt
    writeReceipt(modelSpec, route, output, exitCode);

    return exitCode;
}