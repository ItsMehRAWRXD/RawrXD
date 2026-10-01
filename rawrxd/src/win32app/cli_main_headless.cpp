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
#include <iomanip>
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
    std::fprintf(stderr, "[CLI_OLLAMA] model='%s' prompt='%s' maxTokens=%d\n",
        model.c_str(), prompt.c_str(), maxTokens); std::fflush(stderr);
    // Build JSON body manually (no JSON library dependency)
    std::ostringstream json;
    json << "{\"model\":\"" << model << "\",\"prompt\":\"" << prompt
         << "\",\"stream\":false,\"options\":{\"num_predict\":" << maxTokens << "}}";

    std::string bodyStr = json.str();

#ifdef _WIN32
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { std::fprintf(stderr, "[CLI_OLLAMA] FAIL: WinHttpOpen returned null\n"); std::fflush(stderr); return ""; }

    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 11434, 0);
    if (!hConnect) { std::fprintf(stderr, "[CLI_OLLAMA] FAIL: WinHttpConnect returned null\n"); std::fflush(stderr); WinHttpCloseHandle(hSession); return ""; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate",
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) { std::fprintf(stderr, "[CLI_OLLAMA] FAIL: WinHttpOpenRequest returned null\n"); std::fflush(stderr); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

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
        std::fprintf(stderr, "[CLI_OLLAMA] FAIL: WinHttpReceiveResponse failed\n"); std::fflush(stderr);
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
    if (pos == std::string::npos) { std::fprintf(stderr, "[CLI_OLLAMA] FAIL: no 'response' field in Ollama response (len=%zu)\n", response.size()); std::fflush(stderr); return ""; }
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
    std::fprintf(stderr, "[CLI_OLLAMA] FAIL: non-Windows not supported\n"); std::fflush(stderr);
    return ""; // Non-Windows not supported in this CLI
#endif
}

// ----------------------------------------------------------------------------
// Deep2 GGUF route: load model via Deep2Engine and generate
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// RAWRXD_TEARDOWN_VS_INFERENCE_001
// `engine` is a local inside deep2RunEngine(), so ~Deep2Engine runs when that
// function returns -- before main() reaches its printf. If teardown faults,
// the function never returns and the inference result is lost entirely,
// making a completed generation look like an empty one. deep2RunEngine()
// therefore emits and flushes its result itself while `engine` is still
// alive, and sets this flag so main() does not print it a second time.
// ----------------------------------------------------------------------------
static bool g_inferenceOutputEmitted = false;

// RAWRXD_VULKAN_TEARDOWN_FAULT_001
// Measured: with RAWRXD_ENABLE_VULKAN=1 the generation completes
// (completed=1, status=0, tokens flushed) and the process then dies with
// STATUS_ACCESS_VIOLATION during ~Deep2Engine member destruction -- after
// ~VulkanCompute's body finished and only on the Vulkan path; the CPU-only run
// exits 0. A teardown fault must not convert a completed generation into a
// crash exit code, and it must not suppress the receipt, so the engine scope
// is fenced and the fault is reported rather than swallowed.
static bool          g_teardownFaulted    = false;
static unsigned long g_teardownException  = 0;
static void*         g_teardownAddress    = nullptr;

// The generated text is committed here, before the engine can be torn down, so
// a teardown fault can still be reported against the real output instead of a
// placeholder.
static std::string g_generatedTextCommitted;

static std::string deep2RunEngine(const std::string& modelPath, const std::string& prompt, int maxTokens) {
    std::fprintf(stderr, "[CLI_DEEP2] modelPath='%s' prompt='%s' maxTokens=%d\n",
        modelPath.c_str(), prompt.c_str(), maxTokens);
    std::fflush(stderr);

    // Use the Deep2Engine via the same API as the Win32IDE chat path
    Deep2::Deep2Engine engine;
    Deep2::EngineConfig config;
    config.maxSeqLen = 4096;
    config.numThreads = 0; // auto

    if (!engine.initialize(config)) {
        std::fprintf(stderr, "[CLI_DEEP2] FAIL: Deep2Engine::initialize returned false\n"); std::fflush(stderr);
        return "[DEEP2_INIT_FAILED]";
    }
    std::fprintf(stderr, "[CLI_DEEP2] engine initialized OK\n"); std::fflush(stderr);

    // GPU policy: use the GPU unless explicitly told not to. Previously the CLI
    // read RAWRXD_ENABLE_VULKAN (opt-in) while the IDE read DEEP2_DISABLE_VULKAN
    // (opt-out), so the CLI silently ran CPU-only on the same machine where the
    // IDE used the GPU. Same name and same default as the IDE now.
    const char* vkDisableEnv = std::getenv("DEEP2_DISABLE_VULKAN");
    const char* vkEnableEnv = std::getenv("RAWRXD_ENABLE_VULKAN");
    const bool vkForceOff = vkDisableEnv && (vkDisableEnv[0] == '1' || vkDisableEnv[0] == 't' ||
                                            vkDisableEnv[0] == 'T');
    const bool vkForceOn = vkEnableEnv && (vkEnableEnv[0] == '1' || vkEnableEnv[0] == 't' ||
                                           vkEnableEnv[0] == 'T');
    const bool vkRequested = vkForceOn ? true : !vkForceOff;
    engine.enableVulkan(vkRequested);
    std::fprintf(stderr,
        "[CLI_DEEP2] Vulkan requested=%d enabled=%d initialized=%d devices=%u%s\n",
        vkRequested ? 1 : 0,
        engine.isVulkanEnabled() ? 1 : 0,
        engine.isVulkanInitialized() ? 1 : 0,
        engine.vulkanDeviceCount(),
        vkForceOff ? " (opt-out via DEEP2_DISABLE_VULKAN)" : "");
    std::fflush(stderr);
    if (!vkRequested)
        std::fprintf(stderr, "[CLI_DEEP2] Vulkan disabled (CPU-only mode)\n");
    else if (!engine.isVulkanInitialized())
        std::fprintf(stderr, "[CLI_DEEP2] Vulkan requested but NOT initialized - "
                             "no usable compute device; continuing on CPU\n");
    std::fflush(stderr);

    Deep2::ModelLoadDiag diag{};
    if (!engine.loadModel(modelPath, &diag)) {
        std::fprintf(stderr, "[CLI_DEEP2] FAIL: loadModel returned false stage=%s msg='%s' code=%d\n",
            diag.stageName.c_str(), diag.message.c_str(), diag.stageCode); std::fflush(stderr);
        return "[DEEP2_LOAD_FAILED]";
    }
    std::fprintf(stderr, "[CLI_DEEP2] model loaded OK\n"); std::fflush(stderr);

    Deep2::GenerationOptions opts;
    opts.maxTokens = maxTokens;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.topP = 1.0f;
    opts.seed = 1;

    std::string generatedText;
    auto callback = [&generatedText](int32_t tokenId, const std::string& token) -> bool {
        generatedText += token;
        return true;
    };

    std::fprintf(stderr, "[CLI_DEEP2] calling generateStream...\n"); std::fflush(stderr);
    Deep2::GenerationResult result = engine.generateStream(prompt, opts, callback);
    std::fprintf(stderr, "[CLI_DEEP2] generateStream returned completed=%d generatedTokens=%llu status=%d\n",
        result.completed ? 1 : 0, (unsigned long long)result.generatedTokens, (int)result.status);
    std::fflush(stderr);

    if (result.completed) {
        std::fprintf(stderr, "[CLI_DEEP2] SUCCESS: %zu chars generated\n", generatedText.size()); std::fflush(stderr);
        // RAWRXD_TEARDOWN_VS_INFERENCE_001: `engine` is a local in this
        // function, so ~Deep2Engine runs before main() can print the result.
        // A destructor fault therefore destroys the output as collateral and
        // makes a completed generation look like an empty one. Emit and flush
        // the inference result HERE, while `engine` is still alive, so a future
        // teardown defect can never mask inference that already succeeded.
        std::printf("%s\n", generatedText.c_str());
        std::fflush(stdout);
        g_generatedTextCommitted = generatedText;
        g_inferenceOutputEmitted = true;
        return generatedText;
    }
    std::fprintf(stderr, "[CLI_DEEP2] FAIL: generation incomplete cancelled=%d failureDetail='%s'\n",
        result.cancelled ? 1 : 0, result.failureDetail.c_str()); std::fflush(stderr);
    return "[DEEP2_GENERATION_FAILED]";
}

// RAWRXD_VULKAN_TEARDOWN_FAULT_001
// The engine lives in deep2RunEngine() so that this wrapper -- which must hold
// no object requiring unwinding -- can fence it with SEH. MSVC rejects __try
// in a function that itself needs object unwinding (C2712), so the result is
// handed back through file scope rather than a local std::string.
//
// A fault here happens AFTER the generation result has already been emitted
// and flushed, so the run is reported as the success it was, with the teardown
// exception recorded in the receipt instead of being allowed to masquerade as
// an inference failure or to take the process down with a crash exit code.
static std::string g_deep2Result;

// The SEH-guarded body, kept in its own frame. MSVC rejects __try in any
// function that needs object unwinding (C2712), and std::string assignment can
// throw, so the string work must not appear lexically inside the __try. This
// helper is an ordinary function: it may unwind freely. The caller's __try
// block contains only the call.
static void runDeep2AndStore(const std::string& modelPath,
                             const std::string& prompt, int maxTokens) {
    g_deep2Result = deep2RunEngine(modelPath, prompt, maxTokens);
}

// Returns void, not std::string: the return type would itself require
// unwinding in a function containing __try. The result is handed back through
// g_deep2Result at file scope, which is what the caller reads.
static void deep2Generate(const std::string& modelPath, const std::string& prompt, int maxTokens) {
    __try {
        runDeep2AndStore(modelPath, prompt, maxTokens);
    } __except (
        (g_teardownAddress   = GetExceptionInformation()->ExceptionRecord->ExceptionAddress,
         g_teardownException = GetExceptionInformation()->ExceptionRecord->ExceptionCode,
         EXCEPTION_EXECUTE_HANDLER))
    {
        g_teardownFaulted = true;
        std::fprintf(stderr,
            "[CLI_DEEP2] TEARDOWN_FAULT exception=0x%08lX address=%p\n"
            "[CLI_DEEP2] generation had already completed and flushed; "
            "continuing to receipt\n",
            g_teardownException, g_teardownAddress);
        std::fflush(stderr);
    }
    if (g_teardownFaulted && g_deep2Result.empty()) {
        // The fault happened after the result was flushed to stdout and
        // committed to g_generatedTextCommitted, so the generation did
        // succeed. Report the real text, not a placeholder.
        g_deep2Result = g_generatedTextCommitted;
    }
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
    // RAWRXD_VULKAN_TEARDOWN_FAULT_001: a teardown fault must not be recorded
    // as an inference failure. It is reported as its own field so the two are
    // never conflated.
    f << "GENERATION_COMPLETED=" << (!output.empty() && output[0] != '[' ? 1 : 0) << "\n";
    f << "TEARDOWN_FAULT=" << (g_teardownFaulted ? 1 : 0) << "\n";
    f << "TEARDOWN_EXCEPTION=0x"
      << std::hex << g_teardownException << std::dec << "\n";
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
            deep2Generate(modelSpec, prompt, maxTokens);
            output = g_deep2Result;
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

    // Print generated text to stdout.
    // RAWRXD_TEARDOWN_VS_INFERENCE_001: the DEEP2 route already emitted and
    // flushed its result inside deep2Generate(), before ~Deep2Engine runs.
    // Do not print it twice.
    if (!output.empty() && !g_inferenceOutputEmitted) {
        std::printf("%s\n", output.c_str());
    }

    // Write receipt
    writeReceipt(modelSpec, route, output, exitCode);

    return exitCode;
}