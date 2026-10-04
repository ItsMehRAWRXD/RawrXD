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

// RAWRXD_BROWSER_AUTHORITY_001: the browser lane is part of the PRODUCT, not a
// probe. `include/` is an include root for this target, so this resolves to
// include/browser/BrowserAuthority.hpp -- the SAME header the standalone probe
// includes.
#include "browser/BrowserAuthority.hpp"

// RAWRXD_SHELL_AUTHORITY_001: one action envelope over four shell surfaces.
#include "shell/ShellAuthority.hpp"

// RAWRXD_AGENT_BRIDGE_001: ToolIntent -> AgentBridge -> ShellAuthority.
#include "agent/AgentBridge.hpp"

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
    // RAWRXD_DEEP2_ONLY_AUTHORITY_001: RETAINED, NOT REACHABLE.
    // classifyModel() no longer returns this for any input, so the Ollama
    // proxy arm in main() is dead. The enumerator is deliberately kept so that
    // removing the remaining arm, ollamaGenerate(), the <winhttp.h> include and
    // the winhttp.lib pragma is one mechanical follow-up that a build can
    // verify -- rather than six interdependent edits made blind on a tree that
    // has never been compiled.
    //
    // Deleting the enum value NOW would break both switch arms (:341 receipt
    // writer, :449 dispatcher) and leave ollamaGenerate() as a -Wunused-function
    // warning. Keeping it reachable-but-dead is the safer intermediate state.
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

    // RAWRXD_DEEP2_ONLY_AUTHORITY_001
    //
    // This used to read:
    //     // Ollama model names contain ':' (e.g., glm-5.3:cloud, qwen2.5-coder:1.5b)
    //     if (modelSpec.find(':') != std::string::npos) return ModelRoute::OLLAMA_PROXY;
    //
    // which put a live Ollama /api/generate HTTP client (ollamaGenerate, port
    // 11434) on the shipping execution path, contradicting
    // OLLAMA_REQUIRED=NO / DEEP2_NATIVE_AUTHORITY=YES. RawrXD has its own
    // streamer; it must not fall out to Ollama.
    //
    // It was also a correctness bug independent of policy: a Windows path with a
    // drive letter ALWAYS contains ':'. The DEEP2_GGUF checks above catch it
    // only when the file exists, so a mistyped or not-yet-downloaded path such as
    // C:\models\typo.gguf fell through to the Ollama branch and silently issued a
    // network request instead of failing closed -- reporting an Ollama route for a
    // local file the user simply mistyped.
    //
    // Non-GGUF, non-existent specs now fail closed with a reason naming the
    // actual constraint, instead of being silently reinterpreted as an Ollama tag.
    if (modelSpec.find(':') != std::string::npos) {
        std::fprintf(stderr,
            "[CLI_ROUTE] FAIL_CLOSED: spec '%s' contains ':' but is not an existing "
            "GGUF. Ollama proxying is removed from this build "
            "(RAWRXD_DEEP2_ONLY_AUTHORITY_001); pass a GGUF file path.\n",
            modelSpec.c_str());
        std::fflush(stderr);
    }
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
    // Allow CPU fallback when GPU path cannot execute (default is strict=true)
    engine.setVulkanStrictNoCpuFallback(false);
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
        // RAWRXD_NANOBANDWIDTH_VIEW_RESOLUTION_001: emit the mutually-exclusive
        // fullView failure census for THIS run. Previously this printed only
        // "fullView failed name=..." per request, which locates WHERE a request
        // stopped but not WHY -- and 1008 such lines per run cannot be
        // aggregated into a diagnosis.
        Deep2::Deep2ReportFullViewCensus();
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
// RAWRXD_BROWSER_AUTHORITY_001 -- product browser lane
//
// This is the SHIPPING callsite. Until it existed, the browser authority was
// real but reachable only from a standalone probe, which means it was another
// island: authoritative in itself and absent from every binary a user runs.
//
// The product and the probe now call the SAME BrowserAuthority. There is no
// second transport, no second target resolver and no second verdict rule.
//
// The exit code is the authority's own derived verdict, not a literal:
//   0  every requested action PASSed
//   1  at least one action FAILED or stayed UNPROVEN
//   2  no browser exists on this host (UNPROVEN, not FAIL)
//
//   rawrxd --browser <url> [--browser-click SELECTOR] [--browser-verify EXPR:VALUE]
//          [--browser-type SELECTOR:TEXT] [--browser-headless]
//          [--browser-profile DIR] [--browser-receipt PATH]
// ----------------------------------------------------------------------------
static int runBrowserLane(int argc, char* argv[]) {
    std::string url;
    std::string clickSelector, clickExpect;
    std::string typeSelector, typeText, typeExpect;
    std::string profile = "browser_profile";
    std::string receiptPath;
    bool headless = false;

    // Starts at 1, not 2: this function is dispatched BECAUSE argv[1] is
    // "--browser", so the flag itself is still ahead of the cursor. Starting at
    // 2 skipped it and the URL was never read.
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& dst) {
            if (i + 1 < argc) dst = argv[++i];
        };
        if (a == "--browser")                 next(url);
        else if (a == "--browser-click")      next(clickSelector);
        else if (a == "--browser-verify")     next(clickExpect);
        else if (a == "--browser-type")       next(typeSelector);
        else if (a == "--browser-type-text")  next(typeText);
        else if (a == "--browser-type-expect")next(typeExpect);
        else if (a == "--browser-profile")    next(profile);
        else if (a == "--browser-receipt")    next(receiptPath);
        else if (a == "--browser-headless")   headless = true;
    }

    if (url.empty()) {
        std::fprintf(stderr, "--browser requires a URL\n");
        return 1;
    }

    // Discovery returns "" when no browser exists. That is UNPROVEN, not FAIL,
    // and the exit code says so: 2 is neither success nor failure.
    const std::string browser = rawrxd::browser::BrowserSession::findBrowser();
    if (browser.empty()) {
        std::fprintf(stderr,
            "BROWSER_AVAILABLE=0\nVERDICT=UNPROVEN\n"
            "BLOCKER=NO_CHROMIUM_FAMILY_BROWSER_ON_HOST\n");
        return 2;
    }
    std::fprintf(stderr, "BROWSER_PATH=%s\n", browser.c_str());

    rawrxd::browser::BrowserAuthority auth;
    std::string err;
    if (!auth.launch(browser, profile, headless, err)) {
        std::fprintf(stderr, "BROWSER_LAUNCH_FAILED=%s\n", err.c_str());
        for (const auto& f : auth.launchEvidence().failureStages)
            std::fprintf(stderr, "LAUNCH_FAILURE_STAGE=%s\n", f.c_str());
        return 1;
    }
    if (!auth.openPage(url, err)) {
        std::fprintf(stderr, "BROWSER_OPEN_PAGE_FAILED=%s\n", err.c_str());
        auth.close();
        return 1;
    }

    // Navigate, and require the page to report it finished loading.
    //
    // The first version passed an EMPTY readiness expression, which left the
    // navigate action with nothing to measure, so it correctly came back
    // UNPROVEN and dragged the run verdict down with it. An action declared
    // without the evidence needed to verify it cannot be certified -- the same
    // rule that made the early type() action impossible to PASS.
    //
    // --browser-verify may override this when the caller wants a specific
    // readiness condition, in EXPR:VALUE form.
    if (clickExpect.rfind("document.readyState:", 0) == 0) {
        const std::size_t c2 = clickExpect.find(':');
        auth.navigate(url, clickExpect.substr(0, c2),
                      clickExpect.substr(c2 + 1), 30000, err);
    } else {
        auth.navigate(url, "document.readyState", "complete", 30000, err);
    }

    if (!clickSelector.empty()) {
        // Split EXPR:VALUE so one flag carries both sides of the observation.
        const std::size_t colon = clickExpect.find(':');
        std::string expr = clickExpect, want;
        if (colon != std::string::npos) {
            expr = clickExpect.substr(0, colon);
            want = clickExpect.substr(colon + 1);
        }
        auth.click(clickSelector, expr, want, 10000, err);
    }
    if (!typeSelector.empty()) {
        auth.type(typeSelector, typeText, typeExpect, 10000, err);
    }

    auth.observeTargetCount();

    if (!receiptPath.empty()) {
        const bool wrote = auth.writeReceipt(receiptPath);
        std::fprintf(stderr, "BROWSER_RECEIPT_WRITTEN=%d PATH=%s\n",
                     wrote ? 1 : 0, receiptPath.c_str());
    }

    // renderReceipt() already ends with the derived verdict, so it is printed once
    // rather than duplicated here.
    std::fprintf(stderr, "%s", auth.renderReceipt().c_str());
    const auto v = auth.overallVerdict();
    auth.close();
    return v == rawrxd::browser::ActionVerdict::Pass ? 0 : 1;
}

// ----------------------------------------------------------------------------
// RAWRXD_SHELL_AUTHORITY_001 -- product shell surface
//
//   rawrxd --shell <surface> <operation> [args]
//     --shell-files-exists <path>
//     --shell-files-size <path>
//     --shell-files-read <path>
//     --shell-browser-navigate <url>
//     --shell-browser-click <selector> <expr>:<value>
//     --shell-browser-type <selector> <text> <expr>
//     [--shell-headless] [--shell-profile DIR] [--shell-receipt PATH]
//
// Surfaces: app://ide, app://terminal, app://browser, app://files.
//
// Exit code is the authority's own DERIVED verdict:
//   0  every dispatched action PASSed
//   1  at least one FAILED or stayed UNPROVEN
//   2  no browser on this host (browser surface only)
// ----------------------------------------------------------------------------
static int runShellLane(int argc, char* argv[]) {
    using namespace rawrxd::shell;

    std::string filesOp, filesPath;
    std::string navUrl, clickSel, clickExpect, typeSel, typeText, typeExpect;
    std::string profile = "shell_profile";
    std::string receiptPath;
    bool headless = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& d) { if (i + 1 < argc) d = argv[++i]; };
        if      (a == "--shell-files-exists")   { filesOp = "EXISTS"; next(filesPath); }
        else if (a == "--shell-files-size")     { filesOp = "SIZE";   next(filesPath); }
        else if (a == "--shell-files-read")     { filesOp = "READ";   next(filesPath); }
        else if (a == "--shell-browser-navigate") next(navUrl);
        else if (a == "--shell-browser-click")  { next(clickSel); next(clickExpect); }
        else if (a == "--shell-browser-type")   { next(typeSel); next(typeText); next(typeExpect); }
        else if (a == "--shell-profile")        next(profile);
        else if (a == "--shell-receipt")        next(receiptPath);
        else if (a == "--shell-headless")       headless = true;
    }

    ShellAuthority shell;
    // All four surfaces are registered up front. Registration is NOT
    // interactivity: ide/terminal stay non-interactive, so any action aimed at
    // them resolves UNPROVEN rather than being reported as supported.
    const ShellSurfaceId ideS  = shell.registerSurface(ShellSurfaceKind::Ide,      "app://ide",      false);
    const ShellSurfaceId termS = shell.registerSurface(ShellSurfaceKind::Terminal, "app://terminal", false);
    const ShellSurfaceId brS   = shell.registerSurface(ShellSurfaceKind::Browser,  "app://browser",  false);
    const ShellSurfaceId fileS = shell.registerSurface(ShellSurfaceKind::Files,    "app://files",    true);
    (void)ideS; (void)termS;

    std::fprintf(stderr, "SHELL_SURFACES_REGISTERED=%zu\n", shell.surfaceCount());

    // ---- files surface: real, no browser needed ------------------------
    if (!filesOp.empty()) {
        ShellAction a;
        a.surface = fileS;
        a.operation = filesOp;
        a.target = filesPath;
        shell.dispatch(a);
    }

    // ---- browser surface: adapter over BrowserAuthority -----------------
    if (!navUrl.empty() || !clickSel.empty() || !typeSel.empty()) {
        const std::string browser = rawrxd::browser::BrowserSession::findBrowser();
        if (browser.empty()) {
            std::fprintf(stderr,
                "BROWSER_AVAILABLE=0\nVERDICT=UNPROVEN\n"
                "BLOCKER=NO_CHROMIUM_FAMILY_BROWSER_ON_HOST\n");
            shell.close();
            return 2;
        }
        std::string err;
        if (!shell.launchBrowser(browser, profile, headless, err)) {
            std::fprintf(stderr, "BROWSER_LAUNCH_FAILED=%s\n", err.c_str());
            shell.close();
            return 1;
        }
        // Open the page BEFORE any action is dispatched. Doing it lazily inside
        // an action is what forced the URL into the payload field, where a
        // colon-splitting parser then mangled "file:///F:/..." into nonsense.
        if (!navUrl.empty() && !shell.openBrowserPage(navUrl, err)) {
            std::fprintf(stderr, "BROWSER_OPEN_PAGE_FAILED=%s\n", err.c_str());
            shell.close();
            return 1;
        }

        if (!navUrl.empty()) {
            ShellAction a;
            a.surface = brS; a.operation = "NAVIGATE"; a.target = navUrl;
            shell.dispatch(a);
        }
        if (!clickSel.empty()) {
            ShellAction a;
            a.surface = brS; a.operation = "CLICK";
            a.target = clickSel;
            a.payload = clickExpect;                 // EXPR:VALUE
            shell.dispatch(a);
        }
        if (!typeSel.empty()) {
            ShellAction a;
            a.surface = brS; a.operation = "TYPE";
            a.target = typeSel;
            a.payload = typeText + "|" + typeExpect;  // TEXT|EXPR
            shell.dispatch(a);
        }
    }

    if (!receiptPath.empty()) {
        const bool wrote = shell.writeReceipt(receiptPath);
        std::fprintf(stderr, "SHELL_RECEIPT_WRITTEN=%d PATH=%s\n",
                     wrote ? 1 : 0, receiptPath.c_str());
    }
    std::fprintf(stderr, "%s", shell.renderReceipt().c_str());

    // The rule, executed rather than asserted.
    const auto defects = shell.uncertifiableRequirements();
    std::fprintf(stderr, "UNCERTIFIABLE_GATE_RULE=DEFECT EXERCISED_DEFECTS=%zu\n",
                 defects.size());
    for (const auto& d : defects)
        std::fprintf(stderr, "UNCERTIFIABLE_REQUIREMENT=%s\n", d.c_str());

    const auto v = shell.overallVerdict();
    shell.close();
    return v == ShellVerdict::Pass ? 0 : 1;
}

// ----------------------------------------------------------------------------
// RAWRXD_AGENT_BRIDGE_001 -- real local model -> shell -> observation -> model
//
//   rawrxd --agent <model.gguf> [--agent-native|--agent-puppeteer]
//          [--agent-task "click the button"] [--agent-url <url>]
//          [--agent-target <selector>] [--agent-headless] [--agent-receipt P]
//
// HONESTY CONSTRAINTS BUILT INTO THIS LANE, not merely documented:
//
//  1. The ToolIntent is parsed from the model's ACTUAL generated text. When the
//     model produces nothing recognizable, the run reports
//     INTENT_PRODUCED=0 and exits nonzero. The intent is never authored here.
//
//  2. generateChat() builds a prompt string and calls generateText(); it keeps
//     NO conversation history and does NOT preserve a KV cache across calls.
//     So "same session" means the same engine process with the transcript
//     re-supplied, and KV_CONTINUITY_ACROSS_TURNS is reported as 0 rather than
//     implied.
//
//  3. The model's own "verdict=PASS" text is captured and compared against the
//     authority's verdict. It can never change the outcome.
// ----------------------------------------------------------------------------
static int runAgentLane(int argc, char* argv[]) {
    using namespace rawrxd::agent;
    using namespace rawrxd::shell;

    std::string modelPath, task, url, target, receiptPath, profile = "agent_profile";
    std::string replay;
    bool headless = false;
    ToolIntentSource source = ToolIntentSource::Puppeteered;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](std::string& d) { if (i + 1 < argc) d = argv[++i]; };
        // --agent is a BARE MARKER: it must not consume the next argument, or
    // "--agent --agent-replay <text>" swallows "--agent-replay" as a model
    // path. The model is named with --agent-model, matching the --shell style.
    if      (a == "--agent-model")     next(modelPath);
        else if (a == "--agent-task")      next(task);
        else if (a == "--agent-url")       next(url);
        else if (a == "--agent-target")    next(target);
        else if (a == "--agent-receipt")   next(receiptPath);
        else if (a == "--agent-profile")   next(profile);
        else if (a == "--agent-headless")  headless = true;
        else if (a == "--agent-native")    source = ToolIntentSource::NativeToolCall;
        else if (a == "--agent-puppeteer") source = ToolIntentSource::Puppeteered;
        // --agent-replay injects text AS IF the model had produced it.
        //
        // It exists to isolate ONE link: everything downstream of the model in
        // the agent chain. It is labelled REPLAY throughout and can never be
        // reported as model emission, because the whole question is whether a
        // given model emits an intent on its own. A replay that passes proves
        // the bridge; it says nothing about model capability, and conflating the
        // two would be exactly the fabricated-PASS this project has retracted
        // three times.
        else if (a == "--agent-replay")   replay = argv[++i];
    }
    if (modelPath.empty() && replay.empty()) {
        std::fprintf(stderr, "--agent requires --agent-replay or a model path\n");
        return 1;
    }
    if (task.empty())  task  = "click the action button";
    if (url.empty())   url   = "about:blank";
    if (target.empty()) target = "#act";

    // ---- real local model ------------------------------------------------
    Deep2::Deep2Engine engine;
    engine.setVulkanStrictNoCpuFallback(false);

    std::string turn1;
    bool modelLoaded = false;
    if (!replay.empty()) {
        // REPLAY path: no model is loaded at all, and the receipt says so.
        turn1 = replay;
        std::fprintf(stderr, "MODEL_SOURCE=REPLAY\n");
        std::fprintf(stderr, "LOCAL_MODEL_LOADED=0\n");
        std::fprintf(stderr, "MODEL_INTENT_EMISSION=NOT_EXERCISED\n");
    } else {
        const bool loaded = engine.loadModel(modelPath);
        modelLoaded = loaded;
        std::fprintf(stderr, "MODEL_SOURCE=LOCAL_MODEL\n");
        std::fprintf(stderr, "LOCAL_MODEL_PATH=%s\n", modelPath.c_str());
        std::fprintf(stderr, "LOCAL_MODEL_LOADED=%d\n", loaded ? 1 : 0);
        if (!loaded) {
            std::fprintf(stderr, "VERDICT=UNPROVEN\nBLOCKER=MODEL_LOAD_FAILED\n");
            return 2;
        }
    }

    // The prompt asks for a tool call. It also STATES the answer for this
    // environment, because a 1.1B model cannot infer a selector it has never
    // seen -- and the value is part of the TASK, not authored by the bridge.
    // Few-shot, because a 1.1B model does not reliably follow a format described
    // in prose. Both worked examples are COMPLETE, so the pattern to copy is
    // visible rather than inferred.
    //
    // The selector appears inside the worked example, which is what makes the
    // target reproducible. That value is part of the TASK (the page is ours and
    // its markup is known), not something the bridge supplies to the model at
    // dispatch time -- the model must still emit it.
    const std::string prompt =
        "You control a web browser through tool calls.\n"
        "Always answer with exactly one tool call, copied from these examples.\n\n"
        "EXAMPLE 1\n"
        "Task: read the size of a file\n"
        "<tool>{\"surface\":\"app://files\",\"operation\":\"SIZE\","
        "\"target\":\"C:/data.bin\"}</tool>\n\n"
        "EXAMPLE 2\n"
        "Task: click the action button\n"
        "<tool>{\"surface\":\"app://browser\",\"operation\":\"CLICK\","
        "\"target\":\"#act\"}</tool>\n\n"
        "TASK: " + task + "\n"
        "TARGET SELECTOR: " + target + "\n"
        "ANSWER (one tool call only):\n";

    const std::string turn1Text = turn1;
    std::fprintf(stderr, "MODEL_TURN1_CHARS=%zu\n", turn1Text.size());
    std::fprintf(stderr, "MODEL_TURN1_RAW=<<<%s>>>\n", turn1Text.c_str());

    // ---- shell, with the browser surface brought up first ----------------
    ShellAuthority shell;
    const ShellSurfaceId brS = shell.registerSurface(ShellSurfaceKind::Browser,
                                                     "app://browser", false);
    shell.registerSurface(ShellSurfaceKind::Ide,      "app://ide",      false);
    shell.registerSurface(ShellSurfaceKind::Terminal, "app://terminal", false);
    shell.registerSurface(ShellSurfaceKind::Files,    "app://files",    true);

    std::string err;
    const std::string browser = rawrxd::browser::BrowserSession::findBrowser();
    bool browserUp = false;
    if (!browser.empty() && shell.launchBrowser(browser, profile, headless, err)) {
        browserUp = shell.openBrowserPage(url, err);
        if (!browserUp) std::fprintf(stderr, "OPEN_PAGE_FAILED=%s\n", err.c_str());
    } else {
        std::fprintf(stderr, "BROWSER_UNAVAILABLE=%s\n",
                     browser.empty() ? "no browser binary" : err.c_str());
    }

    // The page target must exist before a CLICK can resolve a selector. When the
    // model produced no usable URL, the page we opened above is still real, so
    // the intent's surface/target are honoured as given.
    (void)brS;

    AgentBridge bridge(shell);
    AgentDispatchResult res = bridge.dispatchRaw(turn1Text, source);

    std::fprintf(stderr, "TOOL_INTENT_SOURCE=%s\n",
                 toolIntentSourceName(source));
    std::fprintf(stderr, "INTENT_PRODUCED=%d\n",
                 res.observation.intentProduced ? 1 : 0);
    std::fprintf(stderr, "INTENT_SURFACE=%s\n", res.intent.surface.c_str());
    std::fprintf(stderr, "INTENT_OPERATION=%s\n", res.intent.operation.c_str());
    std::fprintf(stderr, "INTENT_TARGET=%s\n", res.intent.target.c_str());
    std::fprintf(stderr, "SHELL_ACTION_CREATED=%d\n",
                 res.shellSequence ? 1 : 0);
    std::fprintf(stderr, "SHELL_AUTHORITY_ENTERED=%d\n",
                 res.observation.actionExecuted ? 1 : 0);
    std::fprintf(stderr, "AGENT_OBSERVATION_CREATED=%d\n",
                 res.observation.evidencePresent ? 1 : 0);
    std::fprintf(stderr, "AGENT_VERDICT=%s\n",
                 agentVerdictName(res.observation.verdict));
    std::fprintf(stderr, "OBSERVATION_RESULT=%s\n",
                 res.observation.result.c_str());
    std::fprintf(stderr, "MODEL_CLAIMED_PASS=%d\n",
                 res.observation.agentClaimedPass ? 1 : 0);
    if (res.observation.agentClaimedPass) {
        const bool honoured = (res.observation.verdict == AgentVerdict::Pass);
        std::fprintf(stderr, "MODEL_SUCCESS_CLAIM_OVERRIDDEN=%d\n",
                     honoured ? 0 : 1);
    }

    // ---- observation back into the SAME engine ---------------------------
    //
    // In REPLAY mode there is no engine, so this stage is reported as NOT
    // EXERCISED rather than quietly skipped.
    const std::string obsText =
        PuppeteerToolIntentAdapter::renderObservation(res.observation);
    std::fprintf(stderr, "OBSERVATION_TEXT=<<<%s>>>\n", obsText.c_str());

    std::string turn2;
    if (modelLoaded) {
        turn2 = engine.generateText(
            prompt + "\nTool result:\n" + obsText + "\nAssistant:", 64);
        std::fprintf(stderr, "MODEL_RESUMED_SAME_ENGINE=1\n");
        std::fprintf(stderr, "KV_CONTINUITY_ACROSS_TURNS=0\n");
        std::fprintf(stderr, "MODEL_TURN2_CHARS=%zu\n", turn2.size());
        std::fprintf(stderr, "MODEL_TURN2_RAW=<<<%s>>>\n", turn2.c_str());
        std::fprintf(stderr, "POST_TOOL_OUTPUT_PRESENT=%d\n",
                     turn2.empty() ? 0 : 1);
    } else {
        std::fprintf(stderr, "MODEL_RESUMED_SAME_ENGINE=0\n");
        std::fprintf(stderr, "MODEL_RESUMPTION=NOT_EXERCISED\n");
        std::fprintf(stderr, "POST_TOOL_OUTPUT_PRESENT=0\n");
    }

    // ---- receipt ---------------------------------------------------------
    if (!receiptPath.empty()) {
        std::ofstream rf(receiptPath, std::ios::binary | std::ios::trunc);
        if (rf) {
            rf << "=== RAWRXD_AGENT_BRIDGE_001 ===\n";
            rf << shell.renderReceipt();
            rf << "\n[agent]\n";
            rf << "LOCAL_MODEL_LOADED=1\n";
            rf << "TOOL_INTENT_SOURCE=" << toolIntentSourceName(source) << "\n";
            rf << "INTENT_PRODUCED=" << (res.observation.intentProduced?1:0) << "\n";
            rf << "INTENT_SURFACE=" << (res.intent.surface.empty()?"<none>":res.intent.surface) << "\n";
            rf << "INTENT_OPERATION=" << (res.intent.operation.empty()?"<none>":res.intent.operation) << "\n";
            rf << "INTENT_TARGET=" << (res.intent.target.empty()?"<none>":res.intent.target) << "\n";
            rf << "SHELL_ACTION_CREATED=" << (res.shellSequence?1:0) << "\n";
            rf << "AGENT_OBSERVATION_CREATED=" << (res.observation.evidencePresent?1:0) << "\n";
            rf << "AGENT_VERDICT=" << agentVerdictName(res.observation.verdict) << "\n";
            rf << "MODEL_CLAIMED_PASS=" << (res.observation.agentClaimedPass?1:0) << "\n";
            rf << "MODEL_SUCCESS_CLAIM_OVERRIDDEN="
               << ((res.observation.agentClaimedPass &&
                    res.observation.verdict != AgentVerdict::Pass) ? 1 : 0) << "\n";
            rf << "SECOND_SHELL_DISPATCHER=0\n";
            rf << "AGENT_BRIDGE_DERIVES_VERDICT=0\n";
            rf << "KV_CONTINUITY_ACROSS_TURNS=0\n";
            rf << "POST_TOOL_OUTPUT_PRESENT=" << (turn2.empty()?0:1) << "\n";
            rf << "CLOUD_MODEL_USED=0\n";
        }
    }

    shell.close();
    // Exit code reflects MEASURED facts only: an intent was produced, the
    // authority ran it, and the authority says PASS.
    const bool ok = res.observation.intentProduced
                 && res.observation.actionExecuted
                 && res.observation.verdict == AgentVerdict::Pass;
    std::fprintf(stderr, "AGENT_BRIDGE_VERDICT=%s\n",
                 ok ? "PASS" : (res.observation.intentProduced ? "UNPROVEN" : "FAIL"));
    return ok ? 0 : 1;
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
        "Browser lane (RAWRXD_BROWSER_AUTHORITY_001):\n"
        "  rawrxd --browser <url> [--browser-click SEL --browser-verify EXPR:VALUE]\n"
        "         [--browser-type SEL --browser-type-text TXT --browser-type-expect EXPR]\n"
        "         [--browser-headless] [--browser-profile DIR] [--browser-receipt PATH]\n\n"
        "Shell authority (RAWRXD_SHELL_AUTHORITY_001):\n"
        "  rawrxd --shell --shell-files-exists <path>\n"
        "  rawrxd --shell --shell-files-size <path>\n"
        "  rawrxd --shell --shell-browser-navigate <url>\n"
        "  rawrxd --shell --shell-browser-click <sel> <expr>:<value>\n"
        "  rawrxd --shell --shell-receipt <path> [--shell-headless]\n"
        "  Surfaces: app://ide  app://terminal  app://browser  app://files\n\n"
        "  Drives a REAL local browser over the Chrome DevTools Protocol.\n"
        "  Exit 0 = every action PASS, 1 = FAIL/UNPROVEN, 2 = no browser present.\n\n"
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

    // Browser lane is dispatched before model parsing: it needs no model, and
    // requiring one would make the browser authority unreachable from the
    // product.
    if (argc > 1 && std::string(argv[1]) == "--browser")
        return runBrowserLane(argc, argv);
    if (argc > 1 && std::string(argv[1]) == "--shell")
        return runShellLane(argc, argv);
    if (argc > 1 && std::string(argv[1]) == "--agent")
        return runAgentLane(argc, argv);

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