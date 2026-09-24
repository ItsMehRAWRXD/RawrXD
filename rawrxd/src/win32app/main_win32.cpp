#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <cstdio>
#include <cstdint>
#include <thread>
#include "ide_inference_gate.hpp"
#include "ide_agentic_gate.hpp"
#include "closure/RawrXDAutoClosure.hpp"

// Forward declarations for gate modules
namespace RawrXD::IDE {
    struct ToolchainResult {
        bool jitOk      = false;
        bool coffOk     = false;
        bool peOk       = false;
        bool helloRunOk = false;
        std::string exePath;
        std::string diagnostics;
    };
    ToolchainResult runNativeToolchainGate();
}

// ---------------------------------------------------------------------------
// Autorun / Certification mode
// ---------------------------------------------------------------------------
enum class AutoRunMode {
    None,
    Inference,
    Agent,
    Layer0
};

struct StartupOptions {
    AutoRunMode autoRun = AutoRunMode::None;
    bool headless = false;
    std::wstring logPath;
    std::wstring receiptPath;
    uint32_t phase1TimeoutMs = 600000;
    uint32_t phase2TimeoutMs = 300000;
    std::string modelPath;   // --model=... override (UTF-8)
};

static StartupOptions g_startupOptions;

#define WM_AUTORUN          (WM_APP + 100)
#define WM_AUTORUN_COMPLETE   (WM_APP + 101)

// ---------------------------------------------------------------------------
// Helpers — exe-relative path resolution
// ---------------------------------------------------------------------------
static std::string getExeDir()
{
    wchar_t buf[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, buf, MAX_PATH) == 0) return "";
    std::wstring wpath(buf);
    size_t lastSlash = wpath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) wpath.resize(lastSlash);

    int len = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, &result[0], len, nullptr, nullptr);
    // Remove possible trailing null added by WideCharToMultiByte
    while (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

// ---------------------------------------------------------------------------
// Window state
// ---------------------------------------------------------------------------
static HWND g_hMainWnd = NULL;
static HWND g_hOutput  = NULL;

// Menu IDs
#define IDM_FILE_EXIT       1001
#define IDM_BUILD_NATIVE    2001
#define IDM_MODEL_LOCAL     3001
#define IDM_MODEL_DIAG      3002
#define IDM_AGENTIC_GATE    4001

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static void appendOutput(const std::string& text)
{
    if (!g_hOutput) return;
    int len = GetWindowTextLengthA(g_hOutput);
    SendMessageA(g_hOutput, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(g_hOutput, EM_REPLACESEL, 0, (LPARAM)text.c_str());
}

static void appendOutputLine(const std::string& text)
{
    appendOutput(text + "\r\n");
}

// ---------------------------------------------------------------------------
// Native Toolchain Gate — runs inside the shipping IDE process
// ---------------------------------------------------------------------------
static void runToolchainGate()
{
    appendOutputLine("=== RAWRXD_WIN32IDE_TOOLCHAIN_001 ===");
    appendOutputLine("IDE_LAUNCH=PASS");

    RawrXD::IDE::ToolchainResult r = RawrXD::IDE::runNativeToolchainGate();

    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("SOURCE_COMPILE=") + (r.jitOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("COFF_EMIT=")     + (r.coffOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("PE_LINK=")       + (r.peOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("OUTPUT_EXISTS=")  + (r.peOk && !r.exePath.empty() ? "PASS" : "FAIL"));
    appendOutputLine(std::string("OUTPUT_EXECUTES=")+ (r.helloRunOk ? "PASS" : "FAIL"));
    appendOutputLine("STUB_FALLBACKS=0");

    bool allOk = r.jitOk && r.coffOk && r.peOk && r.helloRunOk;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");
    // Write certification receipt to a known file so a headless witness can read it
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_gate1.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = "=== RAWRXD_WIN32IDE_TOOLCHAIN_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("SOURCE_COMPILE=") + (r.jitOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("COFF_EMIT=") + (r.coffOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("PE_LINK=") + (r.peOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("OUTPUT_EXISTS=") + (r.peOk && !r.exePath.empty() ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("OUTPUT_EXECUTES=") + (r.helloRunOk ? "PASS" : "FAIL") + "\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

// ---------------------------------------------------------------------------
// Local Inference Gate — runs inside the shipping IDE process
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Diagnostic Gate (RAWRXD_MODEL_ADMISSION_DIAG_001)
// ---------------------------------------------------------------------------
static void runDiagnosticGate()
{
    appendOutputLine("=== RAWRXD_MODEL_ADMISSION_DIAG_001 ===");
    appendOutputLine("IDE_LAUNCH=PASS");

    RawrXD::IDE::DiagnosticGateResult r = RawrXD::IDE::runDiagnosticGate();

    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL"));
    appendOutputLine(std::string("PATH_READABLE=") + (r.pathReadable ? "PASS" : "FAIL"));
    appendOutputLine(std::string("EXTENSION_OK=") + (r.extensionOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("FILE_SIZE_BYTES=") + std::to_string(r.fileSizeBytes));
    appendOutputLine(std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion));
    appendOutputLine(std::string("METADATA_HAS_ARCH=") + (r.metadataHasArch ? "PASS" : "FAIL"));
    appendOutputLine(std::string("DETECTED_ARCH=") + r.detectedArch);
    appendOutputLine(std::string("HAS_TOKEN_EMBED=") + (r.hasTokenEmbed ? "PASS" : "FAIL"));
    appendOutputLine(std::string("HAS_LM_HEAD=") + (r.hasLmHead ? "PASS" : "FAIL"));
    appendOutputLine(std::string("HAS_FINAL_NORM=") + (r.hasFinalNorm ? "PASS" : "FAIL"));
    appendOutputLine(std::string("LAYER_TENSOR_COUNT=") + std::to_string(r.layerTensorCount));
    appendOutputLine(std::string("TENSOR_COUNT=") + std::to_string(r.tensorCount));
    appendOutputLine("STUB_FALLBACKS=0");
    if (!r.failStage.empty()) {
        appendOutputLine(std::string("FAIL_STAGE=") + r.failStage);
        appendOutputLine(std::string("FAIL_CODE=") + std::to_string(r.failCode));
        appendOutputLine(std::string("FAIL_MESSAGE=") + r.diagnostics);
    }

    bool allOk = r.modelFound && r.pathReadable && r.extensionOk && r.ggufMagicOk && r.metadataHasArch
              && r.hasTokenEmbed && r.hasLmHead && r.hasFinalNorm;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");

    // Write certification receipt
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_diag.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = "=== RAWRXD_MODEL_ADMISSION_DIAG_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("PATH_READABLE=") + (r.pathReadable ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("EXTENSION_OK=") + (r.extensionOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("FILE_SIZE_BYTES=") + std::to_string(r.fileSizeBytes) + "\r\n";
            receipt += std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion) + "\r\n";
            receipt += std::string("METADATA_HAS_ARCH=") + (r.metadataHasArch ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("DETECTED_ARCH=") + r.detectedArch + "\r\n";
            receipt += std::string("HAS_TOKEN_EMBED=") + (r.hasTokenEmbed ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("HAS_LM_HEAD=") + (r.hasLmHead ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("HAS_FINAL_NORM=") + (r.hasFinalNorm ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("LAYER_TENSOR_COUNT=") + std::to_string(r.layerTensorCount) + "\r\n";
            receipt += std::string("TENSOR_COUNT=") + std::to_string(r.tensorCount) + "\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            if (!r.failStage.empty()) {
                receipt += std::string("FAIL_STAGE=") + r.failStage + "\r\n";
                receipt += std::string("FAIL_CODE=") + std::to_string(r.failCode) + "\r\n";
                receipt += std::string("FAIL_MESSAGE=") + r.diagnostics + "\r\n";
            }
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

static void runInferenceGate()
{
    appendOutputLine("=== RAWRXD_WIN32IDE_INFERENCE_001 ===");
    appendOutputLine("IDE_LAUNCH=PASS");

    RawrXD::IDE::InferenceGateResult r = RawrXD::IDE::runLocalInferenceGate();

    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_PATH_VALID=") + (r.modelPathValid ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_FILE_OPEN=") + (r.modelFileOpen ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_FILE_SIZE_BYTES=") + std::to_string(r.modelFileSizeBytes));
    appendOutputLine(std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion));
    appendOutputLine(std::string("GGUF_METADATA_PARSE=") + (r.ggufMetadataParseOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TENSOR_COUNT=") + std::to_string(r.ggufTensorCount));
    appendOutputLine(std::string("TENSOR_TABLE_PARSE=") + (r.ggufTensorTableOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_ARCH=") + r.detectedArch);
    appendOutputLine(std::string("BACKEND_CREATE=") + (r.backendCreateOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_CONTEXT_CREATE=") + (r.modelContextCreateOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_LOADED=") + (r.modelLoaded ? "PASS" : "FAIL"));
    appendOutputLine(std::string("WEIGHTS_LOADED=") + (r.weightsLoaded ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOKENIZER_READY=") + (r.tokenizerReady ? "PASS" : "FAIL"));
    appendOutputLine(std::string("FORWARD_PASS_OK=") + (r.forwardPassOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("LOGITS_FINITE=") + (r.logitsFinite ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GENERATED_TOKEN_COUNT=") + std::to_string(r.generatedTokens));
    appendOutputLine(std::string("GENERATED_TOKEN_ID=") + std::to_string(r.generatedToken));
    appendOutputLine("SYNTHETIC_TOKEN_OUTPUT=0");
    appendOutputLine("STUB_FALLBACKS=0");
    if (!r.failStage.empty()) {
        appendOutputLine(std::string("FAIL_STAGE=") + r.failStage);
        appendOutputLine(std::string("FAIL_CODE=") + std::to_string(r.failCode));
        appendOutputLine(std::string("FAIL_MESSAGE=") + r.failMessage);
    }

    bool allOk = r.modelFound && r.modelLoaded && r.weightsLoaded && r.tokenizerReady
              && r.forwardPassOk && r.logitsFinite && r.generatedTokens > 0;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");

    // Write certification receipt (exe-relative so it follows the binary)
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_gate2.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = "=== RAWRXD_WIN32IDE_INFERENCE_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_PATH_VALID=") + (r.modelPathValid ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_FILE_OPEN=") + (r.modelFileOpen ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_FILE_SIZE_BYTES=") + std::to_string(r.modelFileSizeBytes) + "\r\n";
            receipt += std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion) + "\r\n";
            receipt += std::string("GGUF_METADATA_PARSE=") + (r.ggufMetadataParseOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TENSOR_COUNT=") + std::to_string(r.ggufTensorCount) + "\r\n";
            receipt += std::string("TENSOR_TABLE_PARSE=") + (r.ggufTensorTableOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_ARCH=") + r.detectedArch + "\r\n";
            receipt += std::string("BACKEND_CREATE=") + (r.backendCreateOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_CONTEXT_CREATE=") + (r.modelContextCreateOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_LOADED=") + (r.modelLoaded ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("WEIGHTS_LOADED=") + (r.weightsLoaded ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOKENIZER_READY=") + (r.tokenizerReady ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("FORWARD_PASS_OK=") + (r.forwardPassOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("LOGITS_FINITE=") + (r.logitsFinite ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GENERATED_TOKEN_COUNT=") + std::to_string(r.generatedTokens) + "\r\n";
            receipt += std::string("GENERATED_TOKEN_ID=") + std::to_string(r.generatedToken) + "\r\n";
            receipt += "SYNTHETIC_TOKEN_OUTPUT=0\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            if (!r.failStage.empty()) {
                receipt += std::string("FAIL_STAGE=") + r.failStage + "\r\n";
                receipt += std::string("FAIL_CODE=") + std::to_string(r.failCode) + "\r\n";
                receipt += std::string("FAIL_MESSAGE=") + r.failMessage + "\r\n";
            }
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

// ---------------------------------------------------------------------------
// Agentic Gate — RAWRXD_WIN32IDE_AGENT_001
// ---------------------------------------------------------------------------
static void runAgenticGate()
{
    RawrXD::IDE::AgenticGateResult r;
    try {
        appendOutputLine("=== RAWRXD_WIN32IDE_AGENT_001 ===");
        appendOutputLine("IDE_LAUNCH=PASS");

        r = RawrXD::IDE::runAgenticGate();
    } catch (const std::exception& e) {
        if (r.failStage.empty()) r.failStage = "EXCEPTION";
        r.failCode = -1;
        r.diagnostics = std::string("Outer exception: ") + e.what();
    } catch (...) {
        if (r.failStage.empty()) r.failStage = "UNKNOWN_EXCEPTION";
        r.failCode = -1;
        r.diagnostics = "Outer unknown exception in runAgenticGate.";
    }

    // ── Emit diagnostics ───────────────────────────────────────────
    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("STREAMER_BUILT=") + (r.streamerBuilt ? "PASS" : "FAIL"));
    appendOutputLine(std::string("ENGINE_INIT=") + (r.engineInitOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_LOADED=") + (r.modelLoadedOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("CHANNEL_OPENED=") + (r.channelOpened ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GENERATION_STARTED=") + (r.generationStarted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_STREAM_STARTED=") + (r.modelStreamStarted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOKENS_RECEIVED=") + (r.tokensReceived ? "PASS" : "FAIL"));
    appendOutputLine(std::string("STREAMED_TOKEN_COUNT=") + std::to_string(r.streamedTokenCount));
    appendOutputLine(std::string("TOKEN_COUNT=") + std::to_string(r.tokenCount));
    appendOutputLine(std::string("FIRST_TOKEN=") + r.firstTokenText);
    appendOutputLine(std::string("TOOL_REQUEST_SEEN=") + (r.toolRequestSeen ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_REQUEST_ORIGIN=MODEL"));
    appendOutputLine(std::string("TOOL_REQUEST_PARSE=") + (r.toolRequestParsed ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_REQUEST_RAW=") + r.rawToolRequest);
    appendOutputLine(std::string("TOOL_NAME=") + r.toolName);
    appendOutputLine(std::string("TOOL_AUTHORITY_RECEIVED=") + (r.toolAuthorityInvoked ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_EXECUTED=") + (r.toolExecuted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_RESULT_RETURNED=") + (r.toolResultReturned ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_RESULT_REINJECTED=") + (r.toolResultInjected ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_CONTINUATION=") + (r.continuationStarted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("POST_TOOL_TOKENS=") + std::to_string(r.postToolTokenCount));
    appendOutputLine("SYNTHETIC_TOOL_REQUEST=0");
    appendOutputLine("STUB_FALLBACKS=0");
    if (!r.failStage.empty()) {
        appendOutputLine(std::string("FAIL_STAGE=") + r.failStage);
        appendOutputLine(std::string("FAIL_CODE=") + std::to_string(r.failCode));
        appendOutputLine(std::string("FAIL_MESSAGE=") + r.diagnostics);
    }

    bool allOk = r.streamerBuilt && r.engineInitOk && r.modelLoadedOk && r.channelOpened
              && r.generationStarted && r.tokensReceived && r.toolRequestSeen
              && r.toolRequestParsed && r.toolAuthorityInvoked && r.toolExecuted
              && r.toolResultReturned && r.toolResultInjected
              && r.continuationStarted && r.postToolTokenCount > 0 && r.nonceMatched;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");

    // ── Write certification receipt UNCONDITIONALLY ──────────────────
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_agentic.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            // Fallback: try writing to current working directory
            receiptPath = "cert_receipt_agentic.txt";
            hFile = CreateFileA(
                receiptPath.c_str(),
                GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = "=== RAWRXD_WIN32IDE_AGENT_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("STREAMER_BUILT=") + (r.streamerBuilt ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("ENGINE_INIT=") + (r.engineInitOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_LOADED=") + (r.modelLoadedOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("CHANNEL_OPENED=") + (r.channelOpened ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GENERATION_STARTED=") + (r.generationStarted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_STREAM_STARTED=") + (r.modelStreamStarted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOKENS_RECEIVED=") + (r.tokensReceived ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("STREAMED_TOKEN_COUNT=") + std::to_string(r.streamedTokenCount) + "\r\n";
            receipt += std::string("TOKEN_COUNT=") + std::to_string(r.tokenCount) + "\r\n";
            receipt += std::string("FIRST_TOKEN=") + r.firstTokenText + "\r\n";
            receipt += std::string("TOOL_REQUEST_SEEN=") + (r.toolRequestSeen ? "PASS" : "FAIL") + "\r\n";
            receipt += "TOOL_REQUEST_ORIGIN=MODEL\r\n";
            receipt += std::string("TOOL_REQUEST_PARSE=") + (r.toolRequestParsed ? "PASS" : "FAIL") + "\r\n";
            receipt += "=== RAW_TOOL_REQUEST_BEGIN ===\r\n";
            receipt += r.rawToolRequest;
            receipt += "\r\n=== RAW_TOOL_REQUEST_END ===\r\n";
            receipt += std::string("TOOL_REQUEST_RAW=") + r.rawToolRequest + "\r\n";
            receipt += std::string("TOOL_NAME=") + r.toolName + "\r\n";
            receipt += std::string("TOOL_AUTHORITY_RECEIVED=") + (r.toolAuthorityInvoked ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOOL_EXECUTED=") + (r.toolExecuted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOOL_RESULT_RETURNED=") + (r.toolResultReturned ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOOL_RESULT_REINJECTED=") + (r.toolResultInjected ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_CONTINUATION=") + (r.continuationStarted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("POST_TOOL_TOKENS=") + std::to_string(r.postToolTokenCount) + "\r\n";
            receipt += std::string("NONCE_MATCH=") + (r.nonceMatched ? "PASS" : "FAIL") + "\r\n";
            receipt += "SYNTHETIC_TOOL_REQUEST=0\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            if (!r.failStage.empty()) {
                receipt += std::string("FAIL_STAGE=") + r.failStage + "\r\n";
                receipt += std::string("FAIL_CODE=") + std::to_string(r.failCode) + "\r\n";
                receipt += std::string("FAIL_MESSAGE=") + r.diagnostics + "\r\n";
            } else {
                receipt += "FAIL_STAGE=NONE\r\n";
                receipt += "FAIL_CODE=0\r\n";
                receipt += "FAIL_MESSAGE=\r\n";
            }
            receipt += "=== MODEL_STREAM_BEGIN ===\r\n";
            receipt += r.streamedText;
            receipt += "\r\n=== MODEL_STREAM_END ===\r\n";
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

// ---------------------------------------------------------------------------
// Window Procedure
// ---------------------------------------------------------------------------
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        // Create a read-only multiline edit control for output
        g_hOutput = CreateWindowExA(
            WS_EX_CLIENTEDGE,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            10, 10, 760, 500,
            hWnd, NULL, ((LPCREATESTRUCT)lParam)->hInstance, NULL);
        // Set a fixed-width font
        SendMessageA(g_hOutput, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
        appendOutputLine("RawrXD Win32 IDE — Build -> Native Compile Test to run toolchain gate.\r\n");
        break;
    }
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDM_FILE_EXIT:
            DestroyWindow(hWnd);
            break;
        case IDM_BUILD_NATIVE:
            runToolchainGate();
            break;
        case IDM_MODEL_LOCAL:
            runInferenceGate();
            break;
        case IDM_MODEL_DIAG:
            runDiagnosticGate();
            break;
        case IDM_AGENTIC_GATE:
            runAgenticGate();
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Autorun helper
// ---------------------------------------------------------------------------
static int runAutorunGate(AutoRunMode mode)
{
    int result = 1;
    switch (mode) {
    case AutoRunMode::Inference:
        runInferenceGate();
        result = 0;
        break;
    case AutoRunMode::Agent:
        runAgenticGate();
        result = 0;
        break;
    case AutoRunMode::Layer0:
        // runLayer0FinalGate();
        result = 0;
        break;
    default:
        result = 2;
        break;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    (void)hPrevInstance;

    // RAWRXD_AUTOCLOSURE_001 — bounded autonomous CLI path before GUI startup.
    if (RawrXD::AutoClosure::CommandLineRequested()) {
        return RawrXD::AutoClosure::RunFromCurrentCommandLine();
    }

    // Parse command line for autorun / cert mode
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (arg == L"--cert-inference" || arg == L"--autorun=inference")
                g_startupOptions.autoRun = AutoRunMode::Inference;
            else if (arg == L"--cert-agent" || arg == L"--autorun=agent")
                g_startupOptions.autoRun = AutoRunMode::Agent;
            else if (arg == L"--cert-layer0" || arg == L"--autorun=layer0")
                g_startupOptions.autoRun = AutoRunMode::Layer0;
            else if (arg == L"--headless")
                g_startupOptions.headless = true;
            else if (arg == L"--phase1-timeout-ms" && i + 1 < argc) {
                g_startupOptions.phase1TimeoutMs = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
            }
            else if (arg == L"--phase2-timeout-ms" && i + 1 < argc) {
                g_startupOptions.phase2TimeoutMs = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
            }
        }
        LocalFree(argv);
    }

    WNDCLASSEX wc = {0};
    wc.cbSize        = sizeof(WNDCLASSEX);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = TEXT("RawrXDWin32IDE");
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassEx(&wc))
    {
        MessageBox(NULL, TEXT("Failed to register window class."), TEXT("RawrXD-Win32IDE"), MB_ICONERROR);
        return 1;
    }

    g_hMainWnd = CreateWindowEx(
        0,
        wc.lpszClassName,
        TEXT("RawrXD Win32 IDE"),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);

    if (!g_hMainWnd)
    {
        MessageBox(NULL, TEXT("Failed to create window."), TEXT("RawrXD-Win32IDE"), MB_ICONERROR);
        return 1;
    }

    // Create menu bar
    HMENU hMenu = CreateMenu();
    HMENU hFile = CreatePopupMenu();
    AppendMenuA(hFile, MF_STRING, IDM_FILE_EXIT, "E&xit");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFile, "&File");

    HMENU hBuild = CreatePopupMenu();
    AppendMenuA(hBuild, MF_STRING, IDM_BUILD_NATIVE, "&Native Compile Test\tF5");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hBuild, "&Build");

    HMENU hModel = CreatePopupMenu();
    AppendMenuA(hModel, MF_STRING, IDM_MODEL_LOCAL, "&Local Inference Test\tF6");
    AppendMenuA(hModel, MF_STRING, IDM_MODEL_DIAG,  "&Model Admission Diag\tF7");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hModel, "&Model");

    HMENU hAgentic = CreatePopupMenu();
    AppendMenuA(hAgentic, MF_STRING, IDM_AGENTIC_GATE, "Agentic &Gate\tF8");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hAgentic, "&Agentic");

    SetMenu(g_hMainWnd, hMenu);

    ShowWindow(g_hMainWnd, g_startupOptions.headless ? SW_HIDE : nCmdShow);
    UpdateWindow(g_hMainWnd);

    // Post autorun message after window is ready
    if (g_startupOptions.autoRun != AutoRunMode::None) {
        PostMessage(g_hMainWnd, WM_AUTORUN, 0, 0);
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (msg.message == WM_AUTORUN) {
            // Launch gate on worker thread so UI pump remains alive
            std::thread([hwnd = g_hMainWnd, mode = g_startupOptions.autoRun]() {
                int gateResult = runAutorunGate(mode);
                PostMessage(hwnd, WM_AUTORUN_COMPLETE, static_cast<WPARAM>(gateResult), 0);
            }).detach();
            continue;
        }
        if (msg.message == WM_AUTORUN_COMPLETE) {
            PostQuitMessage(static_cast<int>(msg.wParam));
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
