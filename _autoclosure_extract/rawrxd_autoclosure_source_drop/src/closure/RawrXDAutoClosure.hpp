#pragma once
// RAWRXD_AUTOCLOSURE_001
// No third-party dependencies. C++20 + Win32 + existing Deep2Engine only.
//
// Purpose:
//   - One authoritative model path + SHA-256 identity.
//   - Deterministic bounded decode built directly on Deep2 public primitives.
//   - Strict GPU / zero-fallback certification without depending on the older
//     Deep2Engine::generate() control loop.
//   - Always-written receipts.
//   - Autonomous read/edit/build/test/retry loop with hard iteration/time bounds.
//   - Optional parent-process watchdog so a stuck GPU/driver cannot leave a gate
//     running forever.
//
// Integration:
//   #include "closure/RawrXDAutoClosure.hpp"
//   At the very beginning of WinMain/wWinMain:
//       if (RawrXD::AutoClosure::CommandLineRequested())
//           return RawrXD::AutoClosure::RunFromCurrentCommandLine();
//
// CLI example:
//   RawrXD-Win32IDE.exe --autoclose --model "G:\models\x.gguf" \
//      --workspace "F:\~dev\rawrxd" --task-file "F:\task.txt" \
//      --build "cmake --build F:\~dev\rawrxd\win32ide_strict\build_v4 --target RawrXD-Win32IDE --config Release" \
//      --test "F:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe --cert-fast" \
//      --nonce "7E91B462" --receipt "F:\autoclose_receipt.txt"
//
// The parent invocation automatically spawns an --autoclose-worker child and
// kills it on the configured wall-clock deadline. The child performs all work.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace RawrXD::AutoClosure {

struct Options {
    std::filesystem::path modelPath;
    std::filesystem::path workspace;
    std::filesystem::path taskFile;
    std::filesystem::path receiptPath = L"autoclose_receipt.txt";

    std::string task;
    std::string buildCommand;
    std::string testCommand;
    std::string nonce;

    std::string gatePrompt = "def";
    std::uint32_t gateTokens = 8;
    std::uint32_t agentTokens = 1536;
    std::uint32_t maxIterations = 24;
    std::uint32_t maxToolCalls = 64;

    std::uint64_t commandTimeoutMs = 180000;
    std::uint64_t wallTimeoutMs = 1800000; // parent watchdog: 30 min

    bool strictGpu = true;
    bool requireRealGpuForward = true;
    bool requireZeroFallback = true;
    bool autoBuildAfterEdit = true;
    bool runGateBeforeAgent = true;
};

struct GateResult {
    bool pass = false;
    std::string failStage;
    std::string failMessage;

    std::string modelSha256;
    std::uint64_t modelBytes = 0;

    std::uint64_t promptTokens = 0;
    std::uint64_t generatedTokens = 0;
    std::uint64_t gpuFallbackDelta = 0;

    bool modelLoaded = false;
    bool tokenizerReady = false;
    bool forwardPassOk = false;
    bool logitsFinite = false;
    bool realGpuForward = false;
    bool strictGpuViolation = false;

    std::vector<int> generated;
    std::string generatedText;
};

struct AgentResult {
    bool pass = false;
    std::string failStage;
    std::string failMessage;

    std::uint32_t iterations = 0;
    std::uint32_t toolCalls = 0;
    std::uint32_t filesEdited = 0;
    std::uint32_t buildRuns = 0;
    std::uint32_t testRuns = 0;

    bool finalBuildPass = false;
    bool finalTestPass = false;
    bool finishedByModel = false;

    std::string finalMessage;
};

bool CommandLineRequested();
int RunFromCurrentCommandLine();

// Direct API for embedding in a command handler if preferred.
int Run(const Options& options);

} // namespace RawrXD::AutoClosure
