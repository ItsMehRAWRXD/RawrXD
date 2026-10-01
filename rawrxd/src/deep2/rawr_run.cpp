// rawr_run.cpp
// CLI entry point for: rawr run <model> [--tokens N] [--vulkan] <prompt...>
//
// Usage:
//   rawrxd_cli.exe run <model> <prompt>
//   rawrxd_cli.exe run qwen2.5-coder "audit this codebase for stubs"
//   rawrxd_cli.exe run F:\models\Qwen2.5-Coder-32B-Q4_K_M.gguf "hello"
//   rawrxd_cli.exe run --tokens 256 --vulkan <model> <prompt>
#include "rawr_run.h"
#include "rawrxd_run_modelname_001.h"
#include "cli/RawrDumpAuthority.h"
#include "agent/AgentCore.h"
#include "agent/ResponseCodedAgent.h"
#include "agentmodes/RawrModesCli.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace {

// Default repository for the agent subcommands: the directory the command was
// run from.
//
// It used to be the literal "F:\\~dev\\rawrxd", which is a path that exists on
// exactly one machine. On every other machine the agent read a repository that
// was not there, its git tools failed, and the command still printed
// VERDICT=PASS — the run and its conclusion described a different repository
// than the one on disk, or none at all.
std::string defaultRepo() {
    std::error_code ec;
    const auto p = std::filesystem::current_path(ec);
    return ec ? std::string(".") : p.string();
}

// A receipt that was never written is not evidence. The receipt writers open
// their file with fopen_s and swallow a failure, so the caller has to confirm
// the artifact exists before it is entitled to report PASS.
bool receiptOnDisk(const std::string& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) return false;
    const auto sz = std::filesystem::file_size(path, ec);
    return !ec && sz > 0;
}

} // namespace

int rawr_run_main(int argc, char** argv) {
    // argv[0] is "run" (already consumed by caller)
    // Expected: [--tokens N] [--vulkan] <model> <prompt words...>

    if (argc < 2) {
        std::fprintf(stderr,
            "Usage: rawr run [--tokens N] [--vulkan] <model> <prompt>\n"
            "\n"
            "  <model>   GGUF path or model name (searched in RAWRXD_MODEL_DIR)\n"
            "  <prompt>  Text prompt (remaining args joined with spaces)\n"
            "\n"
            "Examples:\n"
            "  rawr run qwen2.5-coder \"audit this codebase for stubs\"\n"
            "  rawr run F:\\models\\Qwen2.5-Coder-32B-Q4_K_M.gguf \"hello world\"\n"
            "  rawr run --tokens 512 --vulkan qwen2.5-coder \"explain RoPE\"\n");
        return 1;
    }

    uint32_t maxTokens   = 512;
    bool     vulkan      = false;
    int      argIdx      = 0;

    // Parse flags
    while (argIdx < argc) {
        if (std::strcmp(argv[argIdx], "--tokens") == 0 && argIdx + 1 < argc) {
            maxTokens = static_cast<uint32_t>(std::atoi(argv[argIdx + 1]));
            argIdx += 2;
        } else if (std::strcmp(argv[argIdx], "--vulkan") == 0) {
            vulkan = true;
            ++argIdx;
        } else if (std::strcmp(argv[argIdx], "--no-vulkan") == 0) {
            vulkan = false;
            ++argIdx;
        } else {
            break;
        }
    }

    if (argIdx >= argc) {
        std::fprintf(stderr, "[rawr run] ERROR: no model specified after flags\n");
        return 1;
    }

    const std::string model = argv[argIdx++];

    if (argIdx >= argc) {
        std::fprintf(stderr, "[rawr run] ERROR: no prompt specified\n");
        return 1;
    }

    // Join remaining args as prompt
    std::string prompt;
    for (int i = argIdx; i < argc; ++i) {
        if (i > argIdx) prompt += ' ';
        prompt += argv[i];
    }

    return rawrxd_run_modelname_001(model.c_str(), prompt.c_str(),
                                     maxTokens, vulkan);
}

// Standalone executable entry point
int main(int argc, char** argv) {
    // argv[0] is the executable name; shift so argv[0] is treated as "run"
    if (argc < 2) {
        std::fprintf(stderr,
            "Usage: rawr <model> <prompt>\n"
            "  or:  rawr run [--tokens N] [--vulkan] <model> <prompt>\n"
            "  or:  rawr list                 (list every selectable model)\n"
            "\n"
            "<model> may be an Ollama model name (see `rawr list`), a registered\n"
            "alias, or a .gguf path. No model is hardcoded.\n");
        return 1;
    }
    // Full selection: list every selectable model (Ollama + local + aliases)
    if (std::strcmp(argv[1], "list") == 0 ||
        std::strcmp(argv[1], "ls")   == 0 ||
        std::strcmp(argv[1], "models") == 0) {
        return rawrxd_list_models_001();
    }
    // Dump command: first-class model truth command
    if (std::strcmp(argv[1], "dump") == 0) {
        return rawrxd::cli::runRawrDump(argc - 2, argv + 2);
    }
    // Response-coded agent: rawr agent <model> "<question>"  (one bounded turn)
    if (std::strcmp(argv[1], "agent") == 0) {
        if (argc < 3) {
            std::printf("usage: rawr agent <model-ref> \"<question>\" [--repo <path>] "
                        "[--out <receipt>]\n");
            return 64;
        }
        const std::string model = argv[2];
        std::string question, repo = defaultRepo();
        std::string receipt = "_rawr_response_coded_agent_receipt.txt";
        for (int i = 3; i < argc; ++i) {
            if (std::strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) receipt = argv[++i];
            else if (question.empty()) question = argv[i];
        }
        if (question.empty()) {
            std::printf("usage: rawr agent <model-ref> \"<question>\" [--repo <path>]\n");
            return 64;
        }
        rawrxd::rcagent::LocalModelBackend backend(model);
        const rawrxd::rcagent::AgentTurn turn =
            rawrxd::rcagent::runOneTurn(question, backend, repo);
        rawrxd::rcagent::writeReceipt(receipt, turn);

        std::printf("MODEL_REF=%s\n", turn.modelRef.c_str());
        std::printf("RESOLVED_PATH=%s\n", turn.resolvedPath.c_str());
        std::printf("--- first turn ---\n%s\n", turn.firstTurn.c_str());
        if (turn.toolRequested) {
            std::printf("--- tool %s (exit %d) ---\n", turn.toolName.c_str(), turn.toolExitCode);
            std::printf("%s\n", turn.observation.c_str());
        }
        std::printf("--- final response ---\n%s\n", turn.finalResponse.c_str());
        std::printf("RATIONALE=%s\nVERDICT=%s\nreceipt=%s\n",
                    turn.rationale.c_str(), turn.verdict.c_str(), receipt.c_str());
        // The verdict is the agent's; whether it counts as a result depends on
        // the evidence existing. Reporting PASS with no receipt on disk is the
        // failure mode this check exists to prevent.
        const bool wroteReceipt = receiptOnDisk(receipt);
        std::printf("RECEIPT_WRITTEN=%d\n", wroteReceipt ? 1 : 0);
        if (!wroteReceipt) {
            std::printf("RECEIPT_ERROR=no evidence file at %s; verdict not certified\n",
                        receipt.c_str());
            return 7;
        }
        return turn.verdict == "PASS" ? 0 : 6;
    }

    // Two-turn PLAN -> ACT -> OBSERVE -> CONTINUE gate, kept under its own
    // subcommand. `agent` is owned by the single-turn response-coded agent;
    // claiming it here would silently discard that work, so the collision is
    // resolved by naming rather than by overwriting.
    if (std::strcmp(argv[1], "agent-e2e") == 0) {
        std::string model = "qwen2.5-coder:1.5b-base";
        std::string task;
        std::string repo = defaultRepo();
        std::string receipt = "_local_agent_e2e_receipt.txt";
        for (int i = 2; i < argc; ++i) {
            if (std::strcmp(argv[i], "--model") == 0 && i + 1 < argc) model = argv[++i];
            else if (std::strcmp(argv[i], "--task") == 0 && i + 1 < argc) task = argv[++i];
            else if (std::strcmp(argv[i], "--repo") == 0 && i + 1 < argc) repo = argv[++i];
            else if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) receipt = argv[++i];
        }
        if (task.empty()) {
            std::printf("usage: rawr agent-e2e --model <ref> --task \"<objective>\" "
                        "[--repo <path>] [--out <receipt>]\n");
            return 64;
        }
        rawrxd::agentcore::AgentTask t;
        t.objective = task;
        rawrxd::agentcore::LocalModelBackend backend(model);
        rawrxd::agentcore::ReadOnlyToolbox toolbox(repo);
        // Flush an interim receipt before the long second turn.
        rawrxd::agentcore::setReceiptPath(receipt);
        const rawrxd::agentcore::AgentRun run =
            rawrxd::agentcore::runReadOnly(t, backend, toolbox);
        rawrxd::agentcore::writeAgentReceipt(receipt, run);
        std::printf("MODEL_REF=%s\nMODEL_PATH=%s\n", run.modelRef.c_str(),
                    run.resolvedPath.c_str());
        for (const auto& tr : run.transitions)
            std::printf("  [%s] %s\n",
                        tr.phase == rawrxd::agentcore::Phase::Failed ? "FAIL" : "step",
                        tr.detail.c_str());
        std::printf("TOOL_REQUEST_RAW=%s\n", run.toolRequestRaw.c_str());
        std::printf("OBSERVATION=%s\n", run.observation.c_str());
        std::printf("FINAL_RESPONSE=%s\n", run.finalResponse.c_str());
        std::printf("AGENT_TURN_COUNT=%u\nGENERATED_TOKEN_COUNT=%u\n",
                    run.agentTurnCount, run.finalTokenCount);
        std::printf("RATIONALE=%s\nVERDICT=%s\nreceipt=%s\n",
                    run.rationale.c_str(), run.verdict.c_str(), receipt.c_str());
        const bool wroteReceipt = receiptOnDisk(receipt);
        std::printf("RECEIPT_WRITTEN=%d\n", wroteReceipt ? 1 : 0);
        if (!wroteReceipt) {
            std::printf("RECEIPT_ERROR=no evidence file at %s; verdict not certified\n",
                        receipt.c_str());
            return 7;
        }
        return run.verdict == "PASS" ? 0 : 5;
    }

    // Honesty-gated agent modes: modes / audit / gate / cert.
    if (std::strcmp(argv[1], "modes") == 0 ||
        std::strcmp(argv[1], "audit") == 0 ||
        std::strcmp(argv[1], "gate") == 0 ||
        std::strcmp(argv[1], "cert") == 0) {
        return rawrxd::modes::runRawrModes(argc - 1, argv + 1);
    }
    // If first arg is literally "run", consume it (for compatibility)
    int offset = 0;
    if (std::strcmp(argv[1], "run") == 0) {
        offset = 1;
    }
    int subArgc = argc - 1 - offset;
    char** subArgv = argv + 1 + offset;
    return rawr_run_main(subArgc, subArgv);
}
