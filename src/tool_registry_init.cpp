#include "tool_registry_init.hpp"
#include "tool_registry.h"
#include "engine_iface.h"
#include "GitMCPBridge.h"
#include <iostream>
#include <string>
#include <sstream>

// ============================================================================
// register_rawr_inference — Registers the RAWR inference tool with ToolRegistry.
// This tool dispatches prompts to the loaded GGUF model via EngineRegistry.
// ============================================================================
void register_rawr_inference() {
    ToolRegistry::register_tool("rawr_inference", [](const std::string& input) -> std::string {
        // Build an AgentRequest from the raw input
        AgentRequest req{};
        req.mode = 0;              // standard inference
        req.prompt = input;
        req.deep_thinking = false;
        req.deep_research = false;
        req.no_refusal = false;
        req.context_limit = 4096;

        // Try to route through EngineRegistry — pick the first available engine
        Engine* engine = EngineRegistry::get("default");
        if (!engine) engine = EngineRegistry::get("cpu");
        if (!engine) engine = EngineRegistry::get("sovereign_small");

        if (engine) {
            std::string result = engine->infer(req);
            if (!result.empty()) {
                return result;
            }
            return "[rawr_inference] Engine returned empty response";
        }

        return "[rawr_inference] No inference engine available — load a GGUF model first";
    });

    std::cout << "[REGISTRY] Registered RAWR inference tool (routes to EngineRegistry)\n";
}

void register_git_mcp_tools() {
    static RawrXD::GitIntegrator::GitMCPBridge bridge;

    ToolRegistry::register_tool("git_pr_review", [](const std::string& input) -> std::string {
        // Input format: "prNumber owner repo"
        std::stringstream ss(input);
        uint32_t pr;
        std::string owner, repo;
        if (!(ss >> pr >> owner >> repo)) return "Invalid input: expected 'prNumber owner repo'";
        
        auto review = bridge.reviewPullRequest(pr, owner, repo);
        return review.summary + "\nConfidence: " + std::to_string(review.confidence);
    });

    ToolRegistry::register_tool("git_commit_smart", [](const std::string& diff) -> std::string {
        auto proposal = bridge.proposeCommitFromDiff(diff);
        return proposal.commitMessage;
    });

    ToolRegistry::register_tool("git_blame_insight", [](const std::string& input) -> std::string {
        // Input format: "filePath startLine endLine"
        std::stringstream ss(input);
        std::string path;
        uint32_t start, end;
        if (!(ss >> path >> start >> end)) return "Invalid input: expected 'path start end'";
        
        return bridge.analyzeBlameRisk(path, start, end);
    });

    std::cout << "[REGISTRY] Registered Git MCP Bridge tools\n";
}

// ============================================================================
// register_sovereign_engines — Registers Engine800B + SovereignSmall with EngineRegistry.
// Linker fallback: when the real engine module is not linked, this provides
// a diagnostic stub that reports the missing linkage.
// ============================================================================
void register_sovereign_engines() {
    // Check if engines are already registered (real module may have beaten us)
    Engine* existing = EngineRegistry::get("engine_800b");
    if (existing) {
        std::cout << "[REGISTRY] Engine800B already registered by engine module\n";
        return;
    }

    existing = EngineRegistry::get("sovereign_small");
    if (existing) {
        std::cout << "[REGISTRY] SovereignSmall already registered by engine module\n";
        return;
    }

    // Real engine module not linked — register diagnostic tool entries
    // so the tool registry can report availability status
    ToolRegistry::register_tool("engine_800b", [](const std::string& input) -> std::string {
        return "[engine_800b] Engine module not linked. "
               "Rebuild with -DRAWR_ENGINE_MODULE=ON to enable Engine800B.";
    });

    ToolRegistry::register_tool("sovereign_small", [](const std::string& input) -> std::string {
        return "[sovereign_small] Engine module not linked. "
               "Rebuild with -DRAWR_ENGINE_MODULE=ON to enable SovereignSmall.";
    });

    std::cout << "[REGISTRY] register_sovereign_engines — engine module not linked, "
                 "diagnostic tools registered\n";
}
