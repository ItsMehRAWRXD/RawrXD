#include "ReapRuntime.hpp"

#include "reap/ReapRuntimePlan.hpp"
#include "Deep2Engine.h"
#include "deep2/RawrModelAlias.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

namespace RawrXD::Reap {
namespace {

namespace fs = std::filesystem;

struct MemSample {
    uint64_t freePhys = 0;
    uint64_t commitLimit = 0;
    uint64_t commitAvail = 0;
    uint64_t commitUsed = 0;
    uint64_t procWorkingSet = 0;
    uint64_t procPagefile = 0;
    uint64_t procPeakWorkingSet = 0;
    uint64_t procPeakPagefile = 0;
};

MemSample sampleMem() {
    MemSample s{};
#ifdef _WIN32
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        s.freePhys = ms.ullAvailPhys;
        s.commitLimit = ms.ullTotalPageFile;
        s.commitAvail = ms.ullAvailPageFile;
        s.commitUsed = (ms.ullTotalPageFile > ms.ullAvailPageFile)
            ? (ms.ullTotalPageFile - ms.ullAvailPageFile) : 0;
    }
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc))) {
        s.procWorkingSet = pmc.WorkingSetSize;
        s.procPagefile = pmc.PagefileUsage;
        s.procPeakWorkingSet = pmc.PeakWorkingSetSize;
        s.procPeakPagefile = pmc.PeakPagefileUsage;
    }
#endif
    return s;
}

std::string quote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (const unsigned char c : value) {
        if (c == '\\' || c == '"') out << '\\' << static_cast<char>(c);
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 0x20) out << '?';
        else out << static_cast<char>(c);
    }
    out << '"';
    return out.str();
}

bool firstShardFor(const fs::path& input, fs::path& first, std::string& error) {
    std::error_code ec;
    if (fs::is_regular_file(input, ec)) {
        first = input;
        return true;
    }
    if (!fs::is_directory(input, ec)) {
        error = "MODEL_PATH_NOT_FOUND:" + input.string();
        return false;
    }

    fs::path fallback;
    for (const auto& entry : fs::directory_iterator(input, ec)) {
        if (ec || !entry.is_regular_file(ec) || entry.path().extension() != ".gguf") continue;
        if (fallback.empty()) fallback = entry.path();
        const std::string name = entry.path().filename().string();
        if (name.find("-00001-of-") != std::string::npos) {
            first = entry.path();
            return true;
        }
    }
    if (!fallback.empty()) {
        first = fallback;
        return true;
    }
    error = "NO_GGUF_SHARD_FOUND:" + input.string();
    return false;
}

bool resolveModel(const std::string& input, std::string& enginePath,
                  std::string& planPath, std::string& error) {
    Deep2::rawr_run::AliasResolve alias{};
    if (!Deep2::rawr_run::ResolveModelAlias(input.c_str(), alias) || !alias.resolved) {
        error = "MODEL_ALIAS_UNRESOLVED:" + input;
        return false;
    }
    enginePath = alias.path;
    fs::path first;
    if (!firstShardFor(fs::path(alias.path), first, error)) return false;
    // Deep2Engine's multi-shard loader expects the canonical first shard, not
    // the directory that contains it. Keep planning and execution on the same
    // resolved file so the receipt identifies the exact loaded source.
    enginePath = first.string();
    planPath = enginePath;
    return true;
}

} // namespace

RuntimeResult RunRuntime(const RuntimeRequest& request) {
    RuntimeResult result{};
    RuntimeTarget target{};
    std::string error;
    if (!ParseRuntimeTarget(request.target, target, error)) {
        result.receipt = "{\"status\":\"INVALID_TARGET\",\"reason\":" + quote(error) +
                         ",\"writer_invoked\":false,\"source_immutable\":true}\n";
        return result;
    }

    std::string enginePath;
    std::string planPath;
    if (!resolveModel(request.model, enginePath, planPath, error)) {
        result.receipt = "{\"status\":\"MODEL_RESOLUTION_FAILED\",\"reason\":" + quote(error) +
                         ",\"writer_invoked\":false,\"source_immutable\":true}\n";
        return result;
    }

    RuntimePlan plan{};
    if (!BuildRuntimePlan(planPath, target, plan, error)) {
        result.receipt = "{\"status\":\"PLAN_FAILED\",\"reason\":" + quote(error) +
                         ",\"writer_invoked\":false,\"source_immutable\":true}\n";
        return result;
    }

    Deep2::Deep2Engine engine;
    RuntimeInjection injection{};
    injection.parameterCount = target.parameterCount;
    injection.expertCount = target.expertCount;
    injection.workingSetBytes = plan.targetWorkingSetBytes;
    injection.enabled = true;
    // Opt-in only: valued --reap stays residency unless --physical or
    // RAWR_REAP_PHYSICAL=1. Tip14 residency semantics are not redefined.
    const char* physicalEnv = std::getenv("RAWR_REAP_PHYSICAL");
    const bool physicalEnvOn =
        physicalEnv && physicalEnv[0] == '1' && physicalEnv[1] == '\0';
    injection.physicalExclude = request.physicalExclude || physicalEnvOn;
    if (!engine.configureReapRuntimeInjection(injection)) {
        const auto& receipt = engine.reapRuntimeReceipt();
        result.receipt = "{\"status\":\"CONFIGURATION_FAILED\",\"reason\":" +
            quote(receipt.reason) + ",\"writer_invoked\":false,\"source_immutable\":true}\n";
        return result;
    }

    const MemSample memPre = sampleMem();
    const auto started = std::chrono::steady_clock::now();
    const bool loaded = engine.loadModel(enginePath);
    const auto elapsedLoad = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();
    const auto& configuredReceipt = engine.reapRuntimeReceipt();
    const MemSample memPostLoad = sampleMem();

    // PATH_A: reduction never became active (load/config before physical apply).
    // PATH_B: physicalExclude active; failure during retained expert acquire/gen.
    std::string failPhase = "NONE";
    if (!loaded) {
        // Reduction is "active" only after MoE path stamps ACTIVE_PHYSICAL_*.
        if (configuredReceipt.physicalExclude &&
            configuredReceipt.status.find("ACTIVE_PHYSICAL") != std::string::npos)
            failPhase = "DURING_RETAINED_ACQUIRE";
        else
            failPhase = "BEFORE_REDUCTION_ACTIVE";
    }

    std::string generated;
    Deep2::GenerationResult generation{};
    bool generationRequested = !request.prompt.empty();
    bool generationPass = !generationRequested;
    if (loaded && generationRequested) {
        Deep2::GenerationOptions options{};
        options.maxTokens = (std::max)(uint32_t{1}, request.maxTokens);
        options.temperature = 0.0f;
        options.topP = 1.0f;
        options.topK = 1;
        options.repeatPenalty = 1.0f;
        options.seed = 0;
        generation = engine.generateStream(
            request.prompt, options,
            [&](int32_t, const std::string& token) {
                generated += token;
                return true;
            });
        generationPass = generation.completed && generation.generatedTokens > 0;
        if (!generationPass)
            failPhase = "DURING_RETAINED_ACQUIRE";
    }
    const MemSample memPost = sampleMem();

    const bool loadPass = loaded;
    const bool runtimePass = loadPass && generationPass &&
                             configuredReceipt.sourceImmutable &&
                             configuredReceipt.active;
    if (runtimePass) failPhase = "NONE";
    std::ostringstream receipt;
    receipt << "{\"schema\":\"rawrxd.reap.runtime_receipt.v1\""
            << ",\"status\":" << quote(runtimePass ? "PASS" : (loadPass ? "PARTIAL" : "LOAD_FAILED"))
            << ",\"fail_phase\":" << quote(failPhase)
            << ",\"model\":" << quote(enginePath)
            << ",\"plan\":" << RuntimePlanJson(plan).substr(0, RuntimePlanJson(plan).size() - 1)
            << ",\"runtime\":{\"active\":" << (configuredReceipt.active ? "true" : "false")
            << ",\"route_configured\":" << (configuredReceipt.routeConfigured ? "true" : "false")
            << ",\"streamer_configured\":" << (configuredReceipt.streamerConfigured ? "true" : "false")
            << ",\"working_set_configured\":" << (configuredReceipt.workingSetConfigured ? "true" : "false")
            << ",\"physical_exclude\":" << (configuredReceipt.physicalExclude ? "true" : "false")
            << ",\"residency_only\":" << (configuredReceipt.residencyOnly ? "true" : "false")
            << ",\"retained_experts\":" << configuredReceipt.retainedExperts
            << ",\"effective_experts\":" << configuredReceipt.effectiveExperts
            << ",\"status\":" << quote(configuredReceipt.status)
            << ",\"reason\":" << quote(configuredReceipt.reason) << "}"
            << ",\"memory\":{\"free_phys_pre\":" << memPre.freePhys
            << ",\"free_phys_post_load\":" << memPostLoad.freePhys
            << ",\"free_phys_post\":" << memPost.freePhys
            << ",\"commit_limit\":" << memPost.commitLimit
            << ",\"commit_used_post\":" << memPost.commitUsed
            << ",\"proc_ws_post\":" << memPost.procWorkingSet
            << ",\"proc_pagefile_post\":" << memPost.procPagefile
            << ",\"proc_peak_ws\":" << memPost.procPeakWorkingSet
            << ",\"proc_peak_pagefile\":" << memPost.procPeakPagefile << "}"
            << ",\"generation_requested\":" << (generationRequested ? "true" : "false")
            << ",\"generation_completed\":" << (generation.completed ? "true" : "false")
            << ",\"generated_tokens\":" << generation.generatedTokens
            << ",\"prompt_tokens\":" << generation.promptTokens
            << ",\"load_ms\":" << elapsedLoad
            << ",\"output\":" << quote(generated)
            << ",\"writer_invoked\":false,\"source_immutable\":true"
            << ",\"physical_repack\":0,\"promote\":0,\"certified\":0}\n";
    result.receipt = receipt.str();
    result.exitCode = runtimePass ? 0 : 4;
    if (!request.receiptPath.empty()) {
        std::ofstream out(request.receiptPath, std::ios::binary | std::ios::trunc);
        if (!out) {
            result.exitCode = 5;
        } else {
            out << result.receipt;
            if (!out) result.exitCode = 5;
        }
    }
    return result;
}

} // namespace RawrXD::Reap
