// Lane B (RawrEngine headless): resolves symbols referenced by agentic_bridge_headless.cpp
// without linking the full subagent_core.cpp / Win32IDE Phase16-17 translation units.
#include "subagent_core.h"
// Completes BulkFixOrchestrator for SubAgentManager's unique_ptr member destructor.
#include "Win32IDE_Phase16_AgenticController.h"
#include "Win32IDE_Phase17_AgenticProfiler.h"
#include "agent/autonomous_subagent.hpp"

#include <atomic>
#include <sstream>
#include <windows.h>

// -----------------------------------------------------------------------------
// SubAgentManager — minimal no-thread implementation (dispatchToolCall returns false)
// -----------------------------------------------------------------------------

SubAgentManager::SubAgentManager(AgenticEngine* engine) : m_engine(engine) {}

SubAgentManager::~SubAgentManager()
{
    cancelAll();
}

std::string SubAgentManager::spawnSubAgent(const std::string& /*parentId*/, const std::string& /*description*/,
                                           const std::string& /*prompt*/)
{
    return "headless-sa-stub";
}

void SubAgentManager::cancelAll() {}

bool SubAgentManager::waitForSubAgent(const std::string& /*agentId*/, int /*timeoutMs*/)
{
    return true;
}

std::string SubAgentManager::getSubAgentResult(const std::string& /*agentId*/) const
{
    return {};
}

std::string SubAgentManager::executeChain(const std::string& /*parentId*/,
                                          const std::vector<std::string>& /*promptTemplates*/,
                                          const std::string& /*initialInput*/)
{
    return {};
}

std::string SubAgentManager::executeSwarm(const std::string& /*parentId*/, const std::vector<std::string>& /*prompts*/,
                                          const SwarmConfig& /*config*/)
{
    return {};
}

std::string SubAgentManager::getStatusSummary() const
{
    return "SubAgentManager(headless_lane_b_stub)";
}

bool SubAgentManager::dispatchToolCall(const std::string& /*parentId*/, const std::string& /*modelOutput*/,
                                       std::string& toolResult)
{
    toolResult.clear();
    return false;
}

// -----------------------------------------------------------------------------
// Phase 17 profiler exports (C linkage) + C++ helpers used by headless bridge
// -----------------------------------------------------------------------------

static std::atomic<uint64_t> g_agenticEpochCount{0};
static std::atomic<uint64_t> g_agenticEpochStartTick{0};
static std::atomic<uint64_t> g_agenticTokenSamples{0};
static std::atomic<uint64_t> g_agenticToolStarts{0};
static std::atomic<uint64_t> g_agenticToolEnds{0};
static std::atomic<uint64_t> g_agenticToolOk{0};
static std::atomic<uint64_t> g_agenticToolFail{0};
static std::atomic<uint64_t> g_agenticDurAccum{0};
static std::atomic<uint64_t> g_lastToolHash{0};

extern "C" uint64_t RawrXD_Agentic_SampleProfileToken(uint32_t slot)
{
    (void)slot;
    g_agenticTokenSamples.fetch_add(1, std::memory_order_relaxed);
    return GetTickCount64();
}

extern "C" void AgenticProfilerBeginEpoch(void)
{
    g_agenticEpochCount.fetch_add(1, std::memory_order_relaxed);
    g_agenticEpochStartTick.store(GetTickCount64(), std::memory_order_relaxed);
}

extern "C" uint64_t AgenticProfilerGetElapsed(void)
{
    const uint64_t start = g_agenticEpochStartTick.load(std::memory_order_relaxed);
    if (start == 0)
    {
        return 0;
    }
    const uint64_t now = GetTickCount64();
    return (now >= start) ? (now - start) : 0;
}

bool AgenticNotifyToolStart(const char* toolName)
{
    g_agenticToolStarts.fetch_add(1, std::memory_order_relaxed);
    uint64_t h = 1469598103934665603ULL;
    if (toolName)
    {
        for (const unsigned char* p = reinterpret_cast<const unsigned char*>(toolName); *p; ++p)
        {
            h ^= static_cast<uint64_t>(*p);
            h *= 1099511628211ULL;
        }
    }
    g_lastToolHash.store(h, std::memory_order_relaxed);
    return true;
}

void AgenticNotifyToolEnd(bool success, uint32_t latencyMs)
{
    g_agenticToolEnds.fetch_add(1, std::memory_order_relaxed);
    if (success)
    {
        g_agenticToolOk.fetch_add(1, std::memory_order_relaxed);
    }
    else
    {
        g_agenticToolFail.fetch_add(1, std::memory_order_relaxed);
    }
    g_agenticDurAccum.fetch_add(static_cast<uint64_t>(latencyMs), std::memory_order_relaxed);
}

std::string AgenticProfilerTopSummary(uint32_t maxTools)
{
    std::ostringstream oss;
    const uint64_t starts = g_agenticToolStarts.load(std::memory_order_relaxed);
    const uint64_t ends = g_agenticToolEnds.load(std::memory_order_relaxed);
    const uint64_t ok = g_agenticToolOk.load(std::memory_order_relaxed);
    const uint64_t fail = g_agenticToolFail.load(std::memory_order_relaxed);
    const uint64_t totalDur = g_agenticDurAccum.load(std::memory_order_relaxed);
    const uint64_t avgDur = ends ? (totalDur / ends) : 0;
    oss << "headless requested=" << maxTools << " elapsed_ticks=" << AgenticProfilerGetElapsed()
        << " epochs=" << g_agenticEpochCount.load(std::memory_order_relaxed) << " starts=" << starts << " ends=" << ends
        << " ok=" << ok << " fail=" << fail << " avg_latency_ms=" << avgDur
        << " token_samples=" << g_agenticTokenSamples.load(std::memory_order_relaxed)
        << " last_tool_hash=" << g_lastToolHash.load(std::memory_order_relaxed);
    return oss.str();
}

uint32_t Phase17Profiler::GetEpochCount()
{
    return static_cast<uint32_t>(g_agenticEpochCount.load(std::memory_order_relaxed));
}
