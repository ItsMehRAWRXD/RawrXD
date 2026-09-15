// =============================================================================
// agent_tool_authority_selftest.cpp
// Gate: RAWRXD_AGENT_TOOL_AUTHORITY_001
// =============================================================================
// Verifies that AgentToolRegistry is the SINGLE tool-dispatch authority and
// that all 5 surfaces (CLI, GUI, Headless, Swarm, AgenticLoop) reach it
// through AgentToolAuthority::Dispatch().
//
// Pass criteria (GatePass):
//   1. AgentToolAuthority::Get() returns non-null after registration
//   2. Dispatch through each surface increments the corresponding reach_* counter
//   3. All bypass_* counters remain 0
//   4. AgentToolAuthoritySnapshot::GatePass() returns true
//
// Build: cl.exe /std:c++20 /EHsc /I src agent_tool_authority_selftest.cpp
//        src/agentic/AgentToolAuthority.cpp src/agentic/ToolRegistry.cpp
//        (plus required dependency libs)
// =============================================================================

#include "../src/agentic/AgentToolAuthority.hpp"
#include "../src/agentic/ToolRegistry.h"
#include <iostream>
#include <cassert>
#include <string>

using RawrXD::Agent::AgentToolRegistry;
using RawrXD::Agent::AgentToolAuthority;
using RawrXD::Agent::AgentToolRequest;
using RawrXD::Agent::AgentToolResult;
using RawrXD::Agent::AgentToolSurface;
using RawrXD::Agent::AgentToolAuthoritySnapshot;

static int g_failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "FAIL: " << (msg) << " (line " << __LINE__ << ")\n"; \
        ++g_failures; \
    } else { \
        std::cout << "PASS: " << (msg) << "\n"; \
    } \
} while(0)

// ---------------------------------------------------------------------------
// Test 1: Authority registration via CAS
// ---------------------------------------------------------------------------
static void test_authority_registration() {
    std::cout << "\n=== Test 1: Authority Registration ===\n";

    AgentToolAuthority::ResetForTests();
    auto* registry = &AgentToolRegistry::Instance();

    bool registered = AgentToolAuthority::Register(nullptr, registry);
    CHECK(registered, "CAS register succeeds with nullptr expected");

    auto* got = AgentToolAuthority::Get();
    CHECK(got != nullptr, "Get() returns non-null after registration");
    CHECK(got == registry, "Get() returns the registered registry");

    // Double-register should fail (CAS mismatch)
    bool doubleReg = AgentToolAuthority::Register(nullptr, registry);
    CHECK(!doubleReg, "Double-register fails (CAS already set)");
}

// ---------------------------------------------------------------------------
// Test 2: Dispatch through each surface increments reach counters
// ---------------------------------------------------------------------------
static void test_surface_reach() {
    std::cout << "\n=== Test 2: Surface Reach Counters ===\n";

    // Dispatch a read_file through each surface
    const char* surfaces[] = {"cli", "gui", "headless", "swarm", "agentic_loop"};
    for (const char* surface : surfaces) {
        AgentToolRequest req;
        req.tool_name = "list_directory";
        req.caller_surface = surface;
        req.args = {{"path", "."}};

        AgentToolResult result = AgentToolAuthority::Dispatch(req);
        CHECK(result.success, std::string("Dispatch succeeds for surface: ") + surface);
    }

    auto snap = AgentToolAuthority::CaptureSnapshot();
    CHECK(snap.reach_cli >= 1, "reach_cli >= 1");
    CHECK(snap.reach_gui >= 1, "reach_gui >= 1");
    CHECK(snap.reach_headless >= 1, "reach_headless >= 1");
    CHECK(snap.reach_swarm >= 1, "reach_swarm >= 1");
    CHECK(snap.reach_agentic_loop >= 1, "reach_agentic_loop >= 1");
}

// ---------------------------------------------------------------------------
// Test 3: Bypass counters remain zero (no bypasses during test)
// ---------------------------------------------------------------------------
static void test_no_bypasses() {
    std::cout << "\n=== Test 3: No Bypasses ===\n";

    auto snap = AgentToolAuthority::CaptureSnapshot();
    CHECK(snap.bypass_cli == 0, "bypass_cli == 0");
    CHECK(snap.bypass_gui == 0, "bypass_gui == 0");
    CHECK(snap.bypass_headless == 0, "bypass_headless == 0");
    CHECK(snap.bypass_swarm == 0, "bypass_swarm == 0");
    CHECK(snap.bypass_agentic_loop == 0, "bypass_agentic_loop == 0");
}

// ---------------------------------------------------------------------------
// Test 4: IncrementBypass works (for legacy sites that honestly report)
// ---------------------------------------------------------------------------
static void test_bypass_reporting() {
    std::cout << "\n=== Test 4: Bypass Reporting ===\n";

    auto before = AgentToolAuthority::CaptureSnapshot();
    AgentToolAuthority::IncrementBypass(AgentToolSurface::CLI);
    auto after = AgentToolAuthority::CaptureSnapshot();
    CHECK(after.bypass_cli == before.bypass_cli + 1, "IncrementBypass(CLI) increments bypass_cli");
}

// ---------------------------------------------------------------------------
// Test 5: Unknown tool dispatch is rejected
// ---------------------------------------------------------------------------
static void test_unknown_tool_rejected() {
    std::cout << "\n=== Test 5: Unknown Tool Rejected ===\n";

    AgentToolRequest req;
    req.tool_name = "nonexistent_tool";
    req.caller_surface = "cli";
    req.args = json::object();

    AgentToolResult result = AgentToolAuthority::Dispatch(req);
    CHECK(!result.success, "Unknown tool dispatch fails");
    CHECK(result.exit_code != 0, "Unknown tool returns non-zero exit code");
}

// ---------------------------------------------------------------------------
// Test 6: GatePass() returns true when all surfaces reached and no bypasses
// ---------------------------------------------------------------------------
static void test_gate_pass() {
    std::cout << "\n=== Test 6: Gate Pass ===\n";

    // Reset and re-run clean
    AgentToolAuthority::ResetForTests();
    auto* registry = &AgentToolRegistry::Instance();
    AgentToolAuthority::Register(nullptr, registry);

    // Reach all 5 surfaces
    const char* surfaces[] = {"cli", "gui", "headless", "swarm", "agentic_loop"};
    for (const char* surface : surfaces) {
        AgentToolRequest req;
        req.tool_name = "list_directory";
        req.caller_surface = surface;
        req.args = {{"path", "."}};
        AgentToolAuthority::Dispatch(req);
    }

    auto snap = AgentToolAuthority::CaptureSnapshot();
    bool gatePass = snap.GatePass();
    CHECK(gatePass, "GatePass() returns true when all surfaces reached, no bypasses");
}

// ---------------------------------------------------------------------------
// Test 7: GatePass() returns false when a bypass exists
// ---------------------------------------------------------------------------
static void test_gate_fail_on_bypass() {
    std::cout << "\n=== Test 7: Gate Fail on Bypass ===\n";

    AgentToolAuthority::IncrementBypass(AgentToolSurface::Headless);
    auto snap = AgentToolAuthority::CaptureSnapshot();
    CHECK(!snap.GatePass(), "GatePass() returns false when bypass_headless > 0");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================================\n";
    std::cout << "  RAWRXD_AGENT_TOOL_AUTHORITY_001 — Selftest\n";
    std::cout << "========================================================\n";

    test_authority_registration();
    test_surface_reach();
    test_no_bypasses();
    test_bypass_reporting();
    test_unknown_tool_rejected();
    test_gate_pass();
    test_gate_fail_on_bypass();

    std::cout << "\n========================================================\n";
    if (g_failures == 0) {
        std::cout << "  RESULT: PASS — All tests succeeded\n";
        std::cout << "  Gate RAWRXD_AGENT_TOOL_AUTHORITY_001: SEALED\n";
    } else {
        std::cout << "  RESULT: FAIL — " << g_failures << " test(s) failed\n";
        std::cout << "  Gate RAWRXD_AGENT_TOOL_AUTHORITY_001: OPEN\n";
    }
    std::cout << "========================================================\n";

    return g_failures == 0 ? 0 : 1;
}