// ============================================================================
// File: tests/agentic_resilience_test.cpp
//
// Standalone, dependency-free validation for the three new subsystems:
//   1. AdaptiveRetryEngine  ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â retries, backoff+jitter, circuit breaker
//   2. ConflictEngine       ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â detection, 3-way merge, resolution strategies
//   3. DelegationManager    ÃƒÆ’Ã†â€™Ãƒâ€šÃ‚Â¢ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡Ãƒâ€šÃ‚Â¬ÃƒÆ’Ã‚Â¢ÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬Ãƒâ€šÃ‚Â lifecycle, quotas, messaging
//
// NO Qt. NO third-party. Pure C++20 + <cassert>.
//
// Build (MSVC):  cl /std:c++20 /EHsc /Fe:test.exe tests\agentic_resilience_test.cpp
//                              src\agent\adaptive_retry.cpp
//                              src\agentic\conflict_resolution.cpp
//                              src\agent\delegated_agents.cpp
// ============================================================================

#include "../../src/agent/adaptive_retry.hpp"
#include "../../src/agentic/conflict_resolution.hpp"
#include "../../src/agent/delegated_agents.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <fstream>
#include <thread>
#include <chrono>

using namespace RawrXD;

// Local engine instance so tests never touch global state.
AdaptiveRetryEngine& adaptive_retry_test_engine();

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(expr) do { \
    if (expr) { ++g_passed; } \
    else { ++g_failed; \
        std::cerr << "FAIL: " << #expr << " @ line " << __LINE__ << "\\\n"; } \
} while (0)

static void section(const char* name) {
    std::cout << "\n=== " << name << " ===" << std::endl;
}

// ---------------------------------------------------------------------------
// ADAPTIVE RETRY
// ---------------------------------------------------------------------------

static void test_retry_first_attempt_success() {
    section("retry: succeeds on first attempt (no retry)");
    auto& engine = adaptive_retry_test_engine();
    engine.resetAllStats();

    int calls = 0;
    auto r = engine.execute("llm_invocation", [&calls]() -> std::string {
        ++calls;
        return "immediate";
    });
    CHECK(r.success);
    CHECK(r.attemptsMade == 1);
    CHECK(calls == 1);
    CHECK(r.result == "immediate");
    std::cout << "  attempts=" << r.attemptsMade << " result=" << r.result << "\\\n";
}

static void test_retry_eventually_succeeds() {
    section("retry: succeeds after transient failures");
    auto& engine = adaptive_retry_test_engine();
    // Fast policy so the test doesn't take minutes.
    RetryPolicy p = RetryPolicy::defaultLLMInvocation();
    p.maxAttempts = 4;
    p.baseDelayMs = 1;
    p.maxDelayMs = 5;
    p.jitterFactor = 0.0;
    p.enableCircuitBreaker = false;   // isolate retry logic
    engine.registerPolicy(p);
    engine.resetStats("llm_invocation");

    int calls = 0;
    auto r = engine.execute("llm_invocation", [&calls]() -> std::string {
        if (++calls < 3) throw std::runtime_error("connection timeout");
        return "recovered";
    });
    CHECK(r.success);
    CHECK(r.attemptsMade == 3);
    CHECK(calls == 3);
    CHECK(r.attemptErrors.size() == 2);
    std::cout << "  recovered on attempt " << r.attemptsMade << " after "
              << r.attemptErrors.size() << " transient failure(s)\\\n";

    // restore default policy
    engine.registerPolicy(RetryPolicy::defaultLLMInvocation());
}

static void test_gpu_kernel_incompatibility_is_not_retried() {
    section("retry: ROCm kernel-image incompatibility stops immediately");
    auto& engine = adaptive_retry_test_engine();
    RetryPolicy p = RetryPolicy::defaultLLMInvocation();
    p.maxAttempts = 5;
    p.baseDelayMs = 1;
    p.maxDelayMs = 2;
    p.jitterFactor = 0.0;
    p.enableCircuitBreaker = false;
    engine.registerPolicy(p);
    engine.resetStats("llm_invocation");

    int calls = 0;
    auto r = engine.execute("llm_invocation", [&calls]() -> std::string {
        ++calls;
        throw std::runtime_error(
            "rocblaslt error: Could not load TensileLibrary_lazy_gfx1201.dat; "
            "ROCm error: no kernel image is available for execution on the device");
    });

    CHECK(!r.success);
    CHECK(r.attemptsMade == 1);
    CHECK(calls == 1);
    CHECK(r.attemptErrors.size() == 1);
    CHECK(engine.getStats("llm_invocation").totalRetries == 0);

    engine.registerPolicy(RetryPolicy::defaultLLMInvocation());
}

static void test_retry_gives_up_and_reports() {
    section("retry: exhausts attempts and reports all errors");
    auto& engine = adaptive_retry_test_engine();
    RetryPolicy p = RetryPolicy::defaultFileOperation();
    p.maxAttempts = 3;
    p.baseDelayMs = 1;
    p.maxDelayMs = 2;
    p.enableCircuitBreaker = false;
    engine.registerPolicy(p);

    int calls = 0;
    auto r = engine.execute("file_operation", [&calls]() -> std::string {
        ++calls;
        throw std::runtime_error("file locked by another process");
    });
    CHECK(!r.success);
    CHECK(r.attemptsMade == 3);
    CHECK(calls == 3);
    CHECK(r.attemptErrors.size() == 3);
    std::cout << "  gave up after " << r.attemptsMade << " attempts; last error: "
              << r.errorMessage << "\\\n";
}

static void test_non_retryable_error_short_circuits() {
    section("retry: non-retryable error short-circuits");
    auto& engine = adaptive_retry_test_engine();
    RetryPolicy p = RetryPolicy::defaultFileOperation();
    p.baseDelayMs = 1;
    p.enableCircuitBreaker = false;
    engine.registerPolicy(p);

    int calls = 0;
    auto r = engine.execute("file_operation", [&calls]() -> std::string {
        ++calls;
        // "not found" is in nonRetryableErrorPatterns
        throw std::runtime_error("path not found");
    });
    CHECK(!r.success);
    CHECK(calls == 1);                      // must NOT retry
    std::cout << "  non-retryable error returned after " << calls << " attempt(s)\\\n";
}

static void test_circuit_breaker_opens() {
    section("retry: circuit breaker opens after threshold");
    auto& engine = adaptive_retry_test_engine();
    RetryPolicy p = RetryPolicy::defaultLLMInvocation();
    p.maxAttempts = 1;                      // single attempt per execution
    p.failureThreshold = 2;
    p.enableCircuitBreaker = true;
    p.baseDelayMs = 1;
    engine.registerPolicy(p);
    engine.resetStats("llm_invocation");

    auto fail = [&]() -> std::string {
        throw std::runtime_error("temporary outage");
    };
    (void)engine.execute("llm_invocation", fail);
    (void)engine.execute("llm_invocation", fail);

    auto cb = engine.getCircuitBreaker("llm_invocation");
    CHECK(cb.has_value());
    CHECK(cb->getState() == CircuitState::Open);
    std::cout << "  breaker state after 2 failures: " << cb->stateString() << "\\\n";

    // Next request must be rejected fast without invoking the operation.
    bool invoked = false;
    auto r = engine.execute("llm_invocation", [&invoked]() -> std::string {
        invoked = true;
        return "should never run";
    });
    CHECK(!r.success);
    CHECK(r.circuitBreakerTriggered);
    CHECK(!invoked);
    std::cout << "  open breaker rejected request; operation invoked: "
              << (invoked ? "yes" : "no") << "\\\n";
}

static void test_policy_json_roundtrip() {
    section("retry: policy JSON round-trip");
    RetryPolicy original = RetryPolicy::defaultLLMInvocation();
    std::string json = original.toJSON();
    RetryPolicy parsed = RetryPolicy::fromJSON(json);

    CHECK(parsed.operationType == original.operationType);
    CHECK(parsed.maxAttempts == original.maxAttempts);
    CHECK(parsed.baseDelayMs == original.baseDelayMs);
    CHECK(parsed.maxDelayMs == original.maxDelayMs);
    CHECK(parsed.failureThreshold == original.failureThreshold);
    CHECK(parsed.successThreshold == original.successThreshold);
    CHECK(parsed.circuitTimeoutMs == original.circuitTimeoutMs);
    CHECK(parsed.retryableErrorPatterns.size() == original.retryableErrorPatterns.size());
    CHECK(parsed.nonRetryableErrorPatterns.size() == original.nonRetryableErrorPatterns.size());
    CHECK(parsed.enableCircuitBreaker == original.enableCircuitBreaker);
    std::cout << "  round-trip preserved " << parsed.retryableErrorPatterns.size()
              << " retryable + " << parsed.nonRetryableErrorPatterns.size()
              << " non-retryable patterns\\\n";
}

static void test_policy_persistence() {
    section("retry: policy file save/load round-trip");
    auto& engine = adaptive_retry_test_engine();

    std::string path = "adaptive_retry_policies_test.json";
    CHECK(engine.savePoliciesToFile(path));

    // Wipe and reload.
    engine.removePolicy("build");
    CHECK(engine.getPolicy("build") == nullptr);
    CHECK(engine.loadPoliciesFromFile(path));
    CHECK(engine.getPolicy("build") != nullptr);

    std::remove(path.c_str());
    std::cout << "  policies persisted and reloaded from disk\\\n";
}

static void test_stats_reporting() {
    section("retry: statistics reporting");
    auto& engine = adaptive_retry_test_engine();
    RetryPolicy p = RetryPolicy::defaultLLMInvocation();
    p.maxAttempts = 2;
    p.baseDelayMs = 1;
    p.enableCircuitBreaker = false;
    engine.registerPolicy(p);
    engine.resetStats("llm_invocation");

    (void)engine.execute("llm_invocation", []() -> std::string { return "ok"; });
    (void)engine.execute("llm_invocation", []() -> std::string {
        throw std::runtime_error("timeout");
    });

    auto stats = engine.getStats("llm_invocation");
    CHECK(stats.totalExecutions == 2);
    CHECK(stats.successfulExecutions == 1);
    CHECK(stats.failedExecutions == 1);
    // Only the FAILED execution retried (maxAttempts=2 -> 1 retry); the
    // successful one succeeded first try. So totalRetries is exactly 1.
    CHECK(stats.totalRetries == 1);

    std::string js = engine.exportStatsJSON();
    CHECK(js.find("\"llm_invocation\"") != std::string::npos);
    std::cout << "  2 executions -> " << stats.successfulExecutions << " ok, "
              << stats.failedExecutions << " failed, " << stats.totalRetries
              << " retry (only the failing execution retried)\\\n";

    engine.registerPolicy(RetryPolicy::defaultLLMInvocation());
}

// ---------------------------------------------------------------------------
// CONFLICT RESOLUTION
// ---------------------------------------------------------------------------

static ConflictEngine::Edit makeEdit(const std::string& id, const std::string& agent,
                                      int startLine, int endLine,
                                      const std::string& oldText,
                                      const std::string& newText,
                                      int64_t ts) {
    ConflictEngine::Edit e;
    e.id = id;
    e.agentId = agent;
    e.filePath = "test.cpp";
    e.range.startLine = startLine; e.range.endLine = endLine;
    e.oldText = oldText;
    e.newText = newText;
    e.timestamp = ts;
    e.semanticType = ConflictEngine::Edit::SemanticType::FunctionBody;
    return e;
}

static void test_conflict_detection_overlap() {
    section("conflict: detects overlapping edits from different agents");
    ConflictEngine::ConflictDetector detector;

    std::vector<ConflictEngine::Edit> edits = {
        makeEdit("e1", "agent-a", 10, 12, "old1", "new from A", 1000),
        makeEdit("e2", "agent-b", 11, 13, "old2", "new from B", 1100)
    };

    auto conflicts = detector.detectConflicts(edits);
    CHECK(!conflicts.empty());
    CHECK(conflicts.front().conflictingEdits.size() >= 2);
    std::cout << "  detected " << conflicts.size() << " conflict(s); first involves "
              << conflicts.front().conflictingEdits.size() << " edits\\\n";
}

static void test_conflict_not_detected_for_disjoint_edits() {
    section("conflict: disjoint edits from different agents are clean");
    ConflictEngine::ConflictDetector detector;
    ConflictEngine::ConflictDetector::DetectionConfig cfg;
    cfg.enableSemanticDetection = false;   // isolate range detection
    cfg.enableDependencyDetection = false;
    detector.setConfig(cfg);

    std::vector<ConflictEngine::Edit> edits = {
        makeEdit("e1", "agent-a", 1, 5, "old1", "new A", 1000),
        makeEdit("e2", "agent-b", 20, 25, "old2", "new B", 1100)
    };
    auto conflicts = detector.detectConflicts(edits);
    CHECK(conflicts.empty());
    std::cout << "  disjoint edits produced " << conflicts.size() << " conflicts\\\n";
}

static void test_conflict_not_detected_same_agent() {
    section("conflict: same-agent edits never conflict");
    ConflictEngine::ConflictDetector detector;
    std::vector<ConflictEngine::Edit> edits = {
        makeEdit("e1", "agent-a", 10, 15, "old1", "new A", 1000),
        makeEdit("e2", "agent-a", 12, 18, "old2", "more A", 1100)
    };
    auto conflicts = detector.detectConflicts(edits);
    CHECK(conflicts.empty());
    std::cout << "  same-agent overlapping edits produced " << conflicts.size() << " conflicts\\\n";
}

static void test_three_way_merge_only_one_side_changed() {
    section("merge: clean 3-way merge when only one side changed");
    ConflictEngine::ThreeWayMerge merger;
    std::string base  = "line1\nline2\nline3\\\n";
    std::string local = "line1\nCHANGED\nline3\\\n";
    std::string remote = base;

    auto r = merger.merge(base, local, remote, "a.txt");
    CHECK(r.success);
    CHECK(r.conflictCount == 0);
    CHECK(r.mergedText.find("CHANGED") != std::string::npos);
    std::cout << "  merged cleanly: " << r.details << "\\\n";
}

static void test_three_way_merge_identical_changes() {
    section("merge: identical changes on both sides");
    ConflictEngine::ThreeWayMerge merger;
    std::string base   = "a\nb\nc\\\n";
    std::string change = "a\nB2\nc\\\n";
    auto r = merger.merge(base, change, change, "a.txt");
    CHECK(r.success);
    CHECK(r.conflictCount == 0);
    CHECK(r.mergedText == change);
    std::cout << "  identical edits merged without conflict\\\n";
}

static void test_merge_edits_applies_non_overlapping() {
    section("merge: non-overlapping edits applied in line order");
    ConflictEngine::ThreeWayMerge merger;
    std::string base = "l1\nl2\nl3\nl4\nl5\\\n";

    std::vector<ConflictEngine::Edit> edits = {
        makeEdit("e1", "agent-a", 1, 1, "l1", "L1-EDITED", 1000),
        makeEdit("e2", "agent-b", 5, 5, "l5", "L5-EDITED", 1100)
    };
    auto r = merger.mergeEdits(base, edits, "a.txt");
    CHECK(r.success);
    CHECK(r.conflictCount == 0);
    CHECK(r.mergedText.find("L1-EDITED") != std::string::npos);
    CHECK(r.mergedText.find("L5-EDITED") != std::string::npos);
    CHECK(r.mergedText.find("l3") != std::string::npos);   // untouched middle survived
    std::cout << "  applied " << 2 << " edits; middle line preserved\\\n";
}

static void test_resolver_first_wins() {
    section("resolver: first_wins deterministically picks earliest");
    ConflictEngine::ConflictResolver resolver;

    ConflictEngine::Conflict c;
    c.id = "c1";
    c.filePath = "a.cpp";
    c.type = ConflictEngine::Conflict::ConflictType::TextOverlap;
    c.conflictingEdits = {
        makeEdit("e1", "agent-early", 5, 6, "o", "from early", 100),
        makeEdit("e2", "agent-late", 5, 6, "o", "from late", 999999999999LL)
    };

    auto resolved = resolver.autoResolve(c, ConflictEngine::Conflict::ResolutionStrategy::FirstWins);
    CHECK(resolved.isResolved);
    CHECK(resolved.resolvedText == "from early");
    std::cout << "  first_wins -> '" << resolved.resolvedText << "'\\\n";
}

static void test_resolver_last_wins() {
    section("resolver: last_wins picks most recent");
    ConflictEngine::ConflictResolver resolver;
    ConflictEngine::Conflict c;
    c.conflictingEdits = {
        makeEdit("e1", "agent-early", 5, 6, "o", "from early", 100),
        makeEdit("e2", "agent-late", 5, 6, "o", "from late", 999999999999LL)
    };
    auto resolved = resolver.autoResolve(c, ConflictEngine::Conflict::ResolutionStrategy::LastWins);
    CHECK(resolved.isResolved);
    CHECK(resolved.resolvedText == "from late");
    std::cout << "  last_wins -> '" << resolved.resolvedText << "'\\\n";
}

static void test_resolver_priority_wins() {
    section("resolver: priority_wins respects priority field");
    ConflictEngine::ConflictResolver resolver;

    ConflictEngine::Edit low = makeEdit("e1", "agent-low", 5, 6, "o", "low priority", 100);
    low.priority = 10;
    ConflictEngine::Edit high = makeEdit("e2", "agent-high", 5, 6, "o", "high priority", 200);
    high.priority = 90;

    ConflictEngine::Conflict c;
    c.conflictingEdits = { low, high };
    auto resolved = resolver.autoResolve(c, ConflictEngine::Conflict::ResolutionStrategy::PriorityWins);
    CHECK(resolved.isResolved);
    CHECK(resolved.resolvedText == "high priority");
    std::cout << "  priority_wins -> '" << resolved.resolvedText << "' (90 vs 10)\\\n";
}

static void test_resolver_semantic_merge_distinct_types() {
    section("resolver: semantic merge combines distinct element types");
    ConflictEngine::ConflictResolver resolver;

    ConflictEngine::Edit a = makeEdit("e1", "agent-a", 5, 6, "o", "import added", 100);
    a.semanticType = ConflictEngine::Edit::SemanticType::ImportStatement;
    ConflictEngine::Edit b = makeEdit("e2", "agent-b", 5, 6, "o", "function body", 200);
    b.semanticType = ConflictEngine::Edit::SemanticType::FunctionBody;

    ConflictEngine::Conflict c;
    c.conflictingEdits = { a, b };
    auto resolved = resolver.autoResolve(c, ConflictEngine::Conflict::ResolutionStrategy::SemanticMerge);
    CHECK(resolved.isResolved);
    CHECK(resolved.resolvedText.find("import added") != std::string::npos);
    CHECK(resolved.resolvedText.find("function body") != std::string::npos);
    std::cout << "  semantic merge combined both element types\\\n";
}

static void test_manager_process_edits_and_stats() {
    section("conflict: manager processes edits and tracks stats");
    ConflictEngine::ConflictManager manager;
    std::vector<ConflictEngine::Edit> edits = {
        makeEdit("e1", "agent-a", 10, 12, "o", "A", 1000),
        makeEdit("e2", "agent-b", 11, 13, "o", "B", 1100)
    };
    auto passThrough = manager.processEdits(edits, "");
    // The default policy auto-resolves via semantic merge, which synthesizes a
    // result rather than picking a winner, so no individual edit passes through.
    CHECK(passThrough.empty());
    CHECK(manager.getConflictHistory().size() == 1);   // one conflict, deduped

    // With a first_wins policy the winning edit does pass through.
    ConflictEngine::ConflictResolver::ResolutionPolicy firstWins("first_wins");
    firstWins.method = ConflictEngine::ConflictResolver::ResolutionPolicy::Method::FirstWins;
    firstWins.priority = 100;
    // (registered on the resolver inside the manager via a fresh manager)
    ConflictEngine::ConflictManager manager2;
    manager2.setResolutionPolicy(firstWins);
    auto pass2 = manager2.processEdits(edits, "");
    CHECK(pass2.size() == 1);
    CHECK(pass2.front().newText == "A");

    auto stats = manager.getStats();
    CHECK(stats.totalConflictsDetected == 1);
    std::cout << "  stats: detected=" << stats.totalConflictsDetected
              << " autoResolved=" << stats.totalAutoResolved
              << " manualRequired=" << stats.totalManualRequired << "\\\n";
}

static void test_manager_manual_resolution() {
    section("conflict: manual resolution of an unresolved conflict");
    ConflictEngine::ConflictManager::Config cfg;
    cfg.autoResolveEnabled = false;      // force everything to stay unresolved
    ConflictEngine::ConflictManager manager(cfg);

    std::vector<ConflictEngine::Edit> edits = {
        makeEdit("e1", "agent-a", 10, 12, "o", "A", 1000),
        makeEdit("e2", "agent-b", 11, 13, "o", "B", 1100)
    };
    (void)manager.processEdits(edits, "");

    auto unresolved = manager.getUnresolvedConflicts();
    CHECK(!unresolved.empty());

    std::string cid = unresolved.front().id;
    std::cout << "  unresolved count=" << unresolved.size() << " cid='" << cid << "'" << std::endl;
    CHECK(manager.resolveManually(cid, "hand-merged", "resolved by human"));
    CHECK(manager.getUnresolvedConflicts().empty());
    std::cout << "  manually resolved conflict " << cid << "\\\n";
}

static void test_conflict_log_export() {
    section("conflict: conflict log export");
    ConflictEngine::ConflictManager manager;
    std::vector<ConflictEngine::Edit> edits = {
        makeEdit("e1", "agent-a", 10, 12, "o", "A", 1000),
        makeEdit("e2", "agent-b", 11, 13, "o", "B", 1100)
    };
    (void)manager.processEdits(edits, "");

    std::string path = "conflict_log_test.json";
    CHECK(manager.exportConflictLog(path));
    std::ifstream f(path);
    CHECK(f.good());
    f.close();
    std::remove(path.c_str());
    std::cout << "  exported conflict log\\\n";
}

static void test_swarm_conflict_detection() {
    section("conflict: swarm-level detection");
    std::vector<ConflictEngine::SwarmEdit> edits;
    ConflictEngine::SwarmEdit a;
    a.taskId = "t1"; a.agentId = "ag1"; a.filePath = "x.cpp";
    a.content = "version one"; a.timestamp = 1;
    ConflictEngine::SwarmEdit b;
    b.taskId = "t2"; b.agentId = "ag2"; b.filePath = "x.cpp";
    b.content = "version two"; b.timestamp = 2;

    edits = { a, b };
    auto conflicts = ConflictEngine::SwarmConflictResolver::detectSwarmConflicts(edits);
    CHECK(!conflicts.empty());
    std::cout << "  swarm detector found " << conflicts.size() << " conflict(s)\\\n";

    // Dependency violation: both edits on the same file, one depends on the other
    ConflictEngine::SwarmEdit c;
    c.taskId = "t3"; c.agentId = "ag3"; c.filePath = "x.cpp";
    c.content = "dep"; c.dependencies = { "t2" };
    auto depConflicts = ConflictEngine::SwarmConflictResolver::detectSwarmConflicts({ b, c });
    CHECK(!depConflicts.empty());
    bool foundDep = false;
    for (const auto& x : depConflicts) {
        if (x.type == ConflictEngine::Conflict::ConflictType::DependencyConflict) foundDep = true;
    }
    CHECK(foundDep);
    std::cout << "  dependency violation correctly classified\\\n";
}

// ---------------------------------------------------------------------------
// DELEGATED AGENTS
// ---------------------------------------------------------------------------

static void test_delegation_defaults_and_lifecycle() {
    section("delegation: create, delegate, complete");
    Delegation::DelegationManager::Config cfg;
    cfg.maxConcurrentAgents = 4;
    cfg.enforceQuotas = true;
    Delegation::DelegationManager mgr(cfg);

    // Inject real work so the default no-op isn't used.
    mgr.setAgentWorkFn([](Delegation::DelegatedAgent& agent,
                          const Delegation::DelegatedTask& task) -> std::string {
        agent.usage.tokensUsed += 10;
        agent.usage.toolCalls += 1;
        return "handled: " + task.prompt;
    });

    std::string agentId = mgr.createAgent(
        "worker", { Delegation::AgentCapability::CodeEdit }, Delegation::ResourceLimits{});
    CHECK(!agentId.empty());

    Delegation::DelegatedTask task("do work", "print something");
    task.metadata["required_capabilities"] = "code_edit";
    std::string taskId = mgr.delegate(task, agentId);
    CHECK(!taskId.empty());

    auto result = mgr.waitForTask(taskId, 5000);
    CHECK(result.success);
    CHECK(result.output.find("handled") != std::string::npos);
    CHECK(result.usage.tokensUsed == 10);
    std::cout << "  task " << taskId << " -> success in " << result.elapsedMs() << "ms\\\n";

    Delegation::DelegatedAgent* agent = mgr.getAgent(agentId);
    CHECK(agent != nullptr);
    CHECK(agent->tasksCompleted == 1);
    std::cout << "  agent state after completion: " << agent->stateString() << "\\\n";
}

static void test_delegation_depth_limit() {
    section("delegation: max delegation depth enforced");
    Delegation::DelegationManager::Config cfg;
    cfg.maxDelegationDepth = 2;   // root(0) -> child(1) only
    Delegation::DelegationManager mgr(cfg);

    std::string root = mgr.createAgent("root", { Delegation::AgentCapability::Planning });
    CHECK(!root.empty());
    std::string child = mgr.createAgent("child", { Delegation::AgentCapability::CodeEdit },
                                        Delegation::ResourceLimits{}, root);
    CHECK(!child.empty());
    // depth 2 must be refused
    std::string grandchild = mgr.createAgent("grandchild", { Delegation::AgentCapability::CodeEdit },
                                             Delegation::ResourceLimits{}, child);
    CHECK(grandchild.empty());
    std::cout << "  depth 2 correctly refused (maxDelegationDepth=2)\\\n";
}

static void test_delegation_subagent_quota() {
    section("delegation: parent sub-agent quota enforced");
    Delegation::DelegationManager::Config cfg;
    cfg.maxDelegationDepth = 10;
    cfg.enforceQuotas = true;
    Delegation::DelegationManager mgr(cfg);

    Delegation::ResourceLimits limits;
    limits.maxSubAgents = 2;
    std::string root = mgr.createAgent("root", { Delegation::AgentCapability::Planning }, limits);
    CHECK(!root.empty());

    CHECK(!mgr.createAgent("c1", { Delegation::AgentCapability::CodeEdit }, limits, root).empty());
    CHECK(!mgr.createAgent("c2", { Delegation::AgentCapability::CodeEdit }, limits, root).empty());
    // Third child exceeds the parent's quota.
    CHECK(mgr.createAgent("c3", { Delegation::AgentCapability::CodeEdit }, limits, root).empty());
    std::cout << "  2 children accepted, 3rd refused (parent maxSubAgents=2)\\\n";
}

static void test_delegation_capability_requirement() {
    section("delegation: missing capability refused");
    Delegation::DelegationManager mgr;
    Delegation::DelegationManager::Config cfg;
    cfg.enforceQuotas = true;
    mgr.setConfig(cfg);

    std::string reader = mgr.createAgent("reader",
        { Delegation::AgentCapability::Research }, Delegation::ResourceLimits{});
    CHECK(!reader.empty());

    Delegation::DelegatedTask task("edit code", "write files");
    task.metadata["required_capabilities"] = "code_edit";
    std::string taskId = mgr.delegate(task, reader);
    CHECK(taskId.empty());   // refused: no code_edit capability
    std::cout << "  capability check refused the task\\\n";
}

static void test_delegation_messaging() {
    section("delegation: cross-agent messaging");
    Delegation::DelegationManager mgr;
    std::string a = mgr.createAgent("A", { Delegation::AgentCapability::Research });
    std::string b = mgr.createAgent("B", { Delegation::AgentCapability::Research });
    CHECK(!a.empty() && !b.empty());

    Delegation::AgentMessage msg;
    msg.fromAgentId = a;
    msg.toAgentId = b;
    msg.kind = "request";
    msg.subject = "need data";
    msg.body = "please fetch the config";
    CHECK(mgr.sendMessage(msg));

    auto inbox = mgr.getMessagesFor(b, true);
    CHECK(!inbox.empty());
    CHECK(inbox.front().body.find("config") != std::string::npos);
    std::cout << "  delivered " << inbox.size() << " message(s) to B\\\n";

    // Broadcast
    CHECK(mgr.broadcast(a, "event", "shutdown", "wrapping up"));
    CHECK(!mgr.getMessagesFor(b, true).empty());

    // Unknown recipient rejected
    Delegation::AgentMessage bad;
    bad.fromAgentId = a;
    bad.toAgentId = "nonexistent-agent";
    CHECK(!mgr.sendMessage(bad));
    std::cout << "  broadcast works; unknown recipient rejected\\\n";
}

static void test_delegation_quota_exhaustion_blocks_execution() {
    section("delegation: exhausted quota prevents execution");
    Delegation::DelegationManager mgr;
    Delegation::DelegationManager::Config cfg;
    cfg.enforceQuotas = true;
    mgr.setConfig(cfg);

    Delegation::ResourceLimits limits;
    limits.maxToolCalls = 0;      // zero budget => cannot execute anything
    std::string agentId = mgr.createAgent("broke", { Delegation::AgentCapability::CodeEdit }, limits);
    CHECK(!agentId.empty());

    Delegation::DelegatedTask task("work", "do it");
    std::string taskId = mgr.delegate(task, agentId);
    CHECK(!taskId.empty());

    auto result = mgr.waitForTask(taskId, 5000);
    CHECK(!result.success);       // blocked by quota, reported as failure
    std::cout << "  exhausted quota produced: " << result.errorMessage << "\\\n";
}

static void test_delegation_cancellation() {
    section("delegation: cancellation stops work");
    Delegation::DelegationManager mgr;

    std::atomic<bool> observedCancel{false};
    mgr.setAgentWorkFn([&observedCancel](Delegation::DelegatedAgent& agent,
                                         const Delegation::DelegatedTask&) -> std::string {
        for (int i = 0; i < 200; ++i) {
            if (agent.cancelToken && agent.cancelToken->load()) {
                observedCancel.store(true);
                throw std::runtime_error("cancelled by token");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return "finished anyway";
    });

    std::string agentId = mgr.createAgent("longrunner", { Delegation::AgentCapability::CodeEdit });
    Delegation::DelegatedTask task("long", "spin");
    std::string taskId = mgr.delegate(task, agentId);
    CHECK(!taskId.empty());

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    CHECK(mgr.cancelAgent(agentId));

    auto result = mgr.waitForTask(taskId, 5000);
    CHECK(!result.success);

    // Real proof of propagation: the work function must actually have OBSERVED
    // the cancel token. The worker thread may set this flag slightly after it
    // publishes the task result, so poll briefly rather than sampling once.
    int64_t waited = 0;
    while (!observedCancel.load() && waited < 2000) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        waited += 5;
    }
    CHECK(observedCancel.load());
    std::cout << "  cancelled agent produced failure result: " << result.errorMessage
              << " (cancel token observed by worker: "
              << (observedCancel.load() ? "yes" : "no") << ", waited " << waited << "ms)\\\n";
}

static void test_delegation_state_export() {
    section("delegation: state export JSON");
    Delegation::DelegationManager mgr;
    (void)mgr.createAgent("one", { Delegation::AgentCapability::Research });
    (void)mgr.createAgent("two", { Delegation::AgentCapability::CodeEdit });

    std::string js = mgr.exportStateJSON();
    CHECK(js.find("\"agents\"") != std::string::npos);
    CHECK(js.find("one") != std::string::npos);
    CHECK(js.find("two") != std::string::npos);
    std::cout << "  exported state for " << 2 << " agents\\\n";
}

static void test_delegation_stats_and_summary() {
    section("delegation: stats and summary");
    Delegation::DelegationManager mgr;
    mgr.setAgentWorkFn([](Delegation::DelegatedAgent&, const Delegation::DelegatedTask&) {
        return "done";
    });
    std::string agentId = mgr.createAgent("w", { Delegation::AgentCapability::CodeEdit });
    Delegation::DelegatedTask t("t", "p");
    auto tid = mgr.delegate(t, agentId);
    (void)mgr.waitForTask(tid, 5000);

    auto stats = mgr.getStats();
    CHECK(stats.totalAgentsCreated >= 1);
    CHECK(stats.totalTasksCompleted >= 1);
    std::string summary = mgr.statusSummary();
    CHECK(summary.find("agents") != std::string::npos);
    std::cout << "  " << summary << "\\\n";
}

static void test_delegation_async_processing() {
    section("delegation: many concurrent tasks complete");
    Delegation::DelegationManager::Config cfg;
    cfg.maxConcurrentAgents = 4;
    cfg.maxDelegationDepth = 5;
    Delegation::DelegationManager mgr(cfg);

    std::atomic<int> completed{0};
    mgr.setAgentWorkFn([&completed](Delegation::DelegatedAgent&,
                                    const Delegation::DelegatedTask& task) -> std::string {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        ++completed;
        return "ok:" + task.title;
    });

    std::vector<std::string> taskIds;
    for (int i = 0; i < 12; ++i) {
        std::string id = mgr.createAgent("w" + std::to_string(i),
                                        { Delegation::AgentCapability::CodeEdit });
        Delegation::DelegatedTask t("task" + std::to_string(i), "payload");
        taskIds.push_back(mgr.delegate(t, id));
    }

    int successes = 0;
    for (const auto& tid : taskIds) {
        auto r = mgr.waitForTask(tid, 15000);
        if (r.success) ++successes;
    }
    CHECK(successes == 12);
    CHECK(completed.load() == 12);
    std::cout << "  " << successes << "/12 concurrent tasks succeeded\\\n";
    mgr.waitForIdle(1000);
}

// ---------------------------------------------------------------------------
// Test engine accessor (local engine so tests never touch global state)
// ---------------------------------------------------------------------------

AdaptiveRetryEngine& adaptive_retry_test_engine() {
    static AdaptiveRetryEngine engine;
    return engine;
}

// ---------------------------------------------------------------------------

static void test_retry_accounting_identity() {
    section("retry: accounting identity (retries == attempts - 1)");

    auto& engine = adaptive_retry_test_engine();

    // --- Case 1: success on attempt 3 after 2 transient failures ---
    {
        RetryPolicy p = RetryPolicy::defaultLLMInvocation();
        p.maxAttempts = 4;
        p.baseDelayMs = 1;
        p.maxDelayMs = 2;
        p.jitterFactor = 0.0;
        p.enableCircuitBreaker = false;
        engine.registerPolicy(p);
        engine.resetStats("llm_invocation");

        int calls = 0;
        auto r = engine.execute("llm_invocation", [&calls]() -> std::string {
            if (++calls < 3) throw std::runtime_error("connection timeout");
            return "recovered";
        });

        // Recovered on attempt 3 => 3 attempts, 2 transient failures, 2 retries.
        CHECK(r.success);
        CHECK(r.attemptsMade == 3);
        CHECK(r.attemptErrors.size() == 2);
        CHECK(r.attemptsMade - 1 == (int)r.attemptErrors.size());   // identity
        std::cout << "  success case: attempts=" << r.attemptsMade
                  << " failures=" << r.attemptErrors.size()
                  << " retries=" << (r.attemptsMade - 1) << "\\\n";
    }

    // --- Case 2: exhausted retries, all attempts failed ---
    {
        RetryPolicy p = RetryPolicy::defaultLLMInvocation();
        p.maxAttempts = 3;
        p.baseDelayMs = 1;
        p.maxDelayMs = 2;
        p.jitterFactor = 0.0;
        p.enableCircuitBreaker = false;
        engine.registerPolicy(p);
        engine.resetStats("llm_invocation");

        auto r = engine.execute("llm_invocation", []() -> std::string {
            throw std::runtime_error("temporary outage");
        });

        CHECK(!r.success);
        CHECK(r.attemptsMade == 3);          // all attempts performed
        CHECK(r.attemptErrors.size() == 3);
        CHECK(r.attemptsMade - 1 == 2);      // retries

        // Stats must agree with the reported attempts.
        auto stats = engine.getStats("llm_invocation");
        CHECK(stats.totalExecutions == 1);
        CHECK(stats.failedExecutions == 1);
        CHECK(stats.totalRetries == 2);
        std::cout << "  exhausted case: attempts=" << r.attemptsMade
                  << " retries=" << stats.totalRetries << "\\\n";
    }

    // --- Case 3: non-retryable error stops on attempt 1 ---
    {
        RetryPolicy p = RetryPolicy::defaultLLMInvocation();
        p.maxAttempts = 5;                   // would allow 4 retries...
        p.baseDelayMs = 1;
        p.enableCircuitBreaker = false;
        engine.registerPolicy(p);
        engine.resetStats("llm_invocation");

        auto r = engine.execute("llm_invocation", []() -> std::string {
            // "401" is in the default non-retryable patterns.
            throw std::runtime_error("401 unauthorized");
        });

        CHECK(!r.success);
        CHECK(r.attemptsMade == 1);          // NO retry attempted
        CHECK(r.attemptErrors.size() == 1);

        // Regression guard: retries must be 0, not maxAttempts-1.
        auto stats = engine.getStats("llm_invocation");
        CHECK(stats.totalRetries == 0);
        std::cout << "  non-retryable case: attempts=" << r.attemptsMade
                  << " retries=" << stats.totalRetries << " (must be 0)\\\\n";
    }

    // Restore the default policy for later tests.
    engine.registerPolicy(RetryPolicy::defaultLLMInvocation());
}

static void test_retry_documented_counter_semantics() {
    section("retry: documented counter semantics");
    // RetryResult.attemptsMade = total attempts INCLUDING the first.
    // RetryResult.attemptErrors = failures observed BEFORE this result.
    // EngineStats.totalRetries = SUM over executions of (attemptsMade - 1).
    // So for a single execution: totalRetries == attemptsMade - 1.
    std::cout << "  attemptsMade = attempts including the first\\\n"
              << "  attemptErrors = failures observed before the result\\\n"
              << "  totalRetries = SUM(attemptsMade - 1) across executions\\\n";
}

static void test_delegation_no_work_fn_fails_honestly() {
    section("delegation: unwired engine FAILS (no mocked success)");
    Delegation::DelegationManager mgr;
    // Deliberately do NOT call setAgentWorkFn.
    std::string agentId = mgr.createAgent("unwired", { Delegation::AgentCapability::CodeEdit });
    CHECK(!agentId.empty());

    Delegation::DelegatedTask task("do work", "please compute");
    std::string taskId = mgr.delegate(task, agentId);
    CHECK(!taskId.empty());

    auto result = mgr.waitForTask(taskId, 5000);
    // A fabricated "Completed: ..." would be a mocked success. It must fail.
    CHECK(!result.success);
    CHECK(!result.errorMessage.empty());
    // The default no-op used to return this exact string.
    CHECK(result.output.find("Completed:") == std::string::npos);
    std::cout << "  unwired engine -> failure: " << result.errorMessage << "\\\n";

    auto stats = mgr.getStats();
    CHECK(stats.totalTasksFailed == 1);
    CHECK(stats.totalTasksCompleted == 0);
    std::cout << "  completed=0 failed=1 (no fabricated successes)\\\n";
}

static void test_conflict_swarm_merge_actually_merges() {
    section("conflict: swarm merge uses the real 3-way engine");
    std::string base = "a\nb\nc\n";

    ConflictEngine::SwarmEdit e1;
    e1.taskId = "t1"; e1.agentId = "ag1"; e1.filePath = "f.cpp";
    e1.content = "A\nb\nc\n"; e1.timestamp = 1;      // changed line 1
    ConflictEngine::SwarmEdit e2;
    e2.taskId = "t2"; e2.agentId = "ag2"; e2.filePath = "f.cpp";
    e2.content = "a\nb\nC\n"; e2.timestamp = 2;      // changed line 3

    std::string merged = ConflictEngine::SwarmConflictResolver::mergeSwarmResults(base, { e1, e2 });
    // Both edits are compatible (disjoint lines) so both must survive.
    CHECK(merged.find("A") != std::string::npos);
    CHECK(merged.find("C") != std::string::npos);
    CHECK(merged.find("b") != std::string::npos);
    std::cout << "  merged result:\\\n" << merged << "\\\n";

    // No-op merges must return base unchanged, not a fabricated string.
    ConflictEngine::SwarmEdit same;
    same.taskId = "t3"; same.agentId = "ag3"; same.filePath = "f.cpp";
    same.content = base; same.timestamp = 3;
    std::string unchanged = ConflictEngine::SwarmConflictResolver::mergeSwarmResults(base, { same });
    CHECK(unchanged == base);
    std::cout << "  no-op edit returns base unchanged\\\n";

    // Empty input must return base, never a synthesized value.
    CHECK(ConflictEngine::SwarmConflictResolver::mergeSwarmResults(base, {}) == base);

    // Genuine same-line conflict must be VISIBLE (markers), not silently
    // resolved. Both agents changed line 2 to different values.
    std::string base2 = "a\nb\nc\n";
    ConflictEngine::SwarmEdit f1;
    f1.taskId = "t1"; f1.agentId = "ag1"; f1.filePath = "f.cpp";
    f1.content = "a\nFROM_AGENT1\nc\n"; f1.timestamp = 1;
    ConflictEngine::SwarmEdit f2;
    f2.taskId = "t2"; f2.agentId = "ag2"; f2.filePath = "f.cpp";
    f2.content = "a\nFROM_AGENT2\nc\n"; f2.timestamp = 2;
    std::string conflicted = ConflictEngine::SwarmConflictResolver::mergeSwarmResults(base2, { f1, f2 });
    CHECK(conflicted.find("FROM_AGENT1") != std::string::npos);
    CHECK(conflicted.find("FROM_AGENT2") != std::string::npos);
    CHECK(conflicted.find("<<<<<<<") != std::string::npos);
    std::cout << "  same-line conflict emitted markers (collision is visible):\\\n"
              << conflicted << "\\\n";
}

static void test_conflict_resolve_uses_detected_conflicts() {
    section("conflict: swarm resolver honours the conflicts it is given");
    ConflictEngine::SwarmEdit a;
    a.taskId = "t1"; a.agentId = "ag1"; a.filePath = "f.cpp";
    a.content = "v1"; a.timestamp = 1;
    ConflictEngine::SwarmEdit b;
    b.taskId = "t2"; b.agentId = "ag2"; b.filePath = "f.cpp";
    b.content = "v2"; b.timestamp = 2;

    ConflictEngine::SwarmConflict c;
    c.conflictId = "c1";
    c.filePath = "f.cpp";
    c.involvedEdits = { a, b };
    c.type = ConflictEngine::Conflict::ConflictType::TextOverlap;
    c.autoResolvable = true;

    // first_wins: earliest timestamp
    auto first = ConflictEngine::SwarmConflictResolver::resolveSwarmConflicts(
        { a, b }, { c }, ConflictEngine::ConflictResolver::ResolutionPolicy::Method::FirstWins);
    CHECK(first.size() == 1);
    CHECK(first.front().content == "v1");

    // last_wins: latest timestamp
    auto last = ConflictEngine::SwarmConflictResolver::resolveSwarmConflicts(
        { a, b }, { c }, ConflictEngine::ConflictResolver::ResolutionPolicy::Method::LastWins);
    CHECK(last.size() == 1);
    CHECK(last.front().content == "v2");

    // manual_required: keep everything for the human
    auto manual = ConflictEngine::SwarmConflictResolver::resolveSwarmConflicts(
        { a, b }, { c }, ConflictEngine::ConflictResolver::ResolutionPolicy::Method::ManualRequired);
    CHECK(manual.size() == 2);
    std::cout << "  first_wins=v1 last_wins=v2 manual=both (2 edits)\\\n";
}

int main() {
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);
    std::cout << "RawrXD Agentic Resilience Test Suite (no dependencies)\\\n";
    std::cout << "=====================================================\\\n";

    test_retry_first_attempt_success();
    test_retry_eventually_succeeds();
    test_gpu_kernel_incompatibility_is_not_retried();
    test_retry_gives_up_and_reports();
    test_non_retryable_error_short_circuits();
    test_retry_accounting_identity();
    test_retry_documented_counter_semantics();
    test_circuit_breaker_opens();
    test_policy_json_roundtrip();
    test_policy_persistence();
    test_stats_reporting();

    test_conflict_detection_overlap();
    test_conflict_not_detected_for_disjoint_edits();
    test_conflict_not_detected_same_agent();
    test_three_way_merge_only_one_side_changed();
    test_three_way_merge_identical_changes();
    test_merge_edits_applies_non_overlapping();
    test_resolver_first_wins();
    test_resolver_last_wins();
    test_resolver_priority_wins();
    test_resolver_semantic_merge_distinct_types();
    test_manager_process_edits_and_stats();
    test_manager_manual_resolution();
    test_conflict_log_export();
    test_swarm_conflict_detection();

    test_delegation_defaults_and_lifecycle();
    test_delegation_depth_limit();
    test_delegation_subagent_quota();
    test_delegation_capability_requirement();
    test_delegation_messaging();
    test_delegation_quota_exhaustion_blocks_execution();
    test_delegation_cancellation();
    test_delegation_no_work_fn_fails_honestly();
    test_conflict_swarm_merge_actually_merges();
    test_conflict_resolve_uses_detected_conflicts();
    test_delegation_state_export();
    test_delegation_stats_and_summary();
    test_delegation_async_processing();

    std::cout << "\n=====================================================\\\n";
    std::cout << "RESULTS: " << g_passed << " passed, " << g_failed << " failed\\\n";

    if (g_failed > 0) {
        std::cout << "\nSOME TESTS FAILED\\\n";
        return 1;
    }
    std::cout << "\nALL TESTS PASSED\\\n";
    return 0;
}
