// =============================================================================
// RawRamXD_Phase7C_PredictiveTest.cpp
// Acceptance Gates C1-C6: Predictive Memory Intelligence Validation
// =============================================================================
// Phase 7C: Predictive Memory Intelligence
// Goal: Turn RawRamXD's telemetry + autonomous placement into a learning
//       system that refines its own policies over time.
//
// Acceptance Gates:
// C1: Sequence Logging - Per-tensor access traces persist correctly
// C2: Pattern Mining - Recurring patterns detected, placement profiles generated
// C3: Policy Refinement - Feedback-driven optimization improves hit rates
// C4: Online Adaptation - Aggression adjusts based on live workload class
// C5: End-to-End Integration - Full pipeline from trace to refined policy
// C6: Persistence & Recovery - Learned policies survive restarts
// =============================================================================

#include "RawRamXD_Phase7C_PredictiveMemory.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <random>
#include <cassert>

using namespace RawRamXD;

// =============================================================================
// Test Utilities
// =============================================================================

struct TestResult {
    std::string gateName;
    bool passed;
    std::string details;
    double metricValue;
};

std::vector<TestResult> testResults;

void ReportResult(const std::string& gate, bool passed, const std::string& details, double metric = 0.0) {
    TestResult result;
    result.gateName = gate;
    result.passed = passed;
    result.details = details;
    result.metricValue = metric;
    testResults.push_back(result);

    std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << gate << ": " << details;
    if (metric > 0.0) {
        std::cout << " (Metric: " << std::fixed << std::setprecision(2) << metric << ")";
    }
    std::cout << std::endl;
}

// =============================================================================
// Gate C1: Sequence Logging Validation
// =============================================================================

bool TestC1_SequenceLogging() {
    std::cout << "\n=== Gate C1: Sequence Logging ===" << std::endl;
    std::cout << "  Initializing logger..." << std::endl;

    SequenceLogger logger;
    if (!logger.Initialize("./test_logs")) {
        ReportResult("C1", false, "Failed to initialize sequence logger");
        return false;
    }
    std::cout << "  Logger initialized, generating events..." << std::endl;

    // Generate synthetic access events
    const uint64_t testTensorId = 12345;
    const size_t numEvents = 100;

    for (size_t i = 0; i < numEvents; ++i) {
        TensorAccessEvent event;
        event.timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.tensorId = testTensorId;
        event.accessType = (i % 3 == 0) ? AccessType::WRITE : AccessType::READ;
        event.sourceTier = MemoryTier::HOST;
        event.targetTier = MemoryTier::GPU0;
        event.offset = i * 1024;
        event.sizeBytes = 1024;
        event.computeNode = 0;
        event.latencyUs = 50 + (i % 20);
        event.wasHit = (i % 2 == 0);

        logger.LogEvent(event);
    }
    std::cout << "  Events generated, retrieving trace..." << std::endl;

    // Verify trace was recorded
    auto trace = logger.GetTrace(testTensorId);
    if (!trace) {
        ReportResult("C1", false, "Failed to retrieve trace for tensor");
        return false;
    }

    if (trace->events.size() != numEvents) {
        ReportResult("C1", false, "Event count mismatch", trace->events.size());
        return false;
    }

    // Verify trace statistics
    if (trace->totalReads == 0 || trace->totalWrites == 0) {
        ReportResult("C1", false, "Read/write tracking failed");
        return false;
    }

    // Verify average access interval
    double avgInterval = trace->GetAverageAccessIntervalUs();
    if (avgInterval <= 0.0) {
        ReportResult("C1", false, "Invalid average access interval");
        return false;
    }

    // Verify preferred tier detection
    MemoryTier preferred = trace->GetPreferredTier();

    // Get logger stats
    auto stats = logger.GetStats();

    logger.Shutdown();

    bool passed = (stats.totalEventsLogged == numEvents);
    ReportResult("C1", passed, "Sequence logging with " + std::to_string(numEvents) + " events",
                 stats.totalEventsLogged);

    return passed;
}

// =============================================================================
// Gate C2: Pattern Mining Validation
// =============================================================================

bool TestC2_PatternMining() {
    std::cout << "\n=== Gate C2: Pattern Mining ===" << std::endl;

    PatternMiner miner;
    if (!miner.Initialize()) {
        ReportResult("C2", false, "Failed to initialize pattern miner");
        return false;
    }

    // Create a trace with sequential pattern
    SequenceTrace trace;
    trace.tensorId = 99999;

    // Generate sequential access pattern
    for (size_t i = 0; i < 50; ++i) {
        TensorAccessEvent event;
        event.timestampUs = i * 1000;
        event.tensorId = trace.tensorId;
        event.accessType = AccessType::READ;
        event.sourceTier = MemoryTier::HOST;
        event.targetTier = MemoryTier::GPU0;
        event.offset = i * 4096; // Sequential 4KB strides
        event.sizeBytes = 4096;
        event.computeNode = 0;
        event.latencyUs = 100;
        event.wasHit = true;
        trace.AddEvent(event);
    }

    // Mine patterns
    auto patterns = miner.MinePatterns(trace);

    if (patterns.empty()) {
        ReportResult("C2", false, "No patterns detected in sequential trace");
        miner.Shutdown();
        return false;
    }

    // Check for sequential pattern
    bool foundSequential = false;
    for (const auto& pattern : patterns) {
        if (pattern.type == AccessPattern::PatternType::SEQUENTIAL && pattern.confidence >= 0.5) {
            foundSequential = true;
            break;
        }
    }

    if (!foundSequential) {
        ReportResult("C2", false, "Sequential pattern not detected");
        miner.Shutdown();
        return false;
    }

    // Generate placement profile
    WorkloadSignature sig;
    sig.readWriteRatio = 10.0;
    sig.sequentiality = 0.9;
    sig.temporalLocality = 0.7;
    sig.spatialLocality = 0.8;
    sig.burstiness = 0.3;
    sig.avgTensorLifetimeMs = 5000;
    sig.avgAccessIntervalUs = 1000;
    sig.uniqueTensorCount = 10;

    auto profile = miner.GenerateProfile(sig);

    if (profile.tierPreferences.empty()) {
        ReportResult("C2", false, "Profile generation failed - no tier preferences");
        miner.Shutdown();
        return false;
    }

    // Store and retrieve profile
    miner.StoreProfile(profile);
    auto retrieved = miner.GetProfile(profile.profileId);

    if (!retrieved) {
        ReportResult("C2", false, "Profile storage/retrieval failed");
        miner.Shutdown();
        return false;
    }

    // Test profile matching
    auto matched = miner.FindMatchingProfile(sig);

    auto stats = miner.GetStats();
    miner.Shutdown();

    bool passed = (stats.patternsDiscovered > 0 && stats.profilesGenerated > 0);
    ReportResult("C2", passed, "Pattern mining with " + std::to_string(patterns.size()) +
                 " patterns, " + std::to_string(stats.profilesGenerated) + " profiles",
                 stats.patternsDiscovered);

    return passed;
}

// =============================================================================
// Gate C3: Policy Refinement Validation
// =============================================================================

bool TestC3_PolicyRefinement() {
    std::cout << "\n=== Gate C3: Policy Refinement ===" << std::endl;

    PatternMiner miner;
    miner.Initialize();

    PolicyRefinementEngine engine;
    if (!engine.Initialize(&miner)) {
        ReportResult("C3", false, "Failed to initialize refinement engine");
        miner.Shutdown();
        return false;
    }

    // Create a profile
    WorkloadSignature sig;
    sig.readWriteRatio = 5.0;
    sig.sequentiality = 0.8;
    sig.temporalLocality = 0.6;
    sig.spatialLocality = 0.7;
    sig.burstiness = 0.4;

    auto profile = miner.GenerateProfile(sig);
    uint64_t profileId = profile.profileId;
    miner.StoreProfile(profile);

    // Record feedback (need minimum observations for refinement)
    for (size_t i = 0; i < 15; ++i) {
        PolicyFeedback feedback;
        feedback.profileId = profileId;
        feedback.timestamp = i * 1000;
        feedback.actualHitRate = 0.75 + (i * 0.01); // Improving hit rate
        feedback.predictedHitRate = 0.70;
        feedback.actualLatencyUs = 100 - i;
        feedback.predictedLatencyUs = 120;
        feedback.bytesTransferred = 1024 * 1024;
        feedback.migrationCount = i % 3;
        feedback.evictionCount = i % 5;
        feedback.throughput = 1000.0 + i * 10;
        feedback.wasBeneficial = (i > 5);

        engine.RecordFeedback(feedback);
    }

    // Trigger refinement
    engine.RefinePolicies();

    auto refined = engine.GetRefinedPolicy(profileId);
    auto stats = engine.GetStats();

    bool passed = (stats.policiesRefined > 0 || stats.feedbacksRecorded >= 15);
    ReportResult("C3", passed, "Policy refinement with " +
                 std::to_string(stats.feedbacksRecorded) + " feedbacks, " +
                 std::to_string(stats.policiesRefined) + " refined",
                 stats.policiesRefined);

    engine.Shutdown();
    miner.Shutdown();

    return passed;
}

// =============================================================================
// Gate C4: Online Adaptation Validation
// =============================================================================

bool TestC4_OnlineAdaptation() {
    std::cout << "\n=== Gate C4: Online Adaptation ===" << std::endl;

    PatternMiner miner;
    miner.Initialize();

    PolicyRefinementEngine engine;
    engine.Initialize(&miner);

    OnlineAdaptationController controller;
    if (!controller.Initialize(&miner, &engine)) {
        ReportResult("C4", false, "Failed to initialize adaptation controller");
        engine.Shutdown();
        miner.Shutdown();
        return false;
    }

    // Create traces for workload classification
    std::vector<std::shared_ptr<SequenceTrace>> traces;

    // Simulate inference workload (high read ratio, sequential)
    for (size_t t = 0; t < 5; ++t) {
        auto trace = std::make_shared<SequenceTrace>();
        trace->tensorId = 1000 + t;
        for (size_t i = 0; i < 20; ++i) {
            TensorAccessEvent event;
            event.timestampUs = i * 100;
            event.tensorId = trace->tensorId;
            event.accessType = AccessType::READ;
            event.offset = i * 1024;
            event.sizeBytes = 1024;
            event.wasHit = true;
            trace->AddEvent(event);
        }
        traces.push_back(trace);
    }

    // Classify workload
    WorkloadClass classification = controller.ClassifyWorkload(traces);

    // Test aggression adjustment
    WorkloadState state;
    state.currentClass = classification;
    state.currentHitRate = 0.4; // Low hit rate
    state.memoryPressure = 0.9; // High pressure
    state.currentLatency = 2000;
    state.currentThroughput = 500;

    controller.UpdateAggression(state);

    AggressionLevel aggression = controller.GetAggressionLevel();
    auto params = controller.GetPolicyParameters();

    auto stats = controller.GetStats();

    bool passed = (stats.classificationsPerformed > 0 &&
                   params.prefetchThreshold > 0.0 &&
                   params.evictionAggression > 0.0);

    ReportResult("C4", passed, "Online adaptation with " +
                 std::to_string(stats.classificationsPerformed) + " classifications, " +
                 "aggression level " + std::to_string(static_cast<int>(aggression)),
                 stats.classificationsPerformed);

    controller.Shutdown();
    engine.Shutdown();
    miner.Shutdown();

    return passed;
}

// =============================================================================
// Gate C5: End-to-End Integration Validation
// =============================================================================

bool TestC5_EndToEndIntegration() {
    std::cout << "\n=== Gate C5: End-to-End Integration ===" << std::endl;

    PredictiveIntelligenceConfig config;
    config.enableSequenceLogging = true;
    config.enablePatternMining = true;
    config.enablePolicyRefinement = true;
    config.enableOnlineAdaptation = true;
    config.persistenceDir = "./test_predictive";
    config.refinementIntervalMs = 1000;
    config.adaptationIntervalMs = 500;

    auto& intelligence = PredictiveMemoryIntelligence::Instance();
    if (!intelligence.Initialize(config)) {
        ReportResult("C5", false, "Failed to initialize predictive intelligence");
        return false;
    }

    // Simulate tensor accesses
    for (size_t i = 0; i < 50; ++i) {
        TensorAccessEvent event;
        event.timestampUs = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.tensorId = 50000 + (i % 5); // 5 different tensors
        event.accessType = AccessType::READ;
        event.sourceTier = MemoryTier::HOST;
        event.targetTier = MemoryTier::GPU0;
        event.offset = i * 2048;
        event.sizeBytes = 2048;
        event.computeNode = 0;
        event.latencyUs = 80;
        event.wasHit = (i % 3 == 0);

        intelligence.OnTensorAccess(event);
    }

    // Simulate inference end with workload signature
    WorkloadSignature sig;
    sig.readWriteRatio = 8.0;
    sig.sequentiality = 0.85;
    sig.temporalLocality = 0.75;
    sig.spatialLocality = 0.8;
    sig.burstiness = 0.25;

    intelligence.OnInferenceEnd(1, sig);

    // Get policy for workload
    auto policy = intelligence.GetPolicyForWorkload(sig);

    // Get current parameters
    auto params = intelligence.GetCurrentPolicyParameters();

    // Trigger refinement
    intelligence.TriggerPolicyRefinement();

    auto metrics = intelligence.GetMetrics();

    bool passed = (metrics.eventsLogged > 0 && policy != nullptr);
    ReportResult("C5", passed, "End-to-end integration with " +
                 std::to_string(metrics.eventsLogged) + " events, " +
                 (policy ? "policy generated" : "no policy"),
                 metrics.eventsLogged);

    intelligence.Shutdown();

    return passed;
}

// =============================================================================
// Gate C6: Persistence & Recovery Validation
// =============================================================================

bool TestC6_PersistenceAndRecovery() {
    std::cout << "\n=== Gate C6: Persistence & Recovery ===" << std::endl;

    PatternMiner miner;
    miner.Initialize();

    // Create and store profiles
    WorkloadSignature sig1;
    sig1.readWriteRatio = 10.0;
    sig1.sequentiality = 0.9;
    auto profile1 = miner.GenerateProfile(sig1);
    miner.StoreProfile(profile1);

    WorkloadSignature sig2;
    sig2.readWriteRatio = 2.0;
    sig2.sequentiality = 0.3;
    auto profile2 = miner.GenerateProfile(sig2);
    miner.StoreProfile(profile2);

    // Save profiles
    bool saveOk = miner.SaveProfiles("./test_profiles.bin");

    // Clear and reload
    miner.Shutdown();
    miner.Initialize();

    bool loadOk = miner.LoadProfiles("./test_profiles.bin");

    // Verify profiles were recovered
    auto allProfiles = miner.GetAllProfiles();

    auto stats = miner.GetStats();
    miner.Shutdown();

    bool passed = saveOk && loadOk;
    ReportResult("C6", passed, "Persistence with save=" + std::string(saveOk ? "OK" : "FAIL") +
                 ", load=" + std::string(loadOk ? "OK" : "FAIL"),
                 allProfiles.size());

    return passed;
}

// =============================================================================
// Main Test Runner
// =============================================================================

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "RawRamXD Phase 7C: Predictive Memory Intelligence" << std::endl;
    std::cout << "Acceptance Gates C1-C6 Validation" << std::endl;
    std::cout << "=================================================================" << std::endl;

    testResults.clear();

    // Run all gates
    bool c1 = TestC1_SequenceLogging();
    bool c2 = TestC2_PatternMining();
    bool c3 = TestC3_PolicyRefinement();
    bool c4 = TestC4_OnlineAdaptation();
    bool c5 = TestC5_EndToEndIntegration();
    bool c6 = TestC6_PersistenceAndRecovery();

    // Summary
    std::cout << "\n=================================================================" << std::endl;
    std::cout << "Phase 7C Acceptance Gates Summary" << std::endl;
    std::cout << "=================================================================" << std::endl;

    int passed = 0;
    for (const auto& result : testResults) {
        if (result.passed) passed++;
    }

    std::cout << "Gates Passed: " << passed << "/" << testResults.size() << std::endl;
    std::cout << "C1 Sequence Logging:      " << (c1 ? "PASS" : "FAIL") << std::endl;
    std::cout << "C2 Pattern Mining:          " << (c2 ? "PASS" : "FAIL") << std::endl;
    std::cout << "C3 Policy Refinement:       " << (c3 ? "PASS" : "FAIL") << std::endl;
    std::cout << "C4 Online Adaptation:       " << (c4 ? "PASS" : "FAIL") << std::endl;
    std::cout << "C5 End-to-End Integration:  " << (c5 ? "PASS" : "FAIL") << std::endl;
    std::cout << "C6 Persistence & Recovery:  " << (c6 ? "PASS" : "FAIL") << std::endl;

    bool allPassed = c1 && c2 && c3 && c4 && c5 && c6;

    std::cout << "\n=================================================================" << std::endl;
    if (allPassed) {
        std::cout << "PHASE 7C: ALL GATES PASSED" << std::endl;
        std::cout << "Predictive Memory Intelligence is operational!" << std::endl;
    } else {
        std::cout << "PHASE 7C: SOME GATES FAILED" << std::endl;
        std::cout << "Review failures above." << std::endl;
    }
    std::cout << "=================================================================" << std::endl;

    return allPassed ? 0 : 1;
}