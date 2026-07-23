// ============================================================
// AutonomousLoop.cpp - Implementation of the while(alive) cognitive loop
// ============================================================

#include "AutonomousLoop.hpp"
#include "CognitiveMemory.hpp"
#include "WorldModel.hpp"
#include "ExecutiveDirector.hpp"
#include "AutonomousLoop_Integration.hpp"

namespace RawrXD::Executive {

AutonomousLoop::AutonomousLoop(CognitiveMemory& memory,
                WorldModel& worldModel,
                ExecutiveDirector& director)
    : memory_(memory), worldModel_(worldModel), director_(director) {
    
    printf("[Loop] Autonomous Loop created\n");
}

AutonomousLoop::~AutonomousLoop() {
    stop();
}

void AutonomousLoop::start() {
    if (running_.exchange(true)) {
        printf("[Loop] Already running\n");
        return;
    }
    
    alive_.store(true);
    
    loopThread_ = std::thread([this]() {
        runLoop();
    });
    
    printf("[Loop] ✓ Autonomous Loop started (while alive)\n");
}

void AutonomousLoop::stop() {
    alive_.store(false);
    running_.store(false);
    
    if (loopThread_.joinable()) {
        loopThread_.join();
    }
    
    printf("[Loop] Autonomous Loop stopped\n");
}

bool AutonomousLoop::isRunning() { return running_.load(); }
bool AutonomousLoop::isAlive() { return alive_.load(); }

void AutonomousLoop::setCycleRate(float hz) {
    // 1.0 Hz = 1 cycle per second
    // 10.0 Hz = 10 cycles per second
    cyclePeriodMs_ = static_cast<uint64_t>(1000.0f / hz);
    printf("[Loop] Cycle rate: %.1f Hz (period: %llu ms)\n",
           hz, (unsigned long long)cyclePeriodMs_);
}

uint64_t AutonomousLoop::getCycleCount() { return cycleCount_.load(); }
LoopPhase AutonomousLoop::getCurrentPhase() { return currentPhase_; }

void AutonomousLoop::runLoop() {
    printf("[Loop] ════════════════════════════════════════\n");
    printf("[Loop] COGNITIVE LOOP RUNNING: while(alive) {\n");
    printf("[Loop]   perceive → think → plan → act → reflect → learn\n");
    printf("[Loop] }\n");
    printf("[Loop] ════════════════════════════════════════\n\n");
    
    while (alive_.load()) {
        auto cycleStart = std::chrono::high_resolution_clock::now();
        uint64_t cycleStartTimeMs = currentTimeMs();
        
        CycleResult result;
        result.cycleNumber = cycleCount_.fetch_add(1) + 1;
        result.startTimeMs = cycleStartTimeMs;
        result.healthy = true;
        
        // ============================================================
        // Phase 1: PERCEIVE
        // Read findings from the swarm, check for new discoveries
        // ============================================================
        
        currentPhase_ = LoopPhase::Perceive;
        auto perceived = perceive();
        result.findings = perceived.findings;
        
        // If nothing to do → idle
        if (perceived.findings.empty() && !hasActiveMissions()) {
            currentPhase_ = LoopPhase::Idle;
            result.phase = LoopPhase::Idle;
            result.healthy = true;
            result.healthNote = "No active missions or findings — idle";
            
            // Sleep longer when idle (save tokens)
            std::this_thread::sleep_for(
                std::chrono::milliseconds(cyclePeriodMs_ * 4));
            continue;
        }
        
        // ============================================================
        // Phase 2: THINK
        // Consult memory + world model, reason about current state
        // ============================================================
        
        currentPhase_ = LoopPhase::Think;
        auto thoughts = think(perceived);
        
        // ============================================================
        // Phase 3: PLAN
        // Generate/update goals based on thoughts
        // ============================================================
        
        currentPhase_ = LoopPhase::Plan;
        auto plan = planActions(thoughts);
        result.actions = plan.actions;
        
        // ============================================================
        // Phase 4: ACT
        // Dispatch actions to agents/swarm
        // ============================================================
        
        currentPhase_ = LoopPhase::Act;
        auto actionResults = act(plan);
        
        // ============================================================
        // Phase 5: REFLECT
        // Evaluate results, update confidence
        // ============================================================
        
        currentPhase_ = LoopPhase::Reflect;
        auto reflections = reflect(actionResults, thoughts);
        result.reflections = reflections.notes;
        result.healthy = reflections.healthy;
        
        if (!reflections.healthy) {
            currentPhase_ = LoopPhase::Emergency;
            result.healthNote = reflections.healthNote;
            printf("[Loop] ⚠ HEALTH ISSUE: %s\n", reflections.healthNote.c_str());
        }
        
        // ============================================================
        // Phase 6: LEARN
        // Update memory, consolidate, adjust
        // ============================================================
        
        currentPhase_ = LoopPhase::Learn;
        auto learnings = learn(reflections);
        result.learnings = learnings.notes;
        
        // ============================================================
        // Cycle complete
        // ============================================================
        
        auto cycleEnd = std::chrono::high_resolution_clock::now();
        result.endTimeMs = currentTimeMs();
        result.cycleDurationMs = std::chrono::duration<float, std::milli>(
            cycleEnd - cycleStart).count();
        result.phase = currentPhase_;
        
        // Calculate efficiency
        result.tokensConsumed = actionResults.tokensConsumed;
        result.tokensSaved = actionResults.tokensSaved;
        result.efficiency = (result.tokensConsumed + result.tokensSaved) > 0
            ? static_cast<float>(result.tokensSaved) / 
              (result.tokensSaved + result.tokensConsumed)
            : 0.0f;
        
        // Log cycle (every 10th cycle to avoid spam)
        if (result.cycleNumber % 10 == 0) {
            printf("[Loop] Cycle #%llu: %zu findings, %zu actions, "
                   "%zu reflections, %.1fms, efficiency %.0f%%\n",
                   (unsigned long long)result.cycleNumber,
                   result.findings.size(),
                   result.actions.size(),
                   result.reflections.size(),
                   result.cycleDurationMs,
                   result.efficiency * 100);
        }
        
        // Store cycle in memory (every 100th cycle to avoid flooding)
        if (result.cycleNumber % 100 == 0) {
            memory_.storeEpisode({
                .type = "cycle_complete",
                .description = "Cycle " + std::to_string(result.cycleNumber) +
                    ": " + std::to_string(result.findings.size()) +
                    " findings, " + std::to_string(result.actions.size()) +
                    " actions, efficiency " +
                    std::to_string(static_cast<int>(result.efficiency * 100)) + "%",
                .source = "autonomous_loop",
                .timestampMs = result.endTimeMs,
                .confidence = result.healthy ? 0.8f : 0.4f,
                .tags = {"cycle", result.healthy ? "healthy" : "unhealthy"},
                .references = {},
                .context = result.healthNote
            });
        }
        
        // Sleep for remaining cycle time
        auto elapsed = std::chrono::high_resolution_clock::now() - cycleStart;
        auto remainingMs = cyclePeriodMs_ - 
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
        
        if (remainingMs > 0 && alive_.load()) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(remainingMs));
        }
    }
    
    printf("[Loop] ════════════════════════════════════════\n");
    printf("[Loop] COGNITIVE LOOP TERMINATED (alive = false)\n");
    printf("[Loop]   Total cycles: %llu\n",
           (unsigned long long)cycleCount_.load());
    printf("[Loop] ════════════════════════════════════════\n");
}

AutonomousLoop::PerceiveResult AutonomousLoop::perceive() {
    PerceiveResult result;
    
    // Check knowledge base for new findings
    // In real implementation: poll the swarm's knowledge base
    
    // Check for new findings since last cycle
    auto episodes = memory_.getEpisodes("", lastPerceiveMs_, 50);
    for (const auto& e : episodes) {
        if (e.type == "finding" || e.type == "vuln" || 
            e.type == "xor_analysis" || e.type == "injection_pattern" ||
            e.type == "polymorphic_pe") {
            result.findings.push_back(e.description);
        }
        if (e.type == "alert") {
            result.alerts.push_back(e.description);
        }
    }
    
    lastPerceiveMs_ = currentTimeMs();
    
    return result;
}

AutonomousLoop::ThinkResult AutonomousLoop::think(const PerceiveResult& perceived) {
    ThinkResult result;
    result.overallConfidence = 0.5f;
    
    // Reason about current findings
    for (const auto& finding : perceived.findings) {
        auto reasoning = worldModel_.reason(finding);
        if (reasoning.confidence > result.overallConfidence) {
            result.overallConfidence = reasoning.confidence;
            result.currentUnderstanding = reasoning.conclusion;
        }
        result.relevantBeliefs.push_back(reasoning.conclusion);
    }
    
    // Check pending hypotheses
    auto hyps = worldModel_.getPendingHypotheses();
    for (const auto& h : hyps) {
        result.pendingHypotheses.push_back(h.statement);
    }
    
    // Determine recommended action based on state
    if (perceived.findings.empty()) {
        result.recommendedAction = "continue_scan";
    } else if (!perceived.alerts.empty()) {
        result.recommendedAction = "handle_alert";
    } else if (!result.pendingHypotheses.empty()) {
        result.recommendedAction = "test_hypotheses";
    } else {
        result.recommendedAction = "analyze_findings";
    }
    
    return result;
}

AutonomousLoop::PlanResult AutonomousLoop::planActions(const ThinkResult& thoughts) {
    PlanResult result;
    result.estimatedCost = 1000.0f;
    
    if (thoughts.recommendedAction == "continue_scan") {
        result.actions.push_back("dispatch_recon_agents");
        result.goals.push_back("complete_initial_scan");
    } else if (thoughts.recommendedAction == "handle_alert") {
        result.actions.push_back("process_alerts");
        result.goals.push_back("resolve_all_alerts");
    } else if (thoughts.recommendedAction == "test_hypotheses") {
        result.actions.push_back("test_pending_hypotheses");
        result.goals.push_back("verify_all_hypotheses");
    } else {
        result.actions.push_back("analyze_findings");
        result.actions.push_back("generate_report");
        result.goals.push_back("complete_analysis");
    }
    
    return result;
}

AutonomousLoop::ActResult AutonomousLoop::act(const PlanResult& plan) {
    ActResult result;
    result.tokensConsumed = 0;
    result.tokensSaved = 0;
    
    // Generate unique goal ID for this ACT phase
    uint64_t goalId = cycleCount_.load();
    
    // SWARM INTEGRATION: Record estimates before execution
    SWARM_ACT_START(goalId, plan.actions, plan.estimatedCost);
    
    // Dispatch actions to swarm
    for (const auto& action : plan.actions) {
        result.dispatchedActions.push_back(action);
        
        // In real implementation: dispatch to agent pool
        // Track tokens consumed/saved
        
        printf("[Loop]   ACT: %s\n", action.c_str());
    }
    
    // Simulate token consumption (in real implementation: from actual execution)
    result.tokensConsumed = static_cast<size_t>(plan.estimatedCost * 1.2f);  // 20% overhead
    result.tokensSaved = 0;
    
    result.efficiency = result.tokensConsumed > 0
        ? static_cast<float>(result.tokensSaved) /
          (result.tokensSaved + result.tokensConsumed)
        : 0.0f;
    
    // SWARM INTEGRATION: Record actuals after execution
    SWARM_ACT_END(goalId, result.tokensConsumed, result.tokensSaved, 0);
    
    // Check for recommendations
    auto recommendations = SWARM_GET_RECOMMENDATIONS(goalId);
    if (!recommendations.empty()) {
        printf("[Loop]   Swarm Recommendations:\n");
        for (const auto& rec : recommendations) {
            printf("[Loop]     - %s\n", rec.c_str());
        }
    }
    
    return result;
}

AutonomousLoop::ReflectResult AutonomousLoop::reflect(const ActResult& actions, const ThinkResult& thoughts) {
    ReflectResult result;
    result.healthy = true;
    result.performanceScore = 0.5f;
    
    // Reflect on efficiency
    if (actions.efficiency > 0.7f) {
        result.notes.push_back("High efficiency — system performing well");
        result.performanceScore = 0.8f;
    } else if (actions.efficiency < 0.3f) {
        result.notes.push_back("Low efficiency — may need to adjust strategy");
        result.performanceScore = 0.3f;
    }
    
    // Reflect on findings
    if (!thoughts.relevantBeliefs.empty()) {
        result.notes.push_back("Found " + 
            std::to_string(thoughts.relevantBeliefs.size()) +
            " relevant beliefs");
    }
    
    // Health check
    if (actions.tokensConsumed > 100000) {
        result.healthy = false;
        result.healthNote = "Token consumption too high — throttling";
    }
    
    if (thoughts.overallConfidence < 0.2f) {
        result.healthy = false;
        result.healthNote = "Overall confidence too low — may need replan";
    }
    
    return result;
}

AutonomousLoop::LearnResult AutonomousLoop::learn(const ReflectResult& reflections) {
    LearnResult result;
    result.beliefsUpdated = 0;
    result.memoriesStored = 0;
    
    // Update beliefs based on reflections
    if (reflections.performanceScore > 0.7f) {
        result.notes.push_back("Performance is good — keep current strategy");
    }
    
    // Consolidate working memory → semantic
    // (every 100 cycles to avoid overhead)
    if (cycleCount_.load() % 100 == 0) {
        memory_.consolidate();
        result.notes.push_back("Memory consolidated");
    }
    
    // Store reflections in episodic memory
    for (const auto& note : reflections.notes) {
        memory_.storeEpisode({
            .type = "reflection",
            .description = note,
            .source = "autonomous_loop",
            .timestampMs = currentTimeMs(),
            .confidence = reflections.performanceScore,
            .tags = {"reflection", "learning"},
            .references = {},
            .context = reflections.healthNote
        });
        result.memoriesStored++;
    }
    
    return result;
}

bool AutonomousLoop::hasActiveMissions() {
    auto missions = director_.getActiveMissions();
    return !missions.empty();
}

uint64_t AutonomousLoop::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

} // namespace RawrXD::Executive
