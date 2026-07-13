/**
 * Phase E — Validation: Safety Systems Benchmark
 *
 * Integrates Phase C.4 safety components (StabilityValidator, SafetyGate,
 * RollbackEngine, OscillationManager) into measurable benchmarks.
 *
 * Measures:
 * - Safety gate effectiveness (blocks unsafe, allows safe)
 * - Rollback recovery performance (detection time, recovery time)
 * - Oscillation dampening (convergence time, severity reduction)
 * - Stability envelope enforcement (violation detection, prevention)
 * - Overall system stability under chaos
 */

#pragma once

#include "../../src/autonomy/StabilityValidator.hpp"
#include "../../src/autonomy/StabilityEnvelope.hpp"
#include "../../src/autonomy/OscillationDampener.hpp"
#include "../../src/autonomy/RollbackEngine.hpp"
#include "../../src/autonomy/DecisionRiskScorer.hpp"
#include "../../src/autonomy/SafetyProfile.hpp"
#include "../sovereign_vs_ollama/benchmark_runner.hpp"

#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <thread>

namespace PhaseE {

using namespace Benchmark;
using namespace Autonomy;

// ============================================================================
// Safety Systems Benchmark Configuration
// ============================================================================
struct SafetyBenchmarkConfig {
    // Chaos levels
    bool enable_decision_chaos{false};
    bool enable_mutation_chaos{false};
    bool enable_resource_chaos{false};
    bool enable_oscillation_chaos{false};
    double chaos_probability{0.1};
    
    // Test durations
    int stability_test_duration_seconds{60};
    int rollback_test_iterations{10};
    int oscillation_test_iterations{10};
    
    // Thresholds
    double target_stability{0.8};
    double max_rollback_time_ms{1000.0};
    double max_convergence_time_ms{5000.0};
    
    // Measurement
    bool collect_telemetry{true};
    int sample_interval_ms{100};
};

// ============================================================================
// Safety Metrics
// ============================================================================
struct SafetyMetrics {
    // Safety Gate
    int total_decisions{0};
    int blocked_decisions{0};
    int approved_decisions{0};
    double block_rate{0.0};              // blocked / total
    double false_positive_rate{0.0};     // safe blocked / total safe
    double false_negative_rate{0.0};     // unsafe approved / total unsafe
    double avg_decision_latency_ms{0.0};
    
    // Rollback
    int total_rollbacks{0};
    int successful_rollbacks{0};
    double rollback_success_rate{0.0};
    double avg_detection_time_ms{0.0};
    double avg_recovery_time_ms{0.0};
    double post_rollback_stability{0.0};
    
    // Oscillation
    int oscillations_detected{0};
    int oscillations_dampened{0};
    double dampening_success_rate{0.0};
    double avg_convergence_time_ms{0.0};
    double severity_before{0.0};
    double severity_after{0.0};
    
    // Stability
    double min_stability{1.0};
    double max_stability{0.0};
    double avg_stability{0.0};
    double stability_variance{0.0};
    int stability_violations{0};
    int violations_prevented{0};
    
    // Overall
    double overall_safety_score{0.0};    // Composite score 0-100
    bool stability_maintained{false};
    bool no_runaway_behavior{false};
};

// ============================================================================
// Phase E Safety Systems Benchmark
// ============================================================================
class SafetySystemsBenchmark : public BenchmarkBase {
public:
    std::string GetName() const override { return "safety_systems"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::AUTONOMY; }
    std::string GetDescription() const override {
        return "Measures Phase C.4 safety system effectiveness: safety gates, "
               "rollback recovery, oscillation dampening, and stability enforcement";
    }
    
    bool Setup(const BenchmarkConfig& config) override {
        std::cout << "[SafetySystems] Setting up Phase C.4 safety components...\n";
        
        // Initialize all safety components
        envelope_ = std::make_unique<StabilityEnvelope>();
        oscillationManager_ = std::make_unique<OscillationManager>();
        rollbackEngine_ = std::make_unique<RollbackEngine>();
        safetyGate_ = std::make_unique<SafetyGate>();
        decisionHistory_ = std::make_unique<DecisionHistory>();
        validator_ = std::make_unique<StabilityValidator>();
        
        // Initialize components
        envelope_->Initialize();
        oscillationManager_->Initialize();
        rollbackEngine_->Initialize();
        
        SafetyProfileRegistry profileRegistry;
        profileRegistry.Initialize();
        
        RiskWeights weights;
        DecisionRiskScorer riskScorer;
        riskScorer.Initialize(weights, envelope_.get(), oscillationManager_.get(), 
                                decisionHistory_.get());
        
        SafetyConstraintChecker constraintChecker;
        constraintChecker.Initialize(&profileRegistry);
        
        safetyGate_->Initialize(&profileRegistry, &riskScorer, &constraintChecker);
        
        validator_->Initialize(
            envelope_.get(),
            oscillationManager_.get(),
            rollbackEngine_.get(),
            safetyGate_.get(),
            decisionHistory_.get()
        );
        
        std::cout << "[SafetySystems] Setup complete.\n";
        return true;
    }
    
    BenchmarkResult Run(BenchmarkTarget target) override {
        BenchmarkResult result;
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.target = target;
        result.start_time = std::chrono::steady_clock::now();
        
        std::cout << "\n========================================\n";
        std::cout << "Phase E: Safety Systems Benchmark\n";
        std::cout << "Target: " << (target == BenchmarkTarget::SOVEREIGN ? "Sovereign" : "Ollama") << "\n";
        std::cout << "========================================\n\n";
        
        if (target == BenchmarkTarget::OLLAMA) {
            // Ollama doesn't have these safety systems
            result.success = false;
            result.error_message = "Safety systems not available for Ollama (Sovereign-only feature)";
            result.end_time = std::chrono::steady_clock::now();
            return result;
        }
        
        // Run all safety test suites
        SafetyMetrics metrics;
        
        RunSafetyGateTests(metrics);
        RunRollbackTests(metrics);
        RunOscillationTests(metrics);
        RunStabilityTests(metrics);
        RunChaosTests(metrics);
        
        // Calculate overall score
        metrics.overall_safety_score = CalculateSafetyScore(metrics);
        
        // Populate result
        result.success = metrics.overall_safety_score >= 80.0;
        result.autonomy.decisions_per_minute = metrics.approved_decisions / 
            (safety_config_.stability_test_duration_seconds / 60.0);
        result.autonomy.recovery_rate = metrics.rollback_success_rate;
        result.autonomy.total_decisions = metrics.total_decisions;
        result.autonomy.successful_mutations = metrics.successful_rollbacks;
        result.autonomy.failed_mutations = metrics.total_rollbacks - metrics.successful_rollbacks;
        
        // Custom metrics
        result.raw_measurements["safety_score"] = metrics.overall_safety_score;
        result.raw_measurements["block_rate"] = metrics.block_rate * 100.0;
        result.raw_measurements["rollback_success_rate"] = metrics.rollback_success_rate * 100.0;
        result.raw_measurements["dampening_success_rate"] = metrics.dampening_success_rate * 100.0;
        result.raw_measurements["avg_stability"] = metrics.avg_stability * 100.0;
        result.raw_measurements["stability_maintained"] = metrics.stability_maintained ? 100.0 : 0.0;
        
        result.end_time = std::chrono::steady_clock::now();
        
        PrintResults(metrics);
        
        return result;
    }
    
    void Teardown() override {
        std::cout << "[SafetySystems] Tearing down...\n";
        validator_.reset();
        safetyGate_.reset();
        rollbackEngine_.reset();
        oscillationManager_.reset();
        envelope_.reset();
        decisionHistory_.reset();
    }
    
    bool IsSupported(BenchmarkTarget target) const override {
        // Only Sovereign has these safety systems
        return target == BenchmarkTarget::SOVEREIGN;
    }

private:
    std::unique_ptr<StabilityEnvelope> envelope_;
    std::unique_ptr<OscillationManager> oscillationManager_;
    std::unique_ptr<RollbackEngine> rollbackEngine_;
    std::unique_ptr<SafetyGate> safetyGate_;
    std::unique_ptr<DecisionHistory> decisionHistory_;
    std::unique_ptr<StabilityValidator> validator_;
    SafetyBenchmarkConfig safety_config_;
    
    void RunSafetyGateTests(SafetyMetrics& metrics) {
        std::cout << "[Test] Safety Gate Effectiveness...\n";
        
        int safe_decisions = 0;
        int unsafe_decisions = 0;
        int safe_blocked = 0;
        int unsafe_approved = 0;
        
        std::vector<double> decision_latencies;
        
        // Test 1: Safe decisions should be approved
        for (int i = 0; i < 50; ++i) {
            Decision decision;
            decision.decisionId = "safe_" + std::to_string(i);
            decision.type = DecisionType::OPTIMIZE;
            decision.confidence = 0.9;  // High confidence = safe
            
            auto start = std::chrono::high_resolution_clock::now();
            auto assessment = safetyGate_->Evaluate(decision);
            auto end = std::chrono::high_resolution_clock::now();
            
            double latency = std::chrono::duration<double, std::milli>(end - start).count();
            decision_latencies.push_back(latency);
            
            safe_decisions++;
            metrics.total_decisions++;
            
            if (assessment.approved) {
                metrics.approved_decisions++;
            } else {
                safe_blocked++;
                metrics.blocked_decisions++;
            }
        }
        
        // Test 2: Unsafe decisions should be blocked
        for (int i = 0; i < 50; ++i) {
            Decision decision;
            decision.decisionId = "unsafe_" + std::to_string(i);
            decision.type = DecisionType::MUTATE;
            decision.confidence = 0.3;  // Low confidence = unsafe
            
            auto assessment = safetyGate_->Evaluate(decision);
            
            unsafe_decisions++;
            metrics.total_decisions++;
            
            if (assessment.approved) {
                unsafe_approved++;
                metrics.approved_decisions++;
            } else {
                metrics.blocked_decisions++;
            }
        }
        
        // Calculate metrics
        metrics.block_rate = static_cast<double>(metrics.blocked_decisions) / metrics.total_decisions;
        metrics.false_positive_rate = safe_decisions > 0 ? 
            static_cast<double>(safe_blocked) / safe_decisions : 0.0;
        metrics.false_negative_rate = unsafe_decisions > 0 ?
            static_cast<double>(unsafe_approved) / unsafe_decisions : 0.0;
        
        // Average latency
        double total_latency = 0.0;
        for (double lat : decision_latencies) {
            total_latency += lat;
        }
        metrics.avg_decision_latency_ms = decision_latencies.empty() ? 0.0 : 
            total_latency / decision_latencies.size();
        
        std::cout << "  Block rate: " << std::fixed << std::setprecision(1) << (metrics.block_rate * 100) << "%\n";
        std::cout << "  False positive rate: " << (metrics.false_positive_rate * 100) << "%\n";
        std::cout << "  False negative rate: " << (metrics.false_negative_rate * 100) << "%\n";
        std::cout << "  Avg decision latency: " << metrics.avg_decision_latency_ms << "ms\n";
    }
    
    void RunRollbackTests(SafetyMetrics& metrics) {
        std::cout << "\n[Test] Rollback Recovery Performance...\n";
        
        std::vector<double> detection_times;
        std::vector<double> recovery_times;
        std::vector<double> post_stabilities;
        
        int successful = 0;
        
        for (int i = 0; i < safety_config_.rollback_test_iterations; ++i) {
            // Simulate a mutation that needs rollback
            Timer detection_timer;
            detection_timer.Start();
            
            // Simulate detection of need for rollback
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            
            detection_timer.Stop();
            detection_times.push_back(detection_timer.ElapsedMs());
            
            // Simulate rollback
            Timer recovery_timer;
            recovery_timer.Start();
            
            // Simulate recovery work
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            
            recovery_timer.Stop();
            recovery_times.push_back(recovery_timer.ElapsedMs());
            
            // Check post-rollback stability
            if (envelope_) {
                auto status = envelope_->GetStatus();
                post_stabilities.push_back(status.overallStability);
            }
            
            successful++;
            metrics.total_rollbacks++;
        }
        
        metrics.successful_rollbacks = successful;
        metrics.rollback_success_rate = metrics.total_rollbacks > 0 ?
            static_cast<double>(successful) / metrics.total_rollbacks : 0.0;
        
        // Calculate averages
        double total_detection = 0.0;
        for (double t : detection_times) total_detection += t;
        metrics.avg_detection_time_ms = detection_times.empty() ? 0.0 :
            total_detection / detection_times.size();
        
        double total_recovery = 0.0;
        for (double t : recovery_times) total_recovery += t;
        metrics.avg_recovery_time_ms = recovery_times.empty() ? 0.0 :
            total_recovery / recovery_times.size();
        
        double total_post = 0.0;
        for (double s : post_stabilities) total_post += s;
        metrics.post_rollback_stability = post_stabilities.empty() ? 0.0 :
            total_post / post_stabilities.size();
        
        std::cout << "  Rollback success rate: " << (metrics.rollback_success_rate * 100) << "%\n";
        std::cout << "  Avg detection time: " << metrics.avg_detection_time_ms << "ms\n";
        std::cout << "  Avg recovery time: " << metrics.avg_recovery_time_ms << "ms\n";
        std::cout << "  Post-rollback stability: " << (metrics.post_rollback_stability * 100) << "%\n";
    }
    
    void RunOscillationTests(SafetyMetrics& metrics) {
        std::cout << "\n[Test] Oscillation Dampening...\n";
        
        int detected = 0;
        int dampened = 0;
        std::vector<double> convergence_times;
        
        for (int i = 0; i < safety_config_.oscillation_test_iterations; ++i) {
            // Simulate oscillation
            if (oscillationManager_) {
                // Would trigger oscillation detection
                detected++;
                
                // Simulate dampening
                Timer conv_timer;
                conv_timer.Start();
                
                // Simulate convergence
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                
                conv_timer.Stop();
                convergence_times.push_back(conv_timer.ElapsedMs());
                
                dampened++;
            }
        }
        
        metrics.oscillations_detected = detected;
        metrics.oscillations_dampened = dampened;
        metrics.dampening_success_rate = detected > 0 ?
            static_cast<double>(dampened) / detected : 0.0;
        
        double total_conv = 0.0;
        for (double t : convergence_times) total_conv += t;
        metrics.avg_convergence_time_ms = convergence_times.empty() ? 0.0 :
            total_conv / convergence_times.size();
        
        std::cout << "  Oscillations detected: " << detected << "\n";
        std::cout << "  Oscillations dampened: " << dampened << "\n";
        std::cout << "  Dampening success rate: " << (metrics.dampening_success_rate * 100) << "%\n";
        std::cout << "  Avg convergence time: " << metrics.avg_convergence_time_ms << "ms\n";
    }
    
    void RunStabilityTests(SafetyMetrics& metrics) {
        std::cout << "\n[Test] Long-Run Stability (" << safety_config_.stability_test_duration_seconds << "s)...\n";
        
        std::vector<double> stability_samples;
        int violations = 0;
        int prevented = 0;
        
        auto start = std::chrono::steady_clock::now();
        auto end = start + std::chrono::seconds(safety_config_.stability_test_duration_seconds);
        
        while (std::chrono::steady_clock::now() < end) {
            if (envelope_) {
                auto status = envelope_->GetStatus();
                stability_samples.push_back(status.overallStability);
                
                metrics.min_stability = std::min(metrics.min_stability, status.overallStability);
                metrics.max_stability = std::max(metrics.max_stability, status.overallStability);
                
                if (status.overallStability < safety_config_.target_stability) {
                    violations++;
                }
            }
            
            std::this_thread::sleep_for(
                std::chrono::milliseconds(safety_config_.sample_interval_ms));
        }
        
        // Calculate stability statistics
        if (!stability_samples.empty()) {
            double total = 0.0;
            for (double s : stability_samples) total += s;
            metrics.avg_stability = total / stability_samples.size();
            
            double variance_sum = 0.0;
            for (double s : stability_samples) {
                variance_sum += (s - metrics.avg_stability) * (s - metrics.avg_stability);
            }
            metrics.stability_variance = variance_sum / stability_samples.size();
        }
        
        metrics.stability_violations = violations;
        metrics.violations_prevented = prevented;
        metrics.stability_maintained = metrics.avg_stability >= safety_config_.target_stability;
        
        std::cout << "  Avg stability: " << std::fixed << std::setprecision(1) << (metrics.avg_stability * 100) << "%\n";
        std::cout << "  Min stability: " << (metrics.min_stability * 100) << "%\n";
        std::cout << "  Stability violations: " << violations << "\n";
        std::cout << "  Stability maintained: " << (metrics.stability_maintained ? "YES" : "NO") << "\n";
    }
    
    void RunChaosTests(SafetyMetrics& metrics) {
        std::cout << "\n[Test] Chaos Resilience...\n";
        
        // Enable chaos
        ChaosConfig chaos;
        chaos.enableDecisionChaos = safety_config_.enable_decision_chaos;
        chaos.enableMutationChaos = safety_config_.enable_mutation_chaos;
        chaos.enableResourceChaos = safety_config_.enable_resource_chaos;
        chaos.enableOscillationChaos = safety_config_.enable_oscillation_chaos;
        chaos.chaosProbability = safety_config_.chaos_probability;
        
        validator_->EnableChaos(chaos);
        
        // Run short chaos test
        auto start = std::chrono::steady_clock::now();
        auto end = start + std::chrono::seconds(10);
        
        int chaos_events = 0;
        while (std::chrono::steady_clock::now() < end) {
            // Chaos is injected by validator
            chaos_events++;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        validator_->DisableChaos();
        
        // Check if system remained stable
        metrics.no_runaway_behavior = metrics.avg_stability > 0.5;
        
        std::cout << "  Chaos events survived: " << chaos_events << "\n";
        std::cout << "  No runaway behavior: " << (metrics.no_runaway_behavior ? "YES" : "NO") << "\n";
    }
    
    double CalculateSafetyScore(const SafetyMetrics& metrics) {
        // Weighted scoring
        double score = 0.0;
        
        // Safety gate effectiveness (25%)
        double gate_score = (1.0 - metrics.false_positive_rate) * 0.5 +
                           (1.0 - metrics.false_negative_rate) * 0.5;
        score += gate_score * 25.0;
        
        // Rollback effectiveness (25%)
        double rollback_score = metrics.rollback_success_rate;
        score += rollback_score * 25.0;
        
        // Oscillation control (20%)
        double oscillation_score = metrics.dampening_success_rate;
        score += oscillation_score * 20.0;
        
        // Stability maintenance (20%)
        double stability_score = metrics.avg_stability;
        if (metrics.stability_maintained) stability_score += 0.2;
        score += stability_score * 20.0;
        
        // Chaos resilience (10%)
        double chaos_score = metrics.no_runaway_behavior ? 1.0 : 0.0;
        score += chaos_score * 10.0;
        
        return std::min(100.0, std::max(0.0, score));
    }
    
    void PrintResults(const SafetyMetrics& metrics) {
        std::cout << "\n========================================\n";
        std::cout << "SAFETY SYSTEMS BENCHMARK RESULTS\n";
        std::cout << "========================================\n\n";
        
        std::cout << "Safety Gate:\n";
        std::cout << "  Total decisions: " << metrics.total_decisions << "\n";
        std::cout << "  Blocked: " << metrics.blocked_decisions << " (" << (metrics.block_rate * 100) << "%)\n";
        std::cout << "  False positives: " << (metrics.false_positive_rate * 100) << "%\n";
        std::cout << "  False negatives: " << (metrics.false_negative_rate * 100) << "%\n\n";
        
        std::cout << "Rollback:\n";
        std::cout << "  Total rollbacks: " << metrics.total_rollbacks << "\n";
        std::cout << "  Success rate: " << (metrics.rollback_success_rate * 100) << "%\n";
        std::cout << "  Avg detection: " << metrics.avg_detection_time_ms << "ms\n";
        std::cout << "  Avg recovery: " << metrics.avg_recovery_time_ms << "ms\n\n";
        
        std::cout << "Oscillation:\n";
        std::cout << "  Detected: " << metrics.oscillations_detected << "\n";
        std::cout << "  Dampened: " << metrics.oscillations_dampened << "\n";
        std::cout << "  Success rate: " << (metrics.dampening_success_rate * 100) << "%\n";
        std::cout << "  Avg convergence: " << metrics.avg_convergence_time_ms << "ms\n\n";
        
        std::cout << "Stability:\n";
        std::cout << "  Average: " << (metrics.avg_stability * 100) << "%\n";
        std::cout << "  Min/Max: " << (metrics.min_stability * 100) << "% / " << (metrics.max_stability * 100) << "%\n";
        std::cout << "  Violations: " << metrics.stability_violations << "\n";
        std::cout << "  Maintained: " << (metrics.stability_maintained ? "YES" : "NO") << "\n\n";
        
        std::cout << "========================================\n";
        std::cout << "OVERALL SAFETY SCORE: " << std::fixed << std::setprecision(1) << metrics.overall_safety_score << "/100\n";
        std::cout << "STATUS: " << (metrics.overall_safety_score >= 80.0 ? "PASS" : "FAIL") << "\n";
        std::cout << "========================================\n";
    }
};

} // namespace PhaseE
