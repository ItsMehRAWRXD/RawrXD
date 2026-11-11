// ============================================================================
// SelfImprovement.hpp - Post-mission evaluation and experience-driven improvement
// ============================================================================
#pragma once

#include "AgentTypes.hpp"
#include "KnowledgeGraph.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace RawrXD::Agentic {

// ============================================================================
// SelfImprovement - evaluates missions and drives continuous improvement
// ============================================================================

class SelfImprovement {
public:
    explicit SelfImprovement(std::shared_ptr<KnowledgeGraph> knowledge)
        : knowledge_(std::move(knowledge)) {}

    ~SelfImprovement() = default;

    // Evaluate a completed mission
    SelfEvaluation evaluateMission(const Mission& mission, 
                                    const std::vector<AgentResult>& agent_results) {
        SelfEvaluation eval;
        eval.mission_id = mission.id;
        
        std::cout << "\n[SelfImprovement] Evaluating mission: " << mission.description << std::endl;
        
        // 1. Calculate overall confidence
        double total_conf = 0.0;
        size_t success_count = 0;
        size_t failure_count = 0;
        
        for (const auto& result : agent_results) {
            total_conf += result.confidence;
            if (result.success) success_count++;
            else failure_count++;
            
            eval.agent_confidences.push_back({result.summary, result.confidence});
        }
        
        eval.overall_confidence = agent_results.empty() ? 0.0 : total_conf / agent_results.size();
        
        // 2. Identify disagreements
        for (size_t i = 0; i < agent_results.size(); ++i) {
            for (size_t j = i + 1; j < agent_results.size(); ++j) {
                if (agent_results[i].success != agent_results[j].success) {
                    eval.disagreements.push_back(
                        "Agent " + std::to_string(i) + " (" + agent_results[i].summary + ") vs " +
                        "Agent " + std::to_string(j) + " (" + agent_results[j].summary + ")"
                    );
                }
            }
        }
        
        // 3. Generate recommendations
        if (eval.overall_confidence < 0.5) {
            eval.recommendations.push_back("Overall confidence low - retrain pattern weights");
            eval.needs_retraining = true;
        }
        
        if (failure_count > success_count) {
            eval.recommendations.push_back("More failures than successes - review agent configurations");
        }
        
        if (!eval.disagreements.empty()) {
            eval.recommendations.push_back("Agent disagreements detected - generate verification tasks");
            eval.recommendations.push_back("Run additional verification on disputed regions");
        }
        
        // 4. Store successful workflow
        if (mission.is_successful && eval.overall_confidence > 0.7) {
            std::vector<std::string> workflow;
            workflow.push_back("mission:" + mission.description);
            for (const auto& result : agent_results) {
                if (result.success) {
                    workflow.push_back("step:" + result.summary);
                }
            }
            knowledge_->storeWorkflow(mission.description, workflow);
            eval.successful_workflows.push_back(mission.description);
        }
        
        // 5. Update knowledge graph with lessons
        for (const auto& rec : eval.recommendations) {
            knowledge_->addFact("agent_workflows", 
                "lesson_" + mission.id + "_" + std::to_string(lesson_counter_++),
                rec, 0.6);
        }
        
        // Print evaluation
        printEvaluation(eval);
        
        return eval;
    }

    // Retrain pattern weights based on evaluation
    void retrainWeights(const SelfEvaluation& eval) {
        if (!eval.needs_retraining) return;
        
        std::cout << "\n[SelfImprovement] Retraining pattern weights..." << std::endl;
        
        // Adjust confidence thresholds
        double new_threshold = std::max(0.3, eval.overall_confidence - 0.1);
        knowledge_->addFact("pattern_signatures", "confidence_threshold",
            std::to_string(new_threshold), 0.8);
        
        std::cout << "[SelfImprovement] New confidence threshold: " << new_threshold << std::endl;
    }

    // Generate verification tasks for low-confidence results
    std::vector<AgentGoal> generateVerificationTasks(const SelfEvaluation& eval) {
        std::vector<AgentGoal> tasks;
        
        for (const auto& disagreement : eval.disagreements) {
            AgentGoal task;
            task.description = "Verify: " + disagreement;
            task.priority = 0.7;
            task.success_criteria = {"Resolve disagreement", "Confidence > 0.8"};
            task.is_critical = true;
            tasks.push_back(task);
        }
        
        for (const auto& [agent_name, confidence] : eval.agent_confidences) {
            if (confidence < 0.4) {
                AgentGoal task;
                task.description = "Re-analyze with higher confidence: " + agent_name;
                task.priority = 0.5;
                task.success_criteria = {"Confidence > 0.7"};
                tasks.push_back(task);
            }
        }
        
        return tasks;
    }

    // Generate new hypotheses from evaluation
    std::vector<AgentGoal> generateNewHypotheses(const SelfEvaluation& eval) {
        std::vector<AgentGoal> hypotheses;
        
        if (eval.overall_confidence > 0.8) {
            AgentGoal hypothesis;
            hypothesis.description = "High confidence - attempt to generalize findings";
            hypothesis.priority = 0.6;
            hypothesis.success_criteria = {"Generate generalized pattern", "Update knowledge base"};
            hypotheses.push_back(hypothesis);
        }
        
        if (!eval.disagreements.empty()) {
            AgentGoal hypothesis;
            hypothesis.description = "Disagreements may indicate novel pattern - investigate";
            hypothesis.priority = 0.8;
            hypothesis.success_criteria = {"Resolve disagreement", "Document novel finding"};
            hypotheses.push_back(hypothesis);
        }
        
        return hypotheses;
    }

    // Get improvement statistics
    struct ImprovementStats {
        size_t total_evaluations;
        size_t retraining_events;
        size_t verification_tasks_generated;
        size_t new_hypotheses_generated;
        double average_confidence_improvement;
    };
    
    ImprovementStats getStats() const {
        ImprovementStats stats;
        stats.total_evaluations = evaluation_counter_;
        stats.retraining_events = retrain_counter_;
        stats.verification_tasks_generated = verification_counter_;
        stats.new_hypotheses_generated = hypothesis_counter_;
        stats.average_confidence_improvement = total_confidence_delta_ / std::max(1.0, (double)evaluation_counter_);
        return stats;
    }

private:
    void printEvaluation(const SelfEvaluation& eval) {
        std::cout << "  ┌─────────────────────────────────────────┐\n";
        std::cout << "  │ Self-Evaluation Report                   │\n";
        std::cout << "  ├─────────────────────────────────────────┤\n";
        std::cout << "  │ Mission: " << eval.mission_id << "\n";
        std::cout << "  │ Overall Confidence: " << std::fixed << std::setprecision(3) 
                  << eval.overall_confidence << "\n";
        std::cout << "  │ Disagreements: " << eval.disagreements.size() << "\n";
        std::cout << "  │ Recommendations: " << eval.recommendations.size() << "\n";
        std::cout << "  │ Needs Retraining: " << (eval.needs_retraining ? "YES" : "NO") << "\n";
        std::cout << "  └─────────────────────────────────────────┘\n";
        
        for (const auto& rec : eval.recommendations) {
            std::cout << "    * " << rec << "\n";
        }
    }

    std::shared_ptr<KnowledgeGraph> knowledge_;
    size_t evaluation_counter_ = 0;
    size_t retrain_counter_ = 0;
    size_t verification_counter_ = 0;
    size_t hypothesis_counter_ = 0;
    size_t lesson_counter_ = 0;
    double total_confidence_delta_ = 0.0;
};

} // namespace RawrXD::Agentic
