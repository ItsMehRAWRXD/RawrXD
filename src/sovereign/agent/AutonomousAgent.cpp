// AutonomousAgent.cpp
// Self-Optimizing Agent with Feedback Loop

#include "AutonomousAgent.hpp"
#include <iostream>

namespace Sovereign {

void AutonomousAgent::Start() {
    if (running.exchange(true)) {
        return; // Already running
    }
    
    // Start evaluation thread
    evaluationThread = std::thread(&AutonomousAgent::EvaluationLoop, this);
    
    // Start execution thread
    executionThread = std::thread(&AutonomousAgent::ExecutionLoop, this);
}

void AutonomousAgent::Stop() {
    if (!running.exchange(false)) {
        return; // Not running
    }
    
    // Wake up threads
    queueCV.notify_all();
    
    // Join threads
    if (evaluationThread.joinable()) {
        evaluationThread.join();
    }
    if (executionThread.joinable()) {
        executionThread.join();
    }
}

void AutonomousAgent::EvaluationLoop() {
    while (running.load()) {
        // Sleep for evaluation interval
        std::this_thread::sleep_for(
            std::chrono::milliseconds(evaluationIntervalMs));
        
        if (!running.load()) break;
        
        // Get current metrics
        TelemetryMetrics metrics;
        {
            std::lock_guard<std::mutex> lock(metricsLock);
            metrics = currentMetrics;
        }
        
        // Evaluate and generate action
        OptimizationAction action = decisionEngine.Evaluate(metrics);
        
        if (action.type != OptimizationAction::NONE) {
            // Queue action for execution
            {
                std::lock_guard<std::mutex> lock(queueLock);
                actionQueue.push(action);
            }
            queueCV.notify_one();
        }
    }
}

void AutonomousAgent::ExecutionLoop() {
    while (running.load()) {
        OptimizationAction action;
        
        {
            std::unique_lock<std::mutex> lock(queueLock);
            queueCV.wait(lock, [this] { 
                return !actionQueue.empty() || !running.load(); 
            });
            
            if (!running.load() && actionQueue.empty()) {
                return;
            }
            
            if (actionQueue.empty()) {
                continue;
            }
            
            action = actionQueue.front();
            actionQueue.pop();
        }
        
        // Process the action
        ProcessAction(action);
    }
}

void AutonomousAgent::ProcessAction(const OptimizationAction& action) {
    // Log action
    std::cout << "[AutonomousAgent] Action: " << actionExecutor.ActionToString(action.type)
              << " - " << action.reason << std::endl;
    
    // Execute action
    actionExecutor.Execute(action);
    
    // Additional handling based on action type
    switch (action.type) {
        case OptimizationAction::INCREASE_THREAD_AFFINITY:
            // Could set thread affinity masks here
            break;
            
        case OptimizationAction::REDUCE_BATCH_SIZE:
            // Could adjust batch processing parameters
            break;
            
        case OptimizationAction::EXPAND_MEMORY_APERTURE:
            // Could trigger memory pre-allocation
            break;
            
        case OptimizationAction::TRIGGER_CHECKPOINT:
            // Could trigger session checkpoint
            if (store) {
                // Save current state
            }
            break;
            
        case OptimizationAction::INCREASE_BATCH_SIZE:
            // Could increase batch processing
            break;
            
        case OptimizationAction::APPLY_PATCH:
            // Could apply performance patch
            break;
            
        case OptimizationAction::ROLLBACK_PATCH:
            // Could rollback problematic patch
            break;
            
        case OptimizationAction::SPAWN_SUBAGENT:
            // Could spawn specialized sub-agent
            if (runtime) {
                // Spawn sub-agent via runtime
            }
            break;
            
        default:
            break;
    }
}

void AutonomousAgent::UpdateMetrics(const TelemetryMetrics& metrics) {
    std::lock_guard<std::mutex> lock(metricsLock);
    currentMetrics = metrics;
}

TelemetryMetrics AutonomousAgent::GetMetrics() const {
    std::lock_guard<std::mutex> lock(metricsLock);
    return currentMetrics;
}

void AutonomousAgent::ForceEvaluation() {
    // Wake up evaluation thread immediately
    // This is a no-op in current implementation but could signal the thread
}

} // namespace Sovereign
