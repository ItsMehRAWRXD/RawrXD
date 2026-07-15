// Workload Profiles
// Defines standardized benchmark workloads for reproducible testing
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <vector>
#include <string>

namespace rawrxd::benchmark {

// ============================================================================
// Workload Profile Types
// ============================================================================
enum class WorkloadProfile {
    CHAT = 0,
    CODING = 1,
    AGENTIC = 2,
    SWARM = 3,
    LONG_CONTEXT = 4,
    AUTONOMOUS = 5,
    RECOVERY = 6,
    STRESS = 7
};

inline const char* WorkloadProfileToString(WorkloadProfile profile) {
    switch (profile) {
        case WorkloadProfile::CHAT: return "chat";
        case WorkloadProfile::CODING: return "coding";
        case WorkloadProfile::AGENTIC: return "agentic";
        case WorkloadProfile::SWARM: return "swarm";
        case WorkloadProfile::LONG_CONTEXT: return "long_context";
        case WorkloadProfile::AUTONOMOUS: return "autonomous";
        case WorkloadProfile::RECOVERY: return "recovery";
        case WorkloadProfile::STRESS: return "stress";
        default: return "unknown";
    }
}

// ============================================================================
// Workload Configuration
// ============================================================================
struct WorkloadConfig {
    WorkloadProfile profile;
    std::string name;
    std::string description;
    
    // Model configuration
    std::string model_name;
    int context_length = 4096;
    int max_tokens = 512;
    float temperature = 0.0f;
    int seed = 42;
    
    // Execution parameters
    int iteration_count = 50;
    int timeout_seconds = 300;
    int swarm_size = 16;
    
    // Success criteria
    double min_success_rate = 0.95;
    double max_mean_latency_ms = 5000.0;
    double min_mean_tps = 10.0;
    
    // Prompts
    std::vector<std::string> prompts;
    
    // Quality criteria
    bool require_compile_success = false;
    bool require_test_pass = false;
    bool require_json_valid = false;
    double min_quality_score = 70.0;
};

// ============================================================================
// Reference Workloads
// ============================================================================
class ReferenceWorkloads {
public:
    // Chat workload - interactive conversation
    static WorkloadConfig Chat() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::CHAT;
        config.name = "Chat";
        config.description = "Interactive conversation with multi-turn context";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 4096;
        config.max_tokens = 256;
        config.iteration_count = 50;
        config.timeout_seconds = 60;
        config.min_success_rate = 0.98;
        config.max_mean_latency_ms = 2000.0;
        config.min_mean_tps = 20.0;
        
        config.prompts = {
            "Hello! How are you today?",
            "What can you tell me about machine learning?",
            "Explain the difference between supervised and unsupervised learning.",
            "What are some practical applications of neural networks?",
            "How does backpropagation work in simple terms?",
            "Can you recommend resources for learning deep learning?",
            "What are the current limitations of AI systems?",
            "How might AI impact software development in the future?"
        };
        
        config.min_quality_score = 75.0;
        return config;
    }
    
    // Coding workload - code generation and editing
    static WorkloadConfig Coding() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::CODING;
        config.name = "Coding";
        config.description = "Multi-file code generation and editing tasks";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 8192;
        config.max_tokens = 512;
        config.iteration_count = 30;
        config.timeout_seconds = 120;
        config.min_success_rate = 0.90;
        config.max_mean_latency_ms = 5000.0;
        config.min_mean_tps = 15.0;
        
        config.prompts = {
            "Write a Python function to implement binary search with proper error handling.",
            "Create a C++ class for a thread-safe queue using mutexes and condition variables.",
            "Implement a JavaScript debounce function with cancellation support.",
            "Write a Rust function to parse JSON using serde with error handling.",
            "Create a Go HTTP server with middleware for logging and rate limiting.",
            "Implement a SQL query to find the top 10 customers by total purchase amount.",
            "Write a bash script to backup files with rotation and compression.",
            "Create a CMake configuration for a C++ project with dependencies."
        };
        
        config.require_compile_success = true;
        config.min_quality_score = 80.0;
        return config;
    }
    
    // Agentic workload - planning and execution
    static WorkloadConfig Agentic() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::AGENTIC;
        config.name = "Agentic";
        config.description = "Planning and execution with tool use";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 8192;
        config.max_tokens = 1024;
        config.iteration_count = 20;
        config.timeout_seconds = 300;
        config.min_success_rate = 0.85;
        config.max_mean_latency_ms = 10000.0;
        config.min_mean_tps = 10.0;
        
        config.prompts = {
            "Analyze this codebase and identify potential security vulnerabilities. "
            "Create a plan to fix them and estimate the effort required.",
            
            "Given a slow SQL query, analyze the execution plan and propose optimizations. "
            "Include index recommendations and query rewrites.",
            
            "Review this API design for REST best practices. Identify issues and propose improvements. "
            "Consider authentication, rate limiting, and error handling.",
            
            "Plan a refactoring of this monolithic application into microservices. "
            "Identify boundaries, dependencies, and migration strategy.",
            
            "Design a caching strategy for this high-traffic web application. "
            "Consider cache invalidation, consistency, and failure modes."
        };
        
        config.min_quality_score = 85.0;
        return config;
    }
    
    // Swarm workload - multi-agent coordination
    static WorkloadConfig Swarm() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::SWARM;
        config.name = "Swarm";
        config.description = "16-agent cooperative workflow";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 4096;
        config.max_tokens = 256;
        config.iteration_count = 10;
        config.timeout_seconds = 180;
        config.swarm_size = 16;
        config.min_success_rate = 0.80;
        config.max_mean_latency_ms = 15000.0;
        config.min_mean_tps = 5.0;
        
        config.prompts = {
            "Review this code for: security (4 agents), performance (4 agents), "
            "maintainability (4 agents), and testing (4 agents). Aggregate findings.",
            
            "Analyze this system architecture: scalability team (4 agents), "
            "reliability team (4 agents), cost team (4 agents), security team (4 agents). "
            "Create consolidated recommendations.",
            
            "Generate comprehensive documentation: API docs (4 agents), "
            "user guide (4 agents), developer guide (4 agents), deployment guide (4 agents). "
            "Ensure consistency across all sections."
        };
        
        config.min_quality_score = 75.0;
        return config;
    }
    
    // Long Context workload - retrieval over large contexts
    static WorkloadConfig LongContext() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::LONG_CONTEXT;
        config.name = "Long Context";
        config.description = "Retrieval and reasoning over large contexts";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 32768;
        config.max_tokens = 512;
        config.iteration_count = 20;
        config.timeout_seconds = 120;
        config.min_success_rate = 0.90;
        config.max_mean_latency_ms = 8000.0;
        config.min_mean_tps = 8.0;
        
        // These prompts assume context will be prepended
        config.prompts = {
            "What is the main conclusion of the document?",
            "Summarize the key findings in section 3.",
            "What evidence supports the hypothesis stated in the introduction?",
            "Compare the approaches discussed in sections 2 and 4.",
            "What are the limitations mentioned in the discussion section?",
            "Extract all citations to papers published after 2020.",
            "What methodology was used for the experiments in section 5?",
            "Identify any contradictions between different sections of the document."
        };
        
        config.min_quality_score = 80.0;
        return config;
    }
    
    // Autonomous workload - observe → decide → execute → learn
    static WorkloadConfig Autonomous() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::AUTONOMOUS;
        config.name = "Autonomous";
        config.description = "Full autonomous execution loop";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 8192;
        config.max_tokens = 1024;
        config.iteration_count = 10;
        config.timeout_seconds = 600;
        config.min_success_rate = 0.75;
        config.max_mean_latency_ms = 30000.0;
        config.min_mean_tps = 3.0;
        
        config.prompts = {
            "Given telemetry showing increased latency and error rates, analyze the situation, "
            "decide on the best course of action, and execute the fix. "
            "Then evaluate the results and learn from the outcome.",
            
            "A user has reported a critical bug. Investigate the issue, identify the root cause, "
            "implement a fix, verify with tests, and deploy. Document the resolution.",
            
            "The system is approaching resource limits. Analyze current usage, predict when limits "
            "will be hit, and implement optimizations to prevent degradation.",
            
            "A security vulnerability has been discovered. Assess the impact, plan the remediation, "
            "implement the fix, verify it resolves the issue, and update security documentation."
        };
        
        config.min_quality_score = 85.0;
        return config;
    }
    
    // Recovery workload - failure and recovery scenarios
    static WorkloadConfig Recovery() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::RECOVERY;
        config.name = "Recovery";
        config.description = "Failure injection and recovery testing";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 4096;
        config.max_tokens = 512;
        config.iteration_count = 20;
        config.timeout_seconds = 180;
        config.min_success_rate = 0.85;
        config.max_mean_latency_ms = 10000.0;
        config.min_mean_tps = 5.0;
        
        config.prompts = {
            "A critical service has failed. Diagnose the issue and restore service.",
            "Data corruption detected in the primary database. Recover without data loss.",
            "Network partition has occurred. Restore connectivity and reconcile state.",
            "Memory leak causing system instability. Identify source and implement fix.",
            "Configuration drift detected. Restore to known good state and prevent recurrence."
        };
        
        config.min_quality_score = 80.0;
        return config;
    }
    
    // Stress workload - high load testing
    static WorkloadConfig Stress() {
        WorkloadConfig config;
        config.profile = WorkloadProfile::STRESS;
        config.name = "Stress";
        config.description = "High load and resource pressure testing";
        config.model_name = "phi-3-mini-Q4";
        config.context_length = 4096;
        config.max_tokens = 256;
        config.iteration_count = 100;
        config.timeout_seconds = 300;
        config.swarm_size = 32;
        config.min_success_rate = 0.70;
        config.max_mean_latency_ms = 20000.0;
        config.min_mean_tps = 2.0;
        
        config.prompts = {
            "Process this request under high load conditions.",
            "Handle this task while resources are constrained."
        };
        
        config.min_quality_score = 60.0;
        return config;
    }
    
    // Get all workloads
    static std::vector<WorkloadConfig> All() {
        return {
            Chat(),
            Coding(),
            Agentic(),
            Swarm(),
            LongContext(),
            Autonomous(),
            Recovery(),
            Stress()
        };
    }
    
    // Get workload by profile
    static WorkloadConfig Get(WorkloadProfile profile) {
        switch (profile) {
            case WorkloadProfile::CHAT: return Chat();
            case WorkloadProfile::CODING: return Coding();
            case WorkloadProfile::AGENTIC: return Agentic();
            case WorkloadProfile::SWARM: return Swarm();
            case WorkloadProfile::LONG_CONTEXT: return LongContext();
            case WorkloadProfile::AUTONOMOUS: return Autonomous();
            case WorkloadProfile::RECOVERY: return Recovery();
            case WorkloadProfile::STRESS: return Stress();
            default: return Chat();
        }
    }
};

} // namespace rawrxd::benchmark
