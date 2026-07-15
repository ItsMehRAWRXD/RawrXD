#pragma once

#include "ghost_text_engine.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <future>

namespace RawrXD::Agentic {

// Autonomous step with metadata
struct AutonomousStep {
    std::string description;
    std::string command;
    float confidence;
    bool requires_approval;
    std::vector<std::string> dependencies;
    std::chrono::milliseconds estimated_time;
    bool completed = false;
    bool success = false;
    std::string output;
    std::string error;
};

// Goal decomposition result
struct GoalDecomposition {
    std::string original_goal;
    std::vector<AutonomousStep> steps;
    float overall_confidence;
    bool can_autonomous_execute;
    std::string reasoning;
};

// Execution result
struct ExecutionResult {
    bool success;
    std::string output;
    std::string error;
    std::vector<AutonomousStep> completed_steps;
    std::chrono::milliseconds duration;
};

// Main autonomous agent with ghost text integration
class AutonomousAgent {
public:
    AutonomousAgent();
    ~AutonomousAgent();
    
    // Execute a goal autonomously with ghost text
    ExecutionResult Execute(const std::string& goal);
    
    // Execute with live ghost text feedback
    ExecutionResult ExecuteWithGhost(const std::string& goal, 
                                      GhostTextEngine* ghost);
    
    // Decompose goal into steps
    GoalDecomposition DecomposeGoal(const std::string& goal);
    
    // Execute single step
    ExecutionResult ExecuteStep(const AutonomousStep& step);
    
    // Set approval callback for steps requiring confirmation
    using ApprovalCallback = std::function<bool(const AutonomousStep&)>;
    void SetApprovalCallback(ApprovalCallback callback);
    
    // Set progress callback
    using ProgressCallback = std::function<void(const AutonomousStep&, float)>;
    void SetProgressCallback(ProgressCallback callback);
    
    // Get current state
    bool IsExecuting() const { return is_executing_.load(); }
    float GetProgress() const { return current_progress_.load(); }
    std::string GetCurrentStep() const;
    
    // Cancel execution
    void Cancel();

private:
    // Core execution logic
    ExecutionResult ExecuteInternal(const std::string& goal, 
                                       GhostTextEngine* ghost);
    
    // Show ghost plan
    void ShowGhostPlan(const GoalDecomposition& decomposition, 
                       GhostTextEngine* ghost);
    
    // Show ghost step
    void ShowGhostStep(const AutonomousStep& step, GhostTextEngine* ghost);
    
    // Show ghost result
    void ShowGhostResult(const ExecutionResult& result, GhostTextEngine* ghost);
    
    // Reason about next step
    AutonomousStep ReasonNextStep(const std::vector<AutonomousStep>& completed,
                                   const std::vector<AutonomousStep>& remaining);
    
    // Update state
    void UpdateState(const AutonomousStep& step, bool success, 
                     const std::string& output);
    
    // Tool execution
    ExecutionResult ExecuteTool(const std::string& tool_name, 
                                 const std::string& args);
    
    // Native toolchain execution
    ExecutionResult ExecuteNativeCompile(const std::string& args);
    ExecutionResult ExecuteNativePatch(const std::string& args);
    ExecutionResult ExecuteNativeDisasm(const std::string& args);
    ExecutionResult ExecuteAnalyze(const std::string& args);
    ExecutionResult ExecuteSearch(const std::string& args);

private:
    std::atomic<bool> is_executing_{false};
    std::atomic<bool> should_cancel_{false};
    std::atomic<float> current_progress_{0.0f};
    
    std::string current_step_description_;
    std::mutex state_mutex_;
    
    ApprovalCallback approval_callback_;
    ProgressCallback progress_callback_;
    
    // Execution history
    std::vector<AutonomousStep> execution_history_;
    
    // Model interface for reasoning
    class ReasoningModel;
    std::unique_ptr<ReasoningModel> model_;
};

// Specialized agents for common tasks
class ReverseEngineeringAgent : public AutonomousAgent {
public:
    // Analyze binary and generate report
    ExecutionResult AnalyzeBinary(const std::string& binary_path);
    
    // Find and patch vulnerability
    ExecutionResult PatchVulnerability(const std::string& binary_path, 
                                         const std::string& description);
    
    // Extract and analyze strings
    ExecutionResult ExtractStrings(const std::string& binary_path);
};

class CompilationAgent : public AutonomousAgent {
public:
    // Compile with optimizations
    ExecutionResult CompileOptimized(const std::string& source_path);
    
    // Cross-compile for target
    ExecutionResult CrossCompile(const std::string& source_path, 
                                  const std::string& target_arch);
    
    // Self-hosting compilation
    ExecutionResult SelfHostCompile(const std::string& source_path);
};

class SecurityAuditAgent : public AutonomousAgent {
public:
    // Full security audit
    ExecutionResult AuditSecurity(const std::string& target_path);
    
    // Find hardcoded credentials
    ExecutionResult FindCredentials(const std::string& binary_path);
    
    // Check for anti-debug
    ExecutionResult DetectAntiDebug(const std::string& binary_path);
};

} // namespace RawrXD::Agentic
