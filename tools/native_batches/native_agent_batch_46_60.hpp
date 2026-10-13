#pragma once
#include "native_agent_batch_31_45.hpp"
#include <chrono>
#include <set>
namespace RawrXD::NativeBridge {
// 46-60: guarded execution, deterministic diagnostics, and reproducible receipts.
struct RunConfig {size_t maxTasks=128,maxArgs=32,maxArgBytes=65536,maxOutputBytes=1048576;std::set<std::string> permittedTools;};
Result validateRunConfig(const RunConfig& config); // 46
Result preflightTasks(const std::vector<Task>& tasks,const RunConfig& config); // 47
std::vector<std::string> rootsOf(const std::vector<Task>& tasks,std::string& error); // 48
std::vector<std::string> dependentsOf(const std::vector<Task>& tasks,const std::string& id,std::string& error); // 49
std::vector<std::string> terminalFailures(const std::vector<ExecutionReceipt>& receipts); // 50
Result validateReceiptsAgainstTasks(const std::vector<Task>& tasks,const std::vector<ExecutionReceipt>& receipts); // 51
std::string renderExecutionReport(const std::vector<Task>& tasks,const std::vector<ExecutionReceipt>& receipts); // 52
Result verifyExpectedFingerprints(const std::vector<ExecutionReceipt>& receipts,const std::map<std::string,std::string>& expected); // 53
Result guardedRun(const Task& task,const RunConfig& config,const ControlledTools& tools,const std::atomic<bool>& cancel,ExecutionReceipt& receipt); // 54
Result guardedPlanRun(const std::vector<Task>& tasks,const RunConfig& config,const ControlledTools& tools,const std::atomic<bool>& cancel,std::vector<ExecutionReceipt>& receipts); // 55
Result validateNoDuplicateReceipts(const std::vector<ExecutionReceipt>& receipts); // 56
std::vector<std::string> pendingTaskIds(const std::vector<Task>& tasks,const std::vector<ExecutionReceipt>& receipts); // 57
Result verifyCompletedPlan(const std::vector<Task>& tasks,const std::vector<ExecutionReceipt>& receipts); // 58
std::string escapeLogField(const std::string& field); // 59
std::string diagnosticLine(const ExecutionReceipt& receipt); // 60
}
