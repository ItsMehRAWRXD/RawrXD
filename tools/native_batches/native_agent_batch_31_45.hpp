#pragma once
#include "native_agent_batch_16_30.hpp"
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>
namespace RawrXD::NativeBridge {
// 31-45: execution planning, provenance, and bounded validation.
struct ExecutionReceipt {std::string taskId, tool, inputHash, outputHash, error; bool success=false;};
std::string canonicalTask(const Task& task);                                      // 31
std::string taskFingerprint(const Task& task);                                    // 32
Result validateTaskIds(const std::vector<Task>& tasks);                           // 33
Result validateTaskArguments(const Task& task, size_t maxArgs, size_t maxBytes);   // 34
std::vector<std::string> dependencyClosure(const std::vector<Task>& tasks,
                                           const std::string& id, std::string& error); // 35
std::vector<std::vector<std::string>> executionWaves(const std::vector<Task>& tasks,
                                                     std::string& error);         // 36
std::string serializeReceipt(const ExecutionReceipt& receipt);                    // 37
std::optional<ExecutionReceipt> parseReceipt(const std::string& line);            // 38
class ReceiptStore {                                                              // 39
public:
 explicit ReceiptStore(std::filesystem::path path);
 bool append(const ExecutionReceipt& receipt, std::string& error);
 std::vector<ExecutionReceipt> read(std::string& error) const;
private: Journal journal_;
};
Result verifyReceiptChain(const std::vector<ExecutionReceipt>& receipts);          // 40
Result runChecked(const Task& task, const ControlledTools& tools,
                  const std::atomic<bool>& cancel, ExecutionReceipt& receipt);     // 41
Result runWave(const std::vector<Task>& tasks, const ControlledTools& tools,
               const std::atomic<bool>& cancel, std::vector<ExecutionReceipt>& receipts); // 42
Result validateOutput(const Result& result, size_t maxOutputBytes);                // 43
Result checkExpectedText(const Result& result, const std::string& expected);       // 44
struct BatchReport {size_t succeeded=0,failed=0,skipped=0; bool complete=false;};
BatchReport summarize(const std::vector<ExecutionReceipt>& receipts,
                      size_t plannedTasks);                                        // 45
}
