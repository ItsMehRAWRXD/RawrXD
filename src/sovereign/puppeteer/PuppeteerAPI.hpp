#pragma once
#include "SymbolTableGenerator.hpp"
#include "../patcher/IPatcher.hpp"
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <chrono>
#include <mutex>

namespace Sovereign { class IPatcher; }

namespace RawrXD {
namespace Sovereign {

using ::Sovereign::IPatcher;

// Puppeteer action types
enum class PuppeteerAction {
    READ_MEMORY,           // Introspect own code/data
    WRITE_MEMORY,          // Direct memory mutation
    PATCH_FUNCTION,        // Hotpatch a function
    ROLLBACK_PATCH,        // Undo last mutation
    COMPILE_JIT,           // Assemble new code
    INJECT_CODE,           // Execute new code
    SNAPSHOT_STATE,        // Save current execution state
    RESTORE_STATE,         // Restore from snapshot
    QUERY_SYMBOLS,         // Search symbol table
    VALIDATE_PATCH         // Pre-flight safety check
};

// Execution context for puppeteer operations
struct PuppeteerContext {
    uintptr_t targetAddress;
    std::vector<uint8_t> payload;
    std::string symbolName;
    uint32_t flags;
    
    // Safety parameters
    bool requireValidation = true;
    bool createRollbackPoint = true;
    uint32_t timeoutMs = 1000;
};

// Result of puppeteer operation
struct PuppeteerResult {
    bool success;
    std::string errorMessage;
    uintptr_t resultAddress;
    std::vector<uint8_t> payload;          // Data read/written
    std::vector<uint8_t> originalBytes;  // For rollback
    uint64_t executionTimeNs;
    
    // Telemetry
    uint32_t pageFaultsBefore;
    uint32_t pageFaultsAfter;
};

// The Puppeteer - Agent's interface to self-modification
class PuppeteerAPI {
public:
    static PuppeteerAPI& Instance();
    
    // Initialize with symbol table and patcher
    bool Initialize(IPatcher* patcher);
    
    // Core puppeteer operations
    PuppeteerResult ReadMemory(uintptr_t address, size_t size);
    PuppeteerResult WriteMemory(uintptr_t address, const std::vector<uint8_t>& data);
    
    // Symbol-aware operations
    PuppeteerResult PatchFunction(const std::string& functionName, 
                                   const std::vector<uint8_t>& newCode);
    PuppeteerResult PatchFunction(uintptr_t address, 
                                   const std::vector<uint8_t>& newCode,
                                   const std::string& description = "");
    
    // JIT compilation interface
    PuppeteerResult CompileJIT(const std::string& assemblyCode);
    PuppeteerResult InjectCode(uintptr_t entryPoint, const std::vector<uint8_t>& code);
    
    // State management
    PuppeteerResult SnapshotState(const std::string& snapshotName);
    PuppeteerResult RestoreState(const std::string& snapshotName);
    PuppeteerResult RollbackLastPatch();
    
    // Safety and validation
    bool ValidatePatchTarget(uintptr_t address);
    bool ValidatePatchTarget(uintptr_t address, size_t size);
    bool ValidatePatchTarget(const std::string& functionName);
    std::vector<std::string> GetPatchHistory() const;
    
    // Symbol table queries
    std::vector<std::string> FindFunctions(const std::string& pattern);
    std::string GetFunctionDisassembly(const std::string& functionName, size_t maxBytes = 64);
    
    // Autonomous self-optimization
    bool EnableAutoOptimization(bool enable);
    bool IsAutoOptimizationEnabled() const;
    
    // Execute puppeteer script (sequence of operations)
    std::vector<PuppeteerResult> ExecuteScript(const std::vector<PuppeteerContext>& script);
    
private:
    PuppeteerAPI() = default;
    ~PuppeteerAPI() = default;
    
    PuppeteerAPI(const PuppeteerAPI&) = delete;
    PuppeteerAPI& operator=(const PuppeteerAPI&) = delete;
    
    bool PreFlightCheck(const PuppeteerContext& ctx);
    bool PostFlightValidate(const PuppeteerContext& ctx, const PuppeteerResult& result);
    
    IPatcher* patcher_ = nullptr;
    bool initialized_ = false;
    bool autoOptimization_ = false;
    
    struct PatchRecord {
        std::string description;
        uintptr_t address;
        std::vector<uint8_t> originalBytes;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::vector<PatchRecord> patchHistory_;
    mutable std::mutex historyMutex_;
};

// Convenience macros for agent self-modification
#define AGENT_PATCH_FUNCTION(name, code) \
    RawrXD::Sovereign::PuppeteerAPI::Instance().PatchFunction(name, code)

#define AGENT_READ_SELF(addr, size) \
    RawrXD::Sovereign::PuppeteerAPI::Instance().ReadMemory(addr, size)

#define AGENT_SNAPSHOT(name) \
    RawrXD::Sovereign::PuppeteerAPI::Instance().SnapshotState(name)

#define AGENT_ROLLBACK() \
    RawrXD::Sovereign::PuppeteerAPI::Instance().RollbackLastPatch()

// Autonomous optimization trigger
#define AGENT_AUTO_OPTIMIZE(enable) \
    RawrXD::Sovereign::PuppeteerAPI::Instance().EnableAutoOptimization(enable)

} // namespace Sovereign
} // namespace RawrXD
