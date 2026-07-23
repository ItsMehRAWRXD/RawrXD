#include "PuppeteerAPI.hpp"
#include "../patcher/IPatcher.hpp"
#include <chrono>
#include <sstream>
#include <iomanip>

using ::Sovereign::PatchRequest;
using ::Sovereign::PatchResult;

namespace RawrXD {
namespace Sovereign {

PuppeteerAPI& PuppeteerAPI::Instance() {
    static PuppeteerAPI instance;
    return instance;
}

bool PuppeteerAPI::Initialize(IPatcher* patcher) {
    if (initialized_) return true;
    
    patcher_ = patcher;
    
    // Initialize symbol table
    if (!SymbolTableGenerator::Instance().Initialize()) {
        return false;
    }
    
    initialized_ = true;
    return true;
}

PuppeteerResult PuppeteerAPI::ReadMemory(uintptr_t address, size_t size) {
    PuppeteerResult result;
    result.success = false;
    
    auto start = std::chrono::steady_clock::now();
    
    // Validate address
    if (!SymbolTableGenerator::Instance().IsAddressReadable(address)) {
        result.errorMessage = "Address not readable";
        return result;
    }
    
    // Read memory
    result.payload.resize(size);
    try {
        std::memcpy(result.payload.data(), reinterpret_cast<const void*>(address), size);
        result.success = true;
        result.resultAddress = address;
    } catch (...) {
        result.errorMessage = "Memory read exception";
        return result;
    }
    
    auto end = std::chrono::steady_clock::now();
    result.executionTimeNs = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    
    return result;
}

PuppeteerResult PuppeteerAPI::WriteMemory(uintptr_t address, const std::vector<uint8_t>& data) {
    PuppeteerResult result;
    result.success = false;
    
    auto start = std::chrono::steady_clock::now();
    
    // Validate address
    if (!SymbolTableGenerator::Instance().IsAddressWritable(address)) {
        result.errorMessage = "Address not writable";
        return result;
    }
    
    // Save original bytes for potential rollback
    result.originalBytes.resize(data.size());
    std::memcpy(result.originalBytes.data(), reinterpret_cast<const void*>(address), data.size());
    
    // Write memory
    try {
        std::memcpy(reinterpret_cast<void*>(address), data.data(), data.size());
        result.success = true;
        result.resultAddress = address;
    } catch (...) {
        result.errorMessage = "Memory write exception";
        return result;
    }
    
    auto end = std::chrono::steady_clock::now();
    result.executionTimeNs = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    
    return result;
}

PuppeteerResult PuppeteerAPI::PatchFunction(const std::string& functionName, 
                                             const std::vector<uint8_t>& newCode) {
    // Resolve symbol
    uintptr_t address = SymbolTableGenerator::Instance().GetAddress(functionName);
    if (address == 0) {
        PuppeteerResult result;
        result.success = false;
        result.errorMessage = "Function not found: " + functionName;
        return result;
    }
    
    return PatchFunction(address, newCode, functionName);
}

PuppeteerResult PuppeteerAPI::PatchFunction(uintptr_t address, 
                                             const std::vector<uint8_t>& newCode,
                                             const std::string& description) {
    PuppeteerResult result;
    result.success = false;
    
    if (!patcher_) {
        result.errorMessage = "Patcher not initialized";
        return result;
    }
    
    auto start = std::chrono::steady_clock::now();
    
    // Pre-flight validation
    if (!ValidatePatchTarget(address)) {
        result.errorMessage = "Invalid patch target";
        return result;
    }
    
    // Save original bytes
    result.originalBytes.resize(newCode.size());
    std::memcpy(result.originalBytes.data(), reinterpret_cast<const void*>(address), newCode.size());
    
    // Apply patch via registered patcher
    PatchRequest request;
    request.address = address;
    request.replacement = newCode;
    request.reason = description.empty() ? "Agent self-patch" : description;
    
    PatchResult patchResult = patcher_->Apply(request);
    
    if (patchResult.success) {
        result.success = true;
        result.resultAddress = address;
        
        // Record in history
        {
            std::lock_guard<std::mutex> lock(historyMutex_);
            PatchRecord record;
            record.description = request.reason;
            record.address = address;
            record.originalBytes = result.originalBytes;
            record.timestamp = std::chrono::steady_clock::now();
            patchHistory_.push_back(record);
        }
    } else {
        result.errorMessage = patchResult.message;
    }
    
    auto end = std::chrono::steady_clock::now();
    result.executionTimeNs = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    
    return result;
}

PuppeteerResult PuppeteerAPI::CompileJIT(const std::string& assemblyCode) {
    PuppeteerResult result;
    result.success = false;
    result.errorMessage = "JIT compilation requires assembler integration";
    // TODO: Integrate with your MASM assembler toolchain
    return result;
}

PuppeteerResult PuppeteerAPI::InjectCode(uintptr_t entryPoint, const std::vector<uint8_t>& code) {
    // First patch the entry point
    auto patchResult = PatchFunction(entryPoint, code, "JIT code injection");
    
    if (patchResult.success) {
        // TODO: Execute the injected code via function pointer
        // This requires careful stack alignment and calling convention handling
    }
    
    return patchResult;
}

PuppeteerResult PuppeteerAPI::SnapshotState(const std::string& snapshotName) {
    PuppeteerResult result;
    result.success = false;
    
    // Export symbol table
    auto symData = SymbolTableGenerator::Instance().ExportToBinary();
    
    // TODO: Save to SessionStore
    // This would integrate with your existing checkpoint system
    
    result.success = true;
    result.errorMessage = "Snapshot: " + snapshotName + " (" + 
                         std::to_string(symData.size()) + " bytes of symbols)";
    
    return result;
}

PuppeteerResult PuppeteerAPI::RestoreState(const std::string& snapshotName) {
    PuppeteerResult result;
    result.success = false;
    result.errorMessage = "Restore not yet implemented - requires SessionStore integration";
    return result;
}

PuppeteerResult PuppeteerAPI::RollbackLastPatch() {
    PuppeteerResult result;
    result.success = false;
    
    std::lock_guard<std::mutex> lock(historyMutex_);
    
    if (patchHistory_.empty()) {
        result.errorMessage = "No patches to rollback";
        return result;
    }
    
    // Get last patch
    const auto& lastPatch = patchHistory_.back();
    
    // Restore original bytes
    try {
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<void*>(lastPatch.address), 
                       lastPatch.originalBytes.size(), 
                       PAGE_EXECUTE_READWRITE, &oldProtect);
        
        std::memcpy(reinterpret_cast<void*>(lastPatch.address), 
                   lastPatch.originalBytes.data(), 
                   lastPatch.originalBytes.size());
        
        VirtualProtect(reinterpret_cast<void*>(lastPatch.address), 
                       lastPatch.originalBytes.size(), 
                       oldProtect, &oldProtect);
        
        FlushInstructionCache(GetCurrentProcess(), 
                             reinterpret_cast<void*>(lastPatch.address), 
                             lastPatch.originalBytes.size());
        
        result.success = true;
        result.errorMessage = "Rolled back: " + lastPatch.description;
        
        // Remove from history
        patchHistory_.pop_back();
        
    } catch (...) {
        result.errorMessage = "Rollback failed";
    }
    
    return result;
}

bool PuppeteerAPI::ValidatePatchTarget(uintptr_t address, size_t size) {
    return SymbolTableGenerator::Instance().IsValidPatchTarget(address);
}

bool PuppeteerAPI::ValidatePatchTarget(const std::string& functionName) {
    return SymbolTableGenerator::Instance().IsValidPatchTarget(functionName);
}

std::vector<std::string> PuppeteerAPI::GetPatchHistory() const {
    std::lock_guard<std::mutex> lock(historyMutex_);
    std::vector<std::string> history;
    
    for (const auto& record : patchHistory_) {
        std::stringstream ss;
        ss << std::put_time(std::localtime(
            reinterpret_cast<const time_t*>(&record.timestamp)), "%Y-%m-%d %H:%M:%S");
        ss << " - " << record.description << " @ 0x" << std::hex << record.address;
        history.push_back(ss.str());
    }
    
    return history;
}

std::vector<std::string> PuppeteerAPI::FindFunctions(const std::string& pattern) {
    auto symbols = SymbolTableGenerator::Instance().FindSymbols(pattern);
    std::vector<std::string> results;
    
    for (const auto* sym : symbols) {
        if (sym->flags & 0x1) { // Code flag
            results.push_back(sym->name);
        }
    }
    
    return results;
}

std::string PuppeteerAPI::GetFunctionDisassembly(const std::string& functionName, size_t maxBytes) {
    auto sym = SymbolTableGenerator::Instance().GetSymbol(functionName);
    if (!sym) return "Function not found";
    
    // Read function bytes
    auto readResult = ReadMemory(sym->address, maxBytes);
    if (!readResult.success) return "Failed to read function";
    
    // Format as hex dump
    std::stringstream ss;
    ss << functionName << " @ 0x" << std::hex << sym->address << ":\n";
    
    for (size_t i = 0; i < readResult.payload.size(); i++) {
        if (i > 0 && i % 16 == 0) ss << "\n";
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(readResult.payload[i]) << " ";
    }
    
    return ss.str();
}

bool PuppeteerAPI::EnableAutoOptimization(bool enable) {
    autoOptimization_ = enable;
    return true;
}

bool PuppeteerAPI::IsAutoOptimizationEnabled() const {
    return autoOptimization_;
}

std::vector<PuppeteerResult> PuppeteerAPI::ExecuteScript(
    const std::vector<PuppeteerContext>& script) {
    std::vector<PuppeteerResult> results;
    
    for (const auto& ctx : script) {
        PuppeteerResult result;
        
        switch (ctx.flags) {
            case static_cast<uint32_t>(PuppeteerAction::READ_MEMORY):
                result = ReadMemory(ctx.targetAddress, ctx.payload.size());
                break;
            case static_cast<uint32_t>(PuppeteerAction::PATCH_FUNCTION):
                result = PatchFunction(ctx.targetAddress, ctx.payload, ctx.symbolName);
                break;
            case static_cast<uint32_t>(PuppeteerAction::ROLLBACK_PATCH):
                result = RollbackLastPatch();
                break;
            default:
                result.success = false;
                result.errorMessage = "Unknown action";
        }
        
        results.push_back(result);
        
        // Stop on failure unless continue-on-error is set
        if (!result.success && !(ctx.flags & 0x80000000)) {
            break;
        }
    }
    
    return results;
}

bool PuppeteerAPI::PreFlightCheck(const PuppeteerContext& ctx) {
    if (!ctx.requireValidation) return true;
    
    // Check if target is valid
    if (ctx.targetAddress != 0) {
        return ValidatePatchTarget(ctx.targetAddress, ctx.payload.size());
    }
    
    return true;
}

bool PuppeteerAPI::PostFlightValidate(const PuppeteerContext& ctx, const PuppeteerResult& result) {
    // Verify the patch was applied correctly
    if (!result.success) return false;
    
    // Read back and compare
    auto verify = ReadMemory(result.resultAddress, result.payload.size());
    if (!verify.success) return false;
    
    return std::equal(verify.payload.begin(), verify.payload.end(), 
                   ctx.payload.begin(), ctx.payload.end());
}

} // namespace Sovereign
} // namespace RawrXD
