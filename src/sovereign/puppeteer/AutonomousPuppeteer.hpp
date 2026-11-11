#pragma once
#include "PuppeteerAPI.hpp"
#include "SymbolTableGenerator.hpp"
#include "../patcher/HotPatcher.hpp"
#include "../patcher/Deep2Engine.hpp"
#include "../patcher/AgenticSupervisor.hpp"
#include <memory>

namespace RawrXD {
namespace Sovereign {

// AutonomousPuppeteer - The complete self-modification system
// This is what the agent uses to see and modify itself
class AutonomousPuppeteer {
public:
    static AutonomousPuppeteer& Instance();
    
    // Initialize the complete puppeteer stack
    bool Initialize();
    bool IsInitialized() const { return initialized_; }
    
    // Get access to individual components
    PuppeteerAPI& GetPuppeteer() { return PuppeteerAPI::Instance(); }
    SymbolTableGenerator& GetSymbolTable() { return SymbolTableGenerator::Instance(); }
    HotPatcher& GetHotPatcher() { return HotPatcher::Instance(); }
    Deep2Engine& GetDeep2Engine() { return Deep2Engine::Instance(); }
    AgenticSupervisor& GetSupervisor() { return AgenticSupervisor::Instance(); }
    
    // High-level autonomous operations
    
    // Self-introspection: What functions do I have?
    std::vector<std::string> ListOwnFunctions(const std::string& pattern = "");
    
    // Self-introspection: What does this function do?
    std::string AnalyzeFunction(const std::string& functionName);
    
    // Self-modification: Replace my own behavior
    bool ModifyOwnFunction(const std::string& functionName, 
                          const std::vector<uint8_t>& newImplementation);
    
    // Self-modification: Optimize based on telemetry
    bool AutoOptimizeFromTelemetry();
    
    // Self-modification: Inject new capability
    bool InjectCapability(const std::string& capabilityName,
                          const std::vector<uint8_t>& code);
    
    // Safety: Verify system integrity
    bool VerifyIntegrity();
    
    // Safety: Emergency rollback all changes
    bool EmergencyRollback();
    
    // Agent-facing API - what the AI actually calls
    struct AgentInterface {
        // Query
        std::function<std::vector<std::string>(const std::string&)> findFunctions;
        std::function<std::string(const std::string&)> getFunctionCode;
        std::function<std::string(uintptr_t, size_t)> readMemoryHex;
        
        // Modify
        std::function<bool(const std::string&, const std::vector<uint8_t>&)> patchFunction;
        std::function<bool(uintptr_t, const std::vector<uint8_t>&)> writeMemory;
        std::function<bool()> rollbackLast;
        
        // Safety
        std::function<bool(const std::string&)> validatePatch;
        std::function<std::vector<std::string>()> getHistory;
    };
    
    AgentInterface GetAgentInterface();
    
private:
    AutonomousPuppeteer() = default;
    ~AutonomousPuppeteer() = default;
    
    AutonomousPuppeteer(const AutonomousPuppeteer&) = delete;
    AutonomousPuppeteer& operator=(const AutonomousPuppeteer&) = delete;
    
    bool initialized_ = false;
    std::unique_ptr<IPatcher> patcherAdapter_;
};

// Global access for the agent
#define AGENT_PUPPETEER RawrXD::Sovereign::AutonomousPuppeteer::Instance()

} // namespace Sovereign
} // namespace RawrXD
