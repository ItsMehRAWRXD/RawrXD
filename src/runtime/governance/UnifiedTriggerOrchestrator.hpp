#pragma once
#include "HardwareCapabilityProbe.hpp"
#include "CapabilityTierMatrix.hpp"
#include "HardwareGovernor.hpp"
#include "PressedStateEngine.hpp"
#include "Ensemble58Governor.hpp"
#include "TLSInstructionGate.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
namespace RawrXD::Governance {enum class Trigger:uint8_t{ColdBoot,HardwareChange,MemoryPressure,ContextPressure,Periodic};struct RuntimePlan{HardwareSnapshot hardware;TierDecision capability;CapabilityTier effective_tier=CapabilityTier::Emergency;PressureDecision pressure{PressureLevel::Normal,8,false,false,false,false};InstructionPath instruction_path=InstructionPath::Scalar;bool use_ensemble=false;std::string reason;};struct OrchestratorCallbacks{std::function<void(const RuntimePlan&)>apply_plan;std::function<uint64_t()>context_tokens;};class UnifiedTriggerOrchestrator{public:explicit UnifiedTriggerOrchestrator(OrchestratorCallbacks={});~UnifiedTriggerOrchestrator();bool initialize();RuntimePlan evaluate(Trigger=Trigger::Periodic);void start(std::chrono::milliseconds=std::chrono::milliseconds(1000));void stop();RuntimePlan snapshot()const;private:void loop(std::chrono::milliseconds);HardwareCapabilityProbe probe_;CapabilityTierMatrix matrix_;HardwareGovernor governor_;PressedStateEngine pressure_;OrchestratorCallbacks cb_;mutable std::mutex mu_;RuntimePlan plan_{};HardwareSnapshot last_hw_{};std::thread worker_;std::atomic<bool>running_{false};};}
