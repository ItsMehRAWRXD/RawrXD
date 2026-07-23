// ============================================================================
// ValidationGate_Master.h - Master Validation Gate Registry
// RawrXD Sovereign Inference System
// ============================================================================
// This file defines the complete validation gate framework for RawrXD.
// Each VAL-XXX gate represents a certification milestone.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <unordered_map>

namespace RawrXD {
namespace Validation {

// Validation Gate Status
enum class GateStatus {
    NOT_IMPLEMENTED = 0,
    IN_PROGRESS,
    IMPLEMENTED,
    CERTIFIED,
    FAILED
};

// Validation Result
struct ValidationResult {
    bool passed;
    std::string gateId;
    std::string message;
    double durationMs;
    std::vector<std::string> details;
    
    ValidationResult() : passed(false), durationMs(0.0) {}
};

// Validation Gate Interface
class IValidationGate {
public:
    virtual ~IValidationGate() = default;
    virtual std::string GetId() const = 0;
    virtual std::string GetName() const = 0;
    virtual std::string GetDescription() const = 0;
    virtual GateStatus GetStatus() const = 0;
    virtual ValidationResult Execute() = 0;
    virtual std::vector<std::string> GetDependencies() const = 0;
};

// Master Registry
class ValidationGateRegistry {
public:
    static ValidationGateRegistry& Instance();
    
    void RegisterGate(std::shared_ptr<IValidationGate> gate);
    void UnregisterGate(const std::string& gateId);
    
    std::shared_ptr<IValidationGate> GetGate(const std::string& gateId);
    std::vector<std::shared_ptr<IValidationGate>> GetAllGates();
    std::vector<std::shared_ptr<IValidationGate>> GetGatesByStatus(GateStatus status);
    
    ValidationResult RunGate(const std::string& gateId);
    ValidationResult RunAllGates();
    ValidationResult RunGatesUpTo(const std::string& gateId);
    
    void PrintRegistryStatus();
    
private:
    ValidationGateRegistry() = default;
    std::unordered_map<std::string, std::shared_ptr<IValidationGate>> gates_;
};

// Gate Registration Macro
#define REGISTER_VALIDATION_GATE(GateClass) \
    static struct GateClass##_Registrar { \
        GateClass##_Registrar() { \
            RawrXD::Validation::ValidationGateRegistry::Instance().RegisterGate( \
                std::make_shared<GateClass>()); \
        } \
    } GateClass##_instance;

} // namespace Validation
} // namespace RawrXD
