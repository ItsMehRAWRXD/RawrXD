// Phase W.2/5: Capability Registry
// RawrXD Capability Registry - Unified subsystem capability advertisement

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Convergence {

// Capability states
enum class CapabilityState {
    UNAVAILABLE,    // Not available
    EXPERIMENTAL,   // Available but experimental
    BETA,           // Available, beta quality
    STABLE,         // Available, stable
    DEPRECATED      // Available but deprecated
};

// Validation levels
enum class ValidationLevel {
    NONE,           // No validation
    UNIT_TESTED,    // Unit tests pass
    INTEGRATION_TESTED, // Integration tests pass
    BENCHMARKED,    // Benchmarked
    PRODUCTION_READY // Production validated
};

// Capability descriptor
struct CapabilityDescriptor {
    std::string capability_id;
    std::string name;
    std::string version;
    std::string description;
    std::string subsystem;  // "runtime", "inference", "agents", "memory", etc.
    
    // State
    CapabilityState state;
    ValidationLevel validation_level;
    
    // Dependencies
    std::vector<std::string> dependencies;
    std::vector<std::string> optional_dependencies;
    
    // Evidence
    std::vector<std::string> test_suites;
    std::vector<std::string> benchmarks;
    std::vector<std::string> documentation;
    
    // Metadata
    std::chrono::system_clock::time_point implemented_at;
    std::chrono::system_clock::time_point validated_at;
    std::string implemented_by;
    std::string validated_by;
    
    // Performance
    std::unordered_map<std::string, double> performance_metrics;
    std::unordered_map<std::string, std::string> configuration;
};

// Capability query
struct CapabilityQuery {
    std::string subsystem_filter;
    CapabilityState min_state;
    ValidationLevel min_validation;
    bool require_tests;
    bool require_benchmarks;
};

// Dependency graph
struct DependencyGraph {
    std::string root_capability;
    std::unordered_map<std::string, std::vector<std::string>> dependencies;
    std::unordered_map<std::string, bool> is_satisfied;
    std::vector<std::string> missing_dependencies;
    std::vector<std::string> circular_dependencies;
};

// Capability registry interface
class ICapabilityRegistry {
public:
    virtual ~ICapabilityRegistry() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Registration
    virtual std::string RegisterCapability(const CapabilityDescriptor& capability) = 0;
    virtual bool UnregisterCapability(const std::string& capability_id) = 0;
    virtual bool UpdateCapability(const CapabilityDescriptor& capability) = 0;
    
    // Query
    virtual std::optional<CapabilityDescriptor> GetCapability(const std::string& capability_id) = 0;
    virtual std::vector<CapabilityDescriptor> QueryCapabilities(const CapabilityQuery& query) = 0;
    virtual std::vector<CapabilityDescriptor> GetCapabilitiesBySubsystem(const std::string& subsystem) = 0;
    virtual std::vector<CapabilityDescriptor> GetCapabilitiesByState(CapabilityState state) = 0;
    
    // State management
    virtual bool SetCapabilityState(const std::string& capability_id, CapabilityState state) = 0;
    virtual bool SetValidationLevel(const std::string& capability_id, ValidationLevel level) = 0;
    
    // Dependency checking
    virtual DependencyGraph BuildDependencyGraph(const std::string& capability_id) = 0;
    virtual bool CheckDependencies(const std::string& capability_id) = 0;
    virtual std::vector<std::string> GetMissingDependencies(const std::string& capability_id) = 0;
    virtual bool ResolveDependencies(const std::string& capability_id) = 0;
    
    // Evidence
    virtual bool AddTestEvidence(const std::string& capability_id, const std::string& test_suite) = 0;
    virtual bool AddBenchmarkEvidence(const std::string& capability_id, const std::string& benchmark) = 0;
    virtual bool AddDocumentation(const std::string& capability_id, const std::string& doc_path) = 0;
    
    // Performance
    virtual bool SetPerformanceMetric(const std::string& capability_id, 
                                       const std::string& metric, 
                                       double value) = 0;
    virtual std::optional<double> GetPerformanceMetric(const std::string& capability_id, 
                                                          const std::string& metric) = 0;
    
    // Validation
    virtual bool ValidateCapability(const std::string& capability_id) = 0;
    virtual std::vector<std::string> GetValidationErrors(const std::string& capability_id) = 0;
    
    // Statistics
    virtual struct RegistryStatistics {
        uint32_t total_capabilities;
        uint32_t available_capabilities;
        uint32_t experimental_capabilities;
        uint32_t stable_capabilities;
        uint32_t deprecated_capabilities;
        uint32_t unit_tested;
        uint32_t integration_tested;
        uint32_t benchmarked;
        uint32_t production_ready;
        std::unordered_map<std::string, uint32_t> by_subsystem;
    } GetStatistics() = 0;
    
    // Dashboard
    virtual std::string GenerateEvidenceDashboard() = 0;
    virtual std::string GenerateSubsystemReport(const std::string& subsystem) = 0;
};

// Local capability registry
class LocalCapabilityRegistry : public ICapabilityRegistry {
public:
    LocalCapabilityRegistry();
    ~LocalCapabilityRegistry() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RegisterCapability(const CapabilityDescriptor& capability) override;
    bool UnregisterCapability(const std::string& capability_id) override;
    bool UpdateCapability(const CapabilityDescriptor& capability) override;
    
    std::optional<CapabilityDescriptor> GetCapability(const std::string& capability_id) override;
    std::vector<CapabilityDescriptor> QueryCapabilities(const CapabilityQuery& query) override;
    std::vector<CapabilityDescriptor> GetCapabilitiesBySubsystem(const std::string& subsystem) override;
    std::vector<CapabilityDescriptor> GetCapabilitiesByState(CapabilityState state) override;
    
    bool SetCapabilityState(const std::string& capability_id, CapabilityState state) override;
    bool SetValidationLevel(const std::string& capability_id, ValidationLevel level) override;
    
    DependencyGraph BuildDependencyGraph(const std::string& capability_id) override;
    bool CheckDependencies(const std::string& capability_id) override;
    std::vector<std::string> GetMissingDependencies(const std::string& capability_id) override;
    bool ResolveDependencies(const std::string& capability_id) override;
    
    bool AddTestEvidence(const std::string& capability_id, const std::string& test_suite) override;
    bool AddBenchmarkEvidence(const std::string& capability_id, const std::string& benchmark) override;
    bool AddDocumentation(const std::string& capability_id, const std::string& doc_path) override;
    
    bool SetPerformanceMetric(const std::string& capability_id, 
                               const std::string& metric, 
                               double value) override;
    std::optional<double> GetPerformanceMetric(const std::string& capability_id, 
                                                const std::string& metric) override;
    
    bool ValidateCapability(const std::string& capability_id) override;
    std::vector<std::string> GetValidationErrors(const std::string& capability_id) override;
    
    RegistryStatistics GetStatistics() override;
    
    std::string GenerateEvidenceDashboard() override;
    std::string GenerateSubsystemReport(const std::string& subsystem) override;
    
private:
    std::unordered_map<std::string, CapabilityDescriptor> capabilities_;
    bool initialized_ = false;
    
    bool MatchesQuery(const CapabilityDescriptor& cap, const CapabilityQuery& query);
    void BuildDependencyGraphRecursive(const std::string& cap_id, 
                                        DependencyGraph& graph,
                                        std::unordered_set<std::string>& visited);
    bool DetectCircularDependency(const std::string& cap_id, 
                                   std::unordered_set<std::string>& path);
    std::string GenerateMarkdownDashboard();
};

// Global capability registry
extern std::unique_ptr<ICapabilityRegistry> g_capability_registry;

// Initialize capability registry
bool InitializeCapabilityRegistry(const std::string& config_path);
void ShutdownCapabilityRegistry();
bool IsCapabilityRegistryEnabled();

// State helpers
std::string CapabilityStateToString(CapabilityState state);
CapabilityState CapabilityStateFromString(const std::string& str);
std::string ValidationLevelToString(ValidationLevel level);
ValidationLevel ValidationLevelFromString(const std::string& str);

} // namespace Convergence
} // namespace RawrXD
