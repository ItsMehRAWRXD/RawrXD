#pragma once

#include "meta_circular_vm.hpp"
#include "certified_compiler.hpp"

namespace val063 {

// RawrXD IDE Integration Layer
// Connects VAL-063 certification to the IDE's autonomous agent system

struct IDEConfig {
    // Paths
    std::string workspace_root;
    std::string certification_cache;
    std::string replay_artifacts;
    
    // Certification settings
    bool enable_realtime_attestation{true};
    bool enable_self_healing{true};
    bool require_replay_verification{true};
    
    // Autonomous agent integration
    bool enable_autonomous_compilation{false};
    uint32_t max_autonomous_iterations{100};
};

// IDE Certification Manager
// Manages the certification lifecycle for IDE operations
class IDECertificationManager {
public:
    explicit IDECertificationManager(const IDEConfig& config);
    
    // Initialize IDE with VAL-063 gates
    bool initialize();
    
    // Compile file with certification
    // Every compilation produces attestation evidence
    AttestationRecord compile_file(const std::string& filepath);
    
    // Execute compiled output with verification
    AttestationRecord execute_file(const std::string& filepath);
    
    // Self-healing: Detect and fix corrupted modules
    bool self_heal();
    
    // Export IDE certification report
    std::string export_certification_report();
    
    // Get certification status
    struct Status {
        bool gate_a_ready{false};  // Identity primitives
        bool gate_b_ready{false};  // Gateway binding
        bool gate_c_ready{false};  // Streaming adapter
        bool gate_d_ready{false};  // Replay harness
        uint64_t certified_compilations{0};
        uint64_t verified_executions{0};
        uint64_t self_heal_events{0};
    };
    Status get_status() const;
    
private:
    IDEConfig config_;
    std::unique_ptr<CertifiedCompiler> compiler_;
    std::unique_ptr<MetaCircularVM> vm_;
    
    Status status_;
    
    // Certification cache
    std::unordered_map<std::string, AttestationRecord> compilation_cache_;
    
    // Initialize gates
    bool init_gate_a();  // Identity
    bool init_gate_b();  // Gateway
    bool init_gate_c();  // Streaming
    bool init_gate_d();  // Replay
};

// Autonomous compilation agent
// Part of RawrXD's autonomous agent system
class AutonomousCompilationAgent {
public:
    AutonomousCompilationAgent(IDECertificationManager* manager);
    
    // Start autonomous compilation loop
    // Continuously compiles, verifies, and optimizes code
    void start();
    void stop();
    
    // Get agent status
    struct AgentStatus {
        bool running{false};
        uint64_t iterations{0};
        uint64_t successful_compilations{0};
        uint64_t failed_compilations{0};
        uint64_t optimizations_applied{0};
        Hash256 current_identity;
    };
    AgentStatus get_status() const;
    
private:
    IDECertificationManager* manager_;
    std::atomic<bool> running_{false};
    AgentStatus status_;
    
    void autonomous_loop();
    bool attempt_compilation();
    bool verify_and_optimize();
};

// Integration with existing RawrXD modules
namespace rawrxd_integration {
    // Bridge to RawrXD.Agentic.psm1
    bool invoke_agentic_compilation(const std::string& source);
    
    // Bridge to RawrXD.DeploymentOrchestrator
    bool deploy_certified_module(const CompilationUnit& unit);
    
    // Bridge to RawrXD.SwarmIntelligence
    std::vector<AttestationRecord> swarm_verify(const std::vector<CompilationUnit>& units);
}

} // namespace val063
