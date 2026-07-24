#pragma once

#include "certified_compiler.hpp"
#include <memory>
#include <stack>

namespace val063 {

// Meta-Circular Virtual Machine
// A VM that can execute certified bytecode and verify its own execution
// Part of RawrXD IDE's certified execution substrate

struct VMState {
    std::vector<uint64_t> stack;
    std::vector<uint8_t> memory;
    uint64_t pc{0};              // Program counter
    uint64_t sp{0};              // Stack pointer
    
    // VAL-063 attestation
    ExecutionId execution_id;
    std::vector<StreamingEvent> execution_trace;
    
    // Verification
    Hash256 state_hash;          // Hash of complete state
    bool deterministic{true};
};

enum class VMOpcode : uint8_t {
    // Stack operations
    PUSH = 0x01,
    POP = 0x02,
    DUP = 0x03,
    SWAP = 0x04,
    
    // Arithmetic
    ADD = 0x10,
    SUB = 0x11,
    MUL = 0x12,
    DIV = 0x13,
    
    // Memory
    LOAD = 0x20,
    STORE = 0x21,
    ALLOC = 0x22,
    FREE = 0x23,
    
    // Control flow
    JMP = 0x30,
    JZ = 0x31,
    CALL = 0x32,
    RET = 0x33,
    
    // VAL-063 specific
    ATTEST = 0x40,      // Generate execution witness
    VERIFY = 0x41,      // Verify current state
    COMMIT = 0x42,      // Commit state to manifest
    
    // Meta-circular
    SELF_INSPECT = 0x50,  // VM inspects its own state
    SELF_MODIFY = 0x51,   // VM modifies its own code (careful!)
    
    HALT = 0xFF
};

// The Meta-Circular VM
// Can execute certified bytecode and produce VAL-063 attestations
class MetaCircularVM {
public:
    MetaCircularVM();
    
    // Load certified bytecode
    bool load(const CompilationUnit& unit);
    
    // Execute with full attestation
    // Returns: Final state with execution trace
    VMState execute(const ExecutionIdentity& identity);
    
    // Step-by-step execution (for debugging)
    VMState step();
    
    // Verify execution trace
    bool verify_execution(const VMState& state);
    
    // VAL-064: Environment verification
    // Validates that current environment matches compilation environment
    EnvironmentVerificationResult verify_environment(const HostFingerprint& required);
    
    // VAL-064: Cross-environment execution
    // Executes only if environment is compatible
    VMState execute_cross_environment(const CompilationUnit& unit);
    
    // Self-inspection: VM analyzes its own bytecode
    // Returns: Hash of VM's own implementation
    Hash256 self_inspect();
    
    // Self-modification (with safeguards)
    // Only allowed in certified, replay-verified contexts
    bool self_modify(const std::vector<uint8_t>& new_bytecode, 
                     const AttestationRecord& attestation);
    
    // Get execution witness
    AttestationRecord get_witness() const;
    
    // Checkpoint state for rollback
    void checkpoint();
    bool rollback();
    
private:
    VMState state_;
    std::vector<uint8_t> bytecode_;
    std::stack<VMState> checkpoints_;
    
    std::unique_ptr<StreamingAdapter> stream_adapter_;
    
    // Opcode handlers
    void handle_push(uint64_t value);
    void handle_pop();
    void handle_arith(VMOpcode op);
    void handle_memory(VMOpcode op, uint64_t addr);
    void handle_control(VMOpcode op, uint64_t target);
    void handle_attest();
    void handle_verify();
    
    // State hashing for verification
    Hash256 hash_state() const;
};

// Integration with RawrXD IDE
class RawrXDCertifiedExecution {
public:
    // Compile and execute with full certification
    static AttestationRecord compile_and_execute(
        const std::string& source,
        CompilerConfig::Target target
    );
    
    // Verify IDE integrity (all gates)
    static bool verify_ide_integrity();
    
    // Self-hosting verification
    // IDE compiles itself, verifies output
    static bool verify_self_hosting();
};

} // namespace val063
