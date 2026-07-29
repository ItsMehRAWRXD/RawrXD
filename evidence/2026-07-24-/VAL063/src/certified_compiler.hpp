#pragma once

#include "execution_types.hpp"
#include "replay_harness.hpp"
#include <vector>
#include <functional>

namespace val063 {

// Certified Compiler Interface
// Bridges VAL-063 attestation with code generation
// Every compilation produces a verifiable execution witness

struct CompilationUnit {
    std::string source_hash;        // SHA256(source code)
    std::string ast_hash;           // SHA256(AST representation)
    std::string bytecode_hash;      // SHA256(output)
    std::vector<uint8_t> bytecode;
    
    // VAL-063 identity
    ExecutionIdentity compiler_identity;
    ExecutionId compilation_id;
    Timestamp compiled_at;
    
    // VAL-064: Cross-environment replay metadata
    HostFingerprint environment_fingerprint;
    bool environment_captured{false};
    
    // Verification proof
    Hash256 verification_proof;
    bool deterministic_output;
    
    // Combined environment + identity hash for cross-machine verification
    Hash256 environment_identity_hash() const {
        HashProvider provider;
        provider.update(compiler_identity.to_canonical_bytes().data(), 128);
        auto env_bytes = environment_fingerprint.to_bytes();
        provider.update(env_bytes.data(), env_bytes.size());
        return provider.finalize();
    }
};

struct CompilerConfig {
    // Target specification
    enum Target {
        WASM_MVP,           // WebAssembly MVP
        WASM_SIMD,          // WebAssembly + SIMD
        NATIVE_X64,         // Native x64 (position independent)
        NATIVE_AVX512       // Native AVX-512 optimized
    };
    
    Target target{WASM_MVP};
    bool optimize{true};
    bool verify_output{true};      // Run VAL-063 verification
    bool self_hosting_mode{false};  // Compiler compiles itself
    
    // Identity for certification
    ExecutionIdentity identity;
};

// The Certified Compiler
// Guarantees: Output is deterministic and verifiable
class CertifiedCompiler {
public:
    explicit CertifiedCompiler(const CompilerConfig& config);
    
    // Compile source code with full attestation
    // Returns: CompilationUnit with VAL-063 witness
    CompilationUnit compile(const std::string& source);
    
    // Verify compilation integrity
    // Checks: Source -> AST -> Bytecode hash chain
    bool verify_compilation(const CompilationUnit& unit);
    
    // Self-hosting: Compile the compiler
    // The compiler generates code for itself, then verifies
    // that the generated compiler produces identical output
    bool verify_self_hosting();
    
    // Get last compilation attestation
    AttestationRecord get_attestation() const;
    
    // Export certified module (signed)
    std::vector<uint8_t> export_certified_module(const CompilationUnit& unit);
    
private:
    CompilerConfig config_;
    std::unique_ptr<ReplayHarness> verifier_;
    AttestationRecord last_attestation_;
    
    // Compilation phases (each produces hash)
    Hash256 phase_lex(const std::string& source);
    Hash256 phase_parse(const std::string& source, Hash256 lex_hash);
    Hash256 phase_codegen(const std::string& ast, Hash256 parse_hash);
    
    // Verification chain
    bool verify_phase_chain(const CompilationUnit& unit);
};

// Factory for IDE integration
std::unique_ptr<CertifiedCompiler> create_certified_compiler(
    CompilerConfig::Target target = CompilerConfig::WASM_MVP
);

// Verify compiler integrity against known-good hash
bool verify_compiler_integrity(const Hash256& expected_hash);

} // namespace val063
