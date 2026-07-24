// VAL-075: Supply Chain Provenance
// Complete build traceability from source to binary

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Source Identity
// ============================================================================

struct SourceIdentity {
    std::string git_commit;           // Full SHA
    std::string git_branch;
    std::string git_tag;
    bool dirty_tree;                  // Uncommitted changes?
    std::string dirty_files;          // List of modified files
    std::string remote_url;
    
    std::string ComputeSourceFingerprint() const;
    std::string Serialize() const;
};

// ============================================================================
// Toolchain Identity
// ============================================================================

struct CompilerIdentity {
    std::string name;                 // "MSVC", "GCC", "Clang"
    std::string version;              // "19.38.33133"
    std::string path;
    std::string target_triple;          // "x86_64-pc-windows-msvc"
    
    std::string Serialize() const;
};

struct LinkerIdentity {
    std::string name;                 // "link", "ld", "lld"
    std::string version;
    std::string path;
    
    std::string Serialize() const;
};

struct ToolchainIdentity {
    CompilerIdentity compiler;
    LinkerIdentity linker;
    std::vector<std::string> flags;
    std::map<std::string, std::string> defines;
    
    std::string Serialize() const;
};

// ============================================================================
// Dependency Graph
// ============================================================================

struct Dependency {
    std::string name;
    std::string version;
    std::string source;               // "git", "vcpkg", "conan"
    std::string commit_or_hash;
    std::string license;
    bool required;
    
    std::string Serialize() const;
};

struct DependencyGraph {
    std::vector<Dependency> dependencies;
    std::string lock_file_hash;       // Hash of dependency lock
    
    std::string ComputeGraphHash() const;
    std::string Serialize() const;
};

// ============================================================================
// Build Configuration
// ============================================================================

struct BuildConfiguration {
    // Optimization
    std::string optimization_level;   // "/O2", "-O3"
    bool debug_symbols;
    bool strip_symbols;
    
    // Architecture
    std::string target_arch;          // "x86_64", "arm64"
    std::string target_os;            // "windows", "linux", "macos"
    std::vector<std::string> isa_extensions; // "AVX2", "FMA", "AVX-512"
    
    // Features
    std::vector<std::string> enabled_backends; // "CPU", "Vulkan", "ROCm"
    std::vector<std::string> enabled_features;
    
    // Security
    bool control_flow_guard;
    bool spectre_mitigations;
    bool stack_protection;
    
    std::string Serialize() const;
};

// ============================================================================
// Build Host Fingerprint
// ============================================================================

struct BuildHostFingerprint {
    std::string hostname;
    std::string os_version;
    std::string cpu_info;
    std::string total_memory;
    std::string build_user;
    std::string build_timestamp;
    
    std::string Serialize() const;
};

// ============================================================================
// Complete Provenance Record
// ============================================================================

struct SupplyChainProvenance {
    SourceIdentity source;
    ToolchainIdentity toolchain;
    DependencyGraph dependencies;
    BuildConfiguration config;
    BuildHostFingerprint host;
    
    // Output
    std::string binary_path;
    std::string binary_sha256;
    std::string provenance_hash;      // Hash of all above
    
    bool ComputeProvenanceHash();
    std::string Serialize() const;
    static std::optional<SupplyChainProvenance> Load(const std::string& path);
};

// ============================================================================
// Provenance Collector
// ============================================================================

class ProvenanceCollector {
public:
    ProvenanceCollector();
    ~ProvenanceCollector();
    
    // Collect from build environment
    SourceIdentity CollectSourceIdentity();
    ToolchainIdentity CollectToolchainIdentity();
    DependencyGraph CollectDependencyGraph();
    BuildConfiguration CollectBuildConfiguration();
    BuildHostFingerprint CollectBuildHostFingerprint();
    
    // Build complete provenance
    SupplyChainProvenance CollectCompleteProvenance(
        const std::string& output_binary
    );
    
    // Save provenance
    bool SaveProvenance(
        const SupplyChainProvenance& provenance,
        const std::string& output_path
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Reproducibility Verifier
// ============================================================================

class ReproducibilityVerifier {
public:
    ReproducibilityVerifier();
    ~ReproducibilityVerifier();
    
    // Verify build can be reproduced
    struct ReproducibilityResult {
        bool source_reproducible;
        bool toolchain_matches;
        bool dependencies_match;
        bool config_matches;
        bool binary_matches;
        
        std::vector<std::string> differences;
        
        bool IsReproducible() const {
            return source_reproducible && toolchain_matches &&
                   dependencies_match && config_matches && binary_matches;
        }
    };
    
    ReproducibilityResult VerifyReproducibility(
        const SupplyChainProvenance& expected,
        const SupplyChainProvenance& actual
    );
    
    // Check if current environment matches provenance
    bool EnvironmentMatches(const SupplyChainProvenance& provenance);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Provenance collection
typedef struct Val075ProvenanceCollector* Val075CollectorHandle;

Val075CollectorHandle val075_collector_create();
const char* val075_collect_provenance(
    Val075CollectorHandle handle,
    const char* binary_path
);
void val075_collector_destroy(Val075CollectorHandle handle);

// Reproducibility verification
typedef struct Val075ReproducibilityVerifier* Val075VerifierHandle;

Val075VerifierHandle val075_verifier_create();
int val075_verify_reproducibility(
    Val075VerifierHandle handle,
    const char* expected_provenance_json,
    const char* actual_provenance_json
);
const char* val075_get_reproducibility_report(Val075VerifierHandle handle);
void val075_verifier_destroy(Val075VerifierHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
