// VAL-080: Cross-Platform Verification
// Multi-platform verification matrix

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>

namespace RawrXD {
namespace Certification {

// ============================================================================
// Platform Definitions
// ============================================================================

enum class PlatformOS {
    Windows,
    Linux,
    macOS,
    Unknown
};

enum class PlatformArch {
    x86_64,
    ARM64,
    x86,
    Unknown
};

struct PlatformIdentity {
    PlatformOS os;
    PlatformArch arch;
    std::string os_version;
    std::string distro;           // For Linux
    
    std::string ToString() const;
    bool IsSupported() const;
    bool operator==(const PlatformIdentity& other) const;
};

// ============================================================================
// Verification Matrix
// ============================================================================

struct PlatformVerificationResult {
    PlatformIdentity platform;
    bool verified;
    std::string evidence_bundle_path;
    std::string error_message;
    uint64_t verification_time_ms;
    
    bool IsSuccess() const { return verified; }
    std::string Serialize() const;
};

class CrossPlatformVerificationMatrix {
public:
    CrossPlatformVerificationMatrix();
    ~CrossPlatformVerificationMatrix();
    
    // Define supported platforms
    void AddSupportedPlatform(const PlatformIdentity& platform);
    std::vector<PlatformIdentity> GetSupportedPlatforms() const;
    
    // Run verification on all platforms
    std::vector<PlatformVerificationResult> VerifyAllPlatforms(
        const std::string& evidence_bundle
    );
    
    // Verify specific platform
    PlatformVerificationResult VerifyPlatform(
        const PlatformIdentity& platform,
        const std::string& evidence_bundle
    );
    
    // Container verification
    PlatformVerificationResult VerifyInContainer(
        const std::string& container_image,
        const std::string& evidence_bundle
    );
    
    // Air-gapped verification
    PlatformVerificationResult VerifyAirGapped(
        const std::string& evidence_bundle,
        const std::string& offline_key_path
    );
    
    // Get matrix report
    struct MatrixReport {
        int total_platforms;
        int verified_count;
        int failed_count;
        bool all_platforms_passed;
        std::vector<PlatformVerificationResult> results;
    };
    MatrixReport GetMatrixReport() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Platform-Specific Verifiers
// ============================================================================

class WindowsVerifier {
public:
    static PlatformVerificationResult Verify(
        const std::string& evidence_bundle
    );
    static bool IsAvailable();
};

class LinuxVerifier {
public:
    static PlatformVerificationResult Verify(
        const std::string& evidence_bundle
    );
    static bool IsAvailable();
    static std::vector<std::string> GetSupportedDistros();
};

class macOSVerifier {
public:
    static PlatformVerificationResult Verify(
        const std::string& evidence_bundle
    );
    static bool IsAvailable();
};

// ============================================================================
// Container Verification
// ============================================================================

struct ContainerConfig {
    std::string image;
    std::string tag;
    std::vector<std::string> volumes;
    std::vector<std::string> env_vars;
    bool network_disabled;
    uint64_t memory_limit_mb;
    
    std::string Serialize() const;
};

class ContainerVerifier {
public:
    ContainerVerifier();
    ~ContainerVerifier();
    
    // Verify in container
    PlatformVerificationResult VerifyInContainer(
        const ContainerConfig& config,
        const std::string& evidence_bundle
    );
    
    // Supported container runtimes
    enum class Runtime {
        Docker,
        Podman,
        containerd
    };
    std::vector<Runtime> GetAvailableRuntimes() const;
    
    // Build verification image
    bool BuildVerificationImage(
        const std::string& dockerfile_path,
        const std::string& image_name
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Air-Gapped Verification
// ============================================================================

class AirGappedVerifier {
public:
    AirGappedVerifier();
    ~AirGappedVerifier();
    
    // Verify without network access
    PlatformVerificationResult VerifyOffline(
        const std::string& evidence_bundle,
        const std::string& trusted_keys_path
    );
    
    // Prepare offline bundle
    bool PrepareOfflineBundle(
        const std::string& evidence_bundle,
        const std::string& output_path
    );
    
    // Verify offline bundle integrity
    bool VerifyOfflineBundleIntegrity(
        const std::string& offline_bundle
    );

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Cross-Platform Test Suite
// ============================================================================

struct CrossPlatformTestResult {
    std::string test_name;
    PlatformIdentity platform;
    bool passed;
    std::string error_message;
    uint64_t execution_time_ms;
};

class CrossPlatformTestSuite {
public:
    CrossPlatformTestSuite();
    ~CrossPlatformTestSuite();
    
    // Run all platform tests
    std::vector<CrossPlatformTestResult> RunAllTests();
    
    // Individual platform tests
    CrossPlatformTestResult TestWindowsX64();
    CrossPlatformTestResult TestLinuxX64();
    CrossPlatformTestResult TestLinuxARM64();
    CrossPlatformTestResult TestmacOS();
    CrossPlatformTestResult TestContainerized();
    CrossPlatformTestResult TestAirGapped();
    
    // Get summary
    struct Summary {
        int total_tests;
        int passed;
        int failed;
        bool all_platforms_covered;
    };
    Summary GetSummary() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// C API
// ============================================================================

extern "C" {

// Platform identity
typedef struct Val080PlatformIdentity* Val080PlatformHandle;

Val080PlatformHandle val080_platform_create(int os, int arch);
const char* val080_platform_to_string(Val080PlatformHandle handle);
int val080_platform_is_supported(Val080PlatformHandle handle);
void val080_platform_destroy(Val080PlatformHandle handle);

// Cross-platform verification
typedef struct Val080CrossPlatformVerifier* Val080VerifierHandle;

Val080VerifierHandle val080_verifier_create();
int val080_add_supported_platform(Val080VerifierHandle handle, int os, int arch);
int val080_verify_all_platforms(Val080VerifierHandle handle, const char* evidence_bundle);
const char* val080_get_matrix_report(Val080VerifierHandle handle);
void val080_verifier_destroy(Val080VerifierHandle handle);

// Container verification
typedef struct Val080ContainerVerifier* Val080ContainerHandle;

Val080ContainerHandle val080_container_create();
int val080_verify_in_container(
    Val080ContainerHandle handle,
    const char* image,
    const char* evidence_bundle
);
void val080_container_destroy(Val080ContainerHandle handle);

} // extern "C"

} // namespace Certification
} // namespace RawrXD
