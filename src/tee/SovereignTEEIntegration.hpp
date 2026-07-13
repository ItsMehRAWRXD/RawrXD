// Phase D.16 Batch 1/5: TEE Integration
// Trusted Execution Environment support (SGX, SEV, TrustZone)
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace TEE {

// Forward declarations
struct TEEContext;
struct EnclaveConfig;
struct TEEQuote;

// ============================================================================
// TEE Types
// ============================================================================

enum class TEEType {
    INTEL_SGX = 0,
    AMD_SEV = 1,
    ARM_TRUSTZONE = 2,
    AWS_NITRO = 3,
    AZURE_SECURE_ENCLAVE = 4,
    GOOGLE_CONFIDENTIAL = 5,
    SIMULATION = 6
};

enum class TEEState {
    UNINITIALIZED = 0,
    INITIALIZED = 1,
    ENCLAVE_CREATED = 2,
    ENCLAVE_RUNNING = 3,
    ENCLAVE_DESTROYED = 4,
    ERROR = 5
};

enum class TEEError {
    SUCCESS = 0,
    INVALID_PARAMETER = 1,
    OUT_OF_MEMORY = 2,
    ENCLAVE_LOST = 3,
    INVALID_STATE = 4,
    FEATURE_NOT_SUPPORTED = 5,
    ATTESTATION_FAILED = 6,
    SEALING_FAILED = 7,
    QUOTE_VERIFICATION_FAILED = 8
};

struct TEEVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    std::string build_date;
};

struct TEEInfo {
    TEEType type;
    TEEVersion version;
    bool is_simulation;
    bool has_epid;
    bool has_dcap;
    size_t max_enclave_size;
    size_t max_threads;
    std::vector<std::string> supported_features;
    std::map<std::string, std::any> platform_info;
};

struct TEEContext {
    TEEType type;
    TEEState state;
    void* handle;
    std::chrono::steady_clock::time_point created_at;
    std::map<std::string, std::any> metadata;
};

// ============================================================================
// Intel SGX Integration
// ============================================================================

class SGXIntegration {
public:
    struct Config {
        bool use_dcap = true;
        std::string pce_path;
        std::string qpl_path;
        std::string quote_provider_library;
        bool enable_launch_token = false;
    };
    
    struct EnclaveConfig {
        size_t stack_size = 0x10000;      // 64KB
        size_t heap_size = 0x100000;      // 1MB
        size_t tcs_num = 1;
        size_t tcs_max_num = 1;
        size_t tcs_min_pool = 1;
        uint64_t attributes = 0;
        uint64_t xfrm = 0;
        bool debug = false;
        bool mode_64bit = true;
    };
    
    struct LaunchToken {
        std::vector<uint8_t> data;
        bool updated;
    };
    
    explicit SGXIntegration(const Config& config);
    ~SGXIntegration();
    
    bool Initialize();
    void Shutdown();
    
    // Enclave lifecycle
    void* CreateEnclave(const std::string& enclave_path, 
                        const EnclaveConfig& config,
                        LaunchToken& token);
    bool DestroyEnclave(void* enclave_id);
    
    // Enclave operations
    bool EnterEnclave(void* enclave_id, int func_id, void* args);
    bool ECall(void* enclave_id, uint32_t func_id, void* args, size_t args_size);
    bool OCall(uint32_t func_id, void* args, size_t args_size);
    
    // Attestation
    std::vector<uint8_t> GenerateQuote(const std::vector<uint8_t>& report_data);
    bool VerifyQuote(const std::vector<uint8_t>& quote);
    
    // Sealing
    std::vector<uint8_t> SealData(const void* data, size_t size, 
                                   uint16_t key_policy = 0);
    std::vector<uint8_t> UnsealData(const std::vector<uint8_t>& sealed_data);
    
    // Platform services
    bool InitializePlatformServices();
    void ShutdownPlatformServices();
    
    // Info
    TEEInfo GetPlatformInfo() const;
    bool IsDCapAvailable() const;
    bool IsEPIDAvailable() const;
    
private:
    Config config_;
    void* sgx_context_;
    std::map<void*, EnclaveConfig> enclaves_;
    mutable std::mutex enclaves_mutex_;
    
    bool LoadQuoteProvider();
    bool InitializeDCAP();
    bool InitializeEPID();
};

// ============================================================================
// AMD SEV Integration
// ============================================================================

class SEVIntegration {
public:
    struct Config {
        std::string cert_chain_path;
        std::string pdh_path;
        bool use_snp = true;  // Use SEV-SNP if available
        bool require_snp = false;
    };
    
    struct VMConfig {
        size_t memory_size;
        uint32_t vcpu_count;
        uint32_t policy;
        bool debug;
        bool migrateable;
    };
    
    struct Measurement {
        std::vector<uint8_t> launch_digest;
        std::vector<uint8_t> measurement;
        uint32_t api_major;
        uint32_t api_minor;
        uint32_t build_id;
        std::vector<uint8_t> policy;
    };
    
    explicit SEVIntegration(const Config& config);
    ~SEVIntegration();
    
    bool Initialize();
    void Shutdown();
    
    // VM lifecycle
    bool LaunchVM(const VMConfig& config, void** vm_handle);
    bool AttestVM(void* vm_handle, Measurement& measurement);
    bool ActivateVM(void* vm_handle);
    bool ShutdownVM(void* vm_handle);
    
    // Memory management
    bool EncryptMemory(void* vm_handle, void* guest_phys_addr, size_t size);
    bool DecryptMemory(void* vm_handle, void* guest_phys_addr, size_t size);
    bool SetMemoryPrivate(void* vm_handle, void* guest_phys_addr, size_t size);
    bool SetMemoryShared(void* vm_handle, void* guest_phys_addr, size_t size);
    
    // SNP specific
    bool LaunchSNP(void* vm_handle, const std::vector<uint8_t>& guest_policy);
    std::vector<uint8_t> GetSNPReport(void* vm_handle);
    bool VerifySNPReport(const std::vector<uint8_t>& report);
    
    // Certificate management
    bool LoadPDH(const std::string& pdh_path);
    bool LoadCertChain(const std::string& cert_chain_path);
    bool RotatePDH();
    
    // Info
    TEEInfo GetPlatformInfo() const;
    bool IsSEVAvailable() const;
    bool IsSNPAvailable() const;
    
private:
    Config config_;
    void* sev_context_;
    std::map<void*, VMConfig> vms_;
    mutable std::mutex vms_mutex_;
    
    bool InitializeSEV();
    bool InitializeSEVSNP();
    bool ValidateCertChain();
};

// ============================================================================
// ARM TrustZone Integration
// ============================================================================

class TrustZoneIntegration {
public:
    struct Config {
        std::string tee_os_path;
        std::string trusted_app_dir;
        bool use_tee_supplicant = true;
    };
    
    struct TrustedAppConfig {
        std::string uuid;
        std::string path;
        uint32_t stack_size;
        uint32_t heap_size;
        std::vector<std::string> capabilities;
    };
    
    struct Session {
        uint32_t session_id;
        std::string app_uuid;
        void* context;
        std::chrono::steady_clock::time_point created_at;
    };
    
    explicit TrustZoneIntegration(const Config& config);
    ~TrustZoneIntegration();
    
    bool Initialize();
    void Shutdown();
    
    // TEE Context
    bool InitializeContext();
    void FinalizeContext();
    
    // Trusted Application lifecycle
    bool LoadTrustedApp(const TrustedAppConfig& config);
    bool UnloadTrustedApp(const std::string& uuid);
    Session OpenSession(const std::string& uuid);
    bool CloseSession(const Session& session);
    
    // Invocations
    bool InvokeCommand(const Session& session, uint32_t command_id,
                       std::vector<uint8_t>& params);
    bool InvokeCommandWithMemory(const Session& session, uint32_t command_id,
                                  void* buffer, size_t size);
    
    // Shared memory
    void* AllocateSharedMemory(size_t size);
    void FreeSharedMemory(void* buffer);
    bool RegisterSharedMemory(const Session& session, void* buffer, size_t size);
    bool UnregisterSharedMemory(const Session& session, void* buffer);
    
    // Info
    TEEInfo GetPlatformInfo() const;
    std::vector<std::string> GetLoadedApps() const;
    
private:
    Config config_;
    void* tee_context_;
    std::map<std::string, TrustedAppConfig> loaded_apps_;
    std::map<uint32_t, Session> sessions_;
    mutable std::mutex apps_mutex_;
    mutable std::mutex sessions_mutex_;
    
    bool InitializeTEESupplicant();
    void ShutdownTEESupplicant();
};

// ============================================================================
// Cloud TEE Integration
// ============================================================================

class CloudTEEIntegration {
public:
    struct Config {
        std::string provider;  // aws, azure, gcp
        std::string region;
        std::string credentials_path;
        bool use_imds = true;
    };
    
    struct NitroEnclaveConfig {
        size_t memory_mib;
        int vcpu_count;
        std::string enclave_cid;
        std::vector<std::string> subnets;
        std::vector<std::string> security_groups;
    };
    
    struct AttestationDoc {
        std::vector<uint8_t> document;
        std::vector<uint8_t> signature;
        std::vector<uint8_t> certificate;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    explicit CloudTEEIntegration(const Config& config);
    ~CloudTEEIntegration();
    
    bool Initialize();
    void Shutdown();
    
    // AWS Nitro Enclaves
    bool CreateNitroEnclave(const NitroEnclaveConfig& config, std::string& enclave_id);
    bool TerminateNitroEnclave(const std::string& enclave_id);
    bool SendToEnclave(const std::string& enclave_id, const std::vector<uint8_t>& data);
    std::vector<uint8_t> ReceiveFromEnclave(const std::string& enclave_id);
    AttestationDoc GetNitroAttestation(const std::string& enclave_id);
    bool VerifyNitroAttestation(const AttestationDoc& doc);
    
    // Azure Confidential Computing
    bool InitializeAzureCC();
    std::vector<uint8_t> GetAzureQuote();
    bool VerifyAzureQuote(const std::vector<uint8_t>& quote);
    
    // Google Confidential VMs
    bool InitializeGoogleConfidential();
    std::vector<uint8_t> GetGoogleAttestation();
    bool VerifyGoogleAttestation(const std::vector<uint8_t>& attestation);
    
    // Info
    TEEInfo GetPlatformInfo() const;
    bool IsCloudTEEAvailable() const;
    
private:
    Config config_;
    void* cloud_context_;
    std::map<std::string, NitroEnclaveConfig> nitro_enclaves_;
    mutable std::mutex enclaves_mutex_;
    
    bool InitializeAWS();
    bool InitializeAzure();
    bool InitializeGCP();
};

// ============================================================================
// TEE Abstraction Layer
// ============================================================================

class TEEAbstractionLayer {
public:
    struct Config {
        TEEType preferred_tee = TEEType::INTEL_SGX;
        bool auto_detect = true;
        bool fallback_to_simulation = false;
    };
    
    struct EnclaveHandle {
        TEEType type;
        void* native_handle;
        std::string enclave_id;
        size_t memory_size;
        TEEState state;
    };
    
    explicit TEEAbstractionLayer(const Config& config);
    ~TEEAbstractionLayer();
    
    bool Initialize();
    void Shutdown();
    
    // TEE detection
    TEEType DetectAvailableTEE();
    std::vector<TEEType> GetAvailableTEEs();
    bool IsTEEAvailable(TEEType type);
    
    // Unified enclave API
    EnclaveHandle CreateEnclave(const std::string& enclave_path,
                                 size_t memory_size);
    bool DestroyEnclave(const EnclaveHandle& handle);
    bool EnterEnclave(const EnclaveHandle& handle, uint32_t func_id, void* args);
    
    // Unified attestation
    std::vector<uint8_t> GenerateAttestation(const EnclaveHandle& handle,
                                             const std::vector<uint8_t>& user_data);
    bool VerifyAttestation(const std::vector<uint8_t>& attestation);
    
    // Unified sealing
    std::vector<uint8_t> SealData(const EnclaveHandle& handle,
                                 const std::vector<uint8_t>& data);
    std::vector<uint8_t> UnsealData(const EnclaveHandle& handle,
                                   const std::vector<uint8_t>& sealed_data);
    
    // Info
    TEEInfo GetTEEInfo(TEEType type) const;
    TEEInfo GetCurrentTEEInfo() const;
    
private:
    Config config_;
    TEEType active_tee_;
    
    std::unique_ptr<SGXIntegration> sgx_;
    std::unique_ptr<SEVIntegration> sev_;
    std::unique_ptr<TrustZoneIntegration> trustzone_;
    std::unique_ptr<CloudTEEIntegration> cloud_tee_;
    
    std::map<std::string, EnclaveHandle> enclaves_;
    mutable std::mutex enclaves_mutex_;
};

// ============================================================================
// TEE Integration Runtime
// ============================================================================

class TEEIntegrationRuntime {
public:
    struct Config {
        TEEAbstractionLayer::Config abstraction;
        SGXIntegration::Config sgx;
        SEVIntegration::Config sev;
        TrustZoneIntegration::Config trustzone;
        CloudTEEIntegration::Config cloud;
    };
    
    explicit TEEIntegrationRuntime(const Config& config);
    ~TEEIntegrationRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    TEEAbstractionLayer* GetAbstractionLayer();
    SGXIntegration* GetSGX();
    SEVIntegration* GetSEV();
    TrustZoneIntegration* GetTrustZone();
    CloudTEEIntegration* GetCloudTEE();
    
    // High-level API
    TEEType GetActiveTEE() const;
    bool IsTEEAvailable() const;
    
    std::string CreateSecureEnclave(const std::string& enclave_path,
                                     size_t memory_size);
    bool DestroySecureEnclave(const std::string& enclave_id);
    
    std::vector<uint8_t> AttestEnclave(const std::string& enclave_id,
                                      const std::vector<uint8_t>& user_data);
    bool VerifyEnclaveAttestation(const std::vector<uint8_t>& attestation);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<TEEAbstractionLayer> abstraction_layer_;
    std::unique_ptr<SGXIntegration> sgx_;
    std::unique_ptr<SEVIntegration> sev_;
    std::unique_ptr<TrustZoneIntegration> trustzone_;
    std::unique_ptr<CloudTEEIntegration> cloud_tee_;
};

} // namespace TEE
} // namespace Sovereign
