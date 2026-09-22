#pragma once
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <cstring>

namespace RawrXD::License {

enum class LicenseTierV2 : uint32_t { Community = 0, Professional = 1, Enterprise = 2, Sovereign = 3 };

struct LicenseResult {
    bool success = false;
    char message[256] = {};
    uint32_t code = 0;
    static LicenseResult ok(const char* msg) { LicenseResult r; r.success = true; strncpy_s(r.message, msg, sizeof(r.message)-1); return r; }
    static LicenseResult error(const char* msg, uint32_t c=0) { LicenseResult r; r.success = false; strncpy_s(r.message, msg, sizeof(r.message)-1); r.code = c; return r; }
};

struct FeatureMask { uint64_t lo = 0; uint64_t hi = 0; };
struct TierLimits {
    struct Limits { uint32_t maxModelGB = 0; uint32_t maxContextTokens = 0; };
    static Limits forTier(LicenseTierV2 t) { Limits l; if(t>=LicenseTierV2::Sovereign){l.maxModelGB=999;l.maxContextTokens=999;} return l; }
};
struct TierPresets {
    static FeatureMask forTier(LicenseTierV2 t) { FeatureMask m; if(t>=LicenseTierV2::Sovereign){m.lo=~0ULL;m.hi=~0ULL;} return m; }
};

struct LicenseKeyV2 {
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t tier = 0;
    uint32_t issueDate = 0;
    uint32_t expiryDate = 0;
    uint64_t hwid = 0;
    FeatureMask features;
    uint32_t maxModelGB = 0;
    uint32_t maxContextTokens = 0;
    uint8_t signature[32] = {};
    uint8_t padding[32] = {};
};

enum class FeatureID : uint32_t {
    None = 0,
    // Community
    BasicGGUFLoading, Q4Quantization, CPUInference, BasicChatUI, ConfigFileSupport, SingleModelSession,
    // Professional
    MemoryHotpatching, ByteLevelHotpatching, ServerHotpatching, UnifiedHotpatchManager, Q5Q8F16Quantization,
    MultiModelLoading, CUDABackend, AdvancedSettingsPanel, PromptTemplates, TokenStreaming, InferenceStatistics,
    KVCacheManagement, ModelComparison, BatchProcessing, CustomStopSequences, GrammarConstrainedGen,
    LoRAAdapterSupport, ResponseCaching, PromptLibrary, ExportImportSessions, HIPBackend,
    // Enterprise
    DualEngine800B, AgenticFailureDetect, AgenticPuppeteer, AgenticSelfCorrection, ProxyHotpatching,
    ServerSidePatching, SchematicStudioIDE, WiringOracleDebug, FlashAttention, SpeculativeDecoding,
    ModelSharding, TensorParallel, PipelineParallel, ContinuousBatching, GPTQQuantization, AWQQuantization,
    CustomQuantSchemes, MultiGPULoadBalance, DynamicBatchSizing, PriorityQueuing, RateLimitingEngine,
    AuditLogging, APIKeyManagement, ModelSigningVerify, RBAC, ObservabilityDashboard, AVX512Acceleration,
    RawrTunerIDE,
    // Sovereign
    AirGappedDeploy, HSMIntegration, FIPS140_2Compliance, CustomSecurityPolicies, SovereignKeyMgmt,
    ClassifiedNetwork, ImmutableAuditLogs, KubernetesSupport, TamperDetection, SecureBootChain,
    COUNT
};

struct FeatureDefV2 {
    char name[64] = {};
    LicenseTierV2 minTier = LicenseTierV2::Community;
    bool implemented = false;
    bool wiredToUI = false;
    bool tested = false;
};

struct LicenseAuditEntry {
    uint64_t timestamp = 0;
    FeatureID feature = FeatureID::None;
    bool granted = false;
    const char* caller = nullptr;
    const char* detail = nullptr;
};

constexpr size_t MAX_AUDIT_ENTRIES = 256;
constexpr size_t MAX_CALLBACKS = 8;
constexpr uint32_t TOTAL_FEATURES = 128;
extern FeatureDefV2 g_FeatureManifest[TOTAL_FEATURES];

using LicenseChangeCallback = void(*)();

class EnterpriseLicenseV2 {
    mutable std::mutex m_mutex;
    bool m_initialized = false;
    uint64_t m_hwid = 0;
    LicenseTierV2 m_tier = LicenseTierV2::Community;
    LicenseKeyV2 m_currentKey;
    LicenseAuditEntry m_auditTrail[MAX_AUDIT_ENTRIES];
    size_t m_auditHead = 0;
    size_t m_auditCount = 0;
    LicenseChangeCallback m_callbacks[MAX_CALLBACKS] = {};
    size_t m_callbackCount = 0;

public:
    static EnterpriseLicenseV2& Instance();
    LicenseResult initialize();
    void shutdown();
    uint64_t getHardwareID() const;
    bool isFeatureEnabled(FeatureID id) const;
    bool isFeatureLicensed(FeatureID id) const;
    bool isFeatureImplemented(FeatureID id) const;
    bool gate(FeatureID id, const char* caller);
    void recordAudit(FeatureID id, bool granted, const char* caller, const char* detail);
    LicenseTierV2 currentTier() const;
    const TierLimits::Limits& currentLimits() const;
    FeatureMask currentMask() const;
    uint32_t enabledFeatureCount() const;
    LicenseResult loadKeyFromFile(const char* path);
    LicenseResult loadKeyFromRegistry();
    LicenseResult saveKeyToRegistry(const LicenseKeyV2& key);
    LicenseResult loadKeyFromMemory(const void* data, size_t size);
    LicenseResult validateKey(const LicenseKeyV2& key) const;
    LicenseResult requestAzureADLicense(const char* tenantId, const char* clientId);
    bool verifySignature(const LicenseKeyV2& key) const;
    void signKey(LicenseKeyV2& key, const char* secret) const;
    LicenseResult createKey(LicenseTierV2 tier, uint32_t durationDays, const char* signingSecret, LicenseKeyV2* outKey) const;
    size_t getAuditEntryCount() const;
    const LicenseAuditEntry* getAuditEntries() const;
    void clearAuditTrail();
    const FeatureDefV2& getFeatureDef(FeatureID id) const;
    uint32_t countByTier(LicenseTierV2 tier) const;
    uint32_t countImplemented() const;
    uint32_t countWiredToUI() const;
    uint32_t countTested() const;
    void onLicenseChange(LicenseChangeCallback cb);
    LicenseResult devUnlock();
    void getHardwareIDHex(char* buf, size_t bufLen) const;
};

} // namespace RawrXD::License
