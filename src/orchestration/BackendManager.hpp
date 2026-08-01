#pragma once
#include "IBackendProvider.hpp"
#include "BackendConfig.hpp"
#include "BackendCapability.hpp"
#include "BackendFactory.hpp"
#include <memory>
#include <string>
#include <vector>

// Forward declarations from security layer
struct CapabilityToken;
class SandboxPolicy;
class AuditSigner;

class BackendManager {
private:
    std::unique_ptr<IBackendProvider> m_activeBackend;
    BackendType m_activeType;
    int m_timeoutMs;
    bool m_allowScripts;

    // Capability negotiation
    BackendCapabilityMatrix m_capabilityMatrix;
    std::string m_activeBackendName;

    // Security layer
    CapabilityToken* m_activeToken;
    SandboxPolicy*   m_sandboxPolicy;
    AuditSigner*     m_auditSigner;

    void SetBackendProviderInstance(BackendType type);
    bool CheckCapability(BackendFeature required);
    bool CheckSecurity(const std::string& operation, BackendFeature requiredPerm);

public:
    BackendManager();
    ~BackendManager();

    bool Initialize();
    bool SelectBackend(BackendType type);
    IBackendProvider* Active();
    
    bool ExecuteBuild(const std::string& target);
    AuditMetrics RunAudit();
    
    // Identity
    std::string GetActiveBackendName() const;
    BackendType GetActiveBackendType() const;

    // Capability negotiation
    BackendFeature GetActiveCapabilities() const;
    std::string NegotiateBackend(BackendFeature required);
    std::vector<std::string> ListCapableBackends(BackendFeature required) const;

    // Security
    bool IsBuildAllowed();
    bool IsGpuAllowed();
    bool IsNetworkAllowed();

    // Demo harness integration
    bool RunSovereignDemo();

    // Benchmark run capture
    bool CaptureBenchmarkRun(const std::string& label);

    void OnBackendEventSwapped(int receivedModeValue);
};
