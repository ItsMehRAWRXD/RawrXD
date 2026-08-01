#pragma once
#include <string>

struct AuditMetrics {
    int totalIssues;
    int criticalCount;
    int highCount;
    int mediumCount;
    int lowCount;
};

class IBackendProvider {
public:
    virtual ~IBackendProvider() = default;
    virtual bool InitializeEngine() = 0;
    virtual bool ExecuteBuild(const std::string& target) = 0;
    virtual AuditMetrics RunProjectAudit() = 0;
    virtual std::string GetProviderName() const = 0;
};
