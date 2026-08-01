#pragma once
#include "IBackendProvider.hpp"

class BareMetalDriver : public IBackendProvider {
public:
    bool InitializeEngine() override;
    bool ExecuteBuild(const std::string& target) override;
    AuditMetrics RunProjectAudit() override;
    std::string GetProviderName() const override;
};
