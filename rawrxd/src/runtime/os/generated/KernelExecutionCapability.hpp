// ============================================================================
// KernelExecutionCapability.hpp — Generated capability (kernel)
// DO NOT edit the lifecycle contract — override phase methods in hand-written
// subclasses if domain-specific behavior is needed.
// ============================================================================
#pragma once
#include "../RuntimeCapability.hpp"

namespace rawrxd::kernel {

class KernelExecutionCapability final : public rawrxd::runtime::RuntimeCapability {
public:
    KernelExecutionCapability() = default;
    ~KernelExecutionCapability() override = default;

    rawrxd::runtime::CapabilityId id() const noexcept override;
    std::string_view name() const noexcept override;

    bool discover(rawrxd::runtime::CapabilityContext& ctx) override;
    bool admit(rawrxd::runtime::CapabilityContext& ctx) override;
    bool initialize(rawrxd::runtime::CapabilityContext& ctx) override;
    bool execute(rawrxd::runtime::CapabilityContext& ctx) override;
    bool observe(rawrxd::runtime::CapabilityContext& ctx) override;
    bool verify(rawrxd::runtime::CapabilityContext& ctx) override;
    bool commit(rawrxd::runtime::CapabilityContext& ctx) override;
    bool persist(rawrxd::runtime::CapabilityContext& ctx) override;
    bool recover(rawrxd::runtime::CapabilityContext& ctx) override;
    bool shutdown(rawrxd::runtime::CapabilityContext& ctx) override;
};

} // namespace rawrxd::kernel
