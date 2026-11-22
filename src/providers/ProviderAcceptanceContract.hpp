#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace RawrXD::Providers {

enum class Provider : uint8_t {
    Deep2,
    Ollama,
    ReapAutoFit,
    Cursor,
    GitHubCopilot,
    KiloFree,
    KiloPaid,
};

enum class Gate : uint8_t {
    OfficialAuthAndInterface,
    DynamicModelDiscovery,
    BillingClassification,
    Streaming,
    Cancellation,
    ToolCalls,
    QuotaExhaustion,
    QuotaResetRecovery,
    AuthorizedFallback,
    DpapiCredentials,
    ConcurrentIsolation,
    OfflineLocalInference,
    NoUnauthorizedBilling,
    LiveShaAcceptance,
};

struct ProviderAcceptanceContract {
    static constexpr const char* kSchema = "rawrxd.provider.acceptance.v1";
    static constexpr bool kNewDependencies = false;
    static constexpr bool kStubs = false;
    static constexpr bool kSilentPaidFallback = false;
    static constexpr bool kLocalInferenceIndependent = true;

    static constexpr std::array<Provider, 7> providers() {
        return {Provider::Deep2, Provider::Ollama, Provider::ReapAutoFit,
                Provider::Cursor, Provider::GitHubCopilot, Provider::KiloFree,
                Provider::KiloPaid};
    }

    static constexpr bool isBillable(Provider provider) {
        return provider == Provider::Cursor || provider == Provider::KiloPaid;
    }

    static constexpr bool requiresOfficialInterface(Provider provider) {
        return provider == Provider::Cursor ||
               provider == Provider::GitHubCopilot ||
               provider == Provider::KiloFree ||
               provider == Provider::KiloPaid;
    }

    static constexpr bool canRunOffline(Provider provider) {
        return provider == Provider::Deep2 || provider == Provider::Ollama ||
               provider == Provider::ReapAutoFit;
    }
};

} // namespace RawrXD::Providers
