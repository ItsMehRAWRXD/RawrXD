#include "providers/ProviderAcceptanceContract.hpp"

#include <cassert>
#include <iostream>

int main() {
    using namespace RawrXD::Providers;
    const auto providers = ProviderAcceptanceContract::providers();
    assert(providers.size() == 7);
    assert(ProviderAcceptanceContract::requiresOfficialInterface(Provider::GitHubCopilot));
    assert(ProviderAcceptanceContract::isBillable(Provider::KiloPaid));
    assert(!ProviderAcceptanceContract::isBillable(Provider::KiloFree));
    assert(ProviderAcceptanceContract::canRunOffline(Provider::Deep2));
    assert(!ProviderAcceptanceContract::canRunOffline(Provider::GitHubCopilot));
    assert(!ProviderAcceptanceContract::kSilentPaidFallback);
    assert(!ProviderAcceptanceContract::kNewDependencies);
    assert(!ProviderAcceptanceContract::kStubs);
    std::cout << "provider_acceptance_contract: PASS\n";
}
