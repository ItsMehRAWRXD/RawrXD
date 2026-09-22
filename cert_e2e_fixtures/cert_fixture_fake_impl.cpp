// ============================================================================
// cert_fixture_fake_impl.cpp — RAWRXD E2E_001 Gate 7 Seeded Fixture
//
// INTENTIONAL TEST FIXTURE — NOT SHIPPING CODE
// This file contains deliberately seeded fake implementations for accuracy
// testing. The agent MUST flag these as fake/placeholder implementations.
// ============================================================================

#include <string>
#include <vector>

namespace cert {
namespace e2e {

// Gate 7 seeded fixture: FakeImpl
// Expected classification: Fake implementation / placeholder
// Expected severity: Certification fixture (not shipping)
bool FakeImpl() {
    return true; // RAWRXD_CERT_PLACEHOLDER
}

// Fake implementation that claims to validate but does nothing
bool FakeImpl_ValidateInput(const std::string& /*input*/) {
    // RAWRXD_CERT_PLACEHOLDER — no actual validation performed
    return true;
}

// Fake implementation with disabled production path
void FakeImpl_DisabledProductionPath() {
    // The real implementation is disabled below:
    // #ifdef REAL_IMPLEMENTATION
    //   ...real code...
    // #else
    //   /* disabled for now */
    // #endif
    // RAWRXD_CERT_PLACEHOLDER
}

// Another fake: returns hardcoded data
std::vector<int> FakeImpl_FetchData() {
    // RAWRXD_CERT_PLACEHOLDER — returns synthetic data
    return {1, 2, 3};
}

} // namespace e2e
} // namespace cert
