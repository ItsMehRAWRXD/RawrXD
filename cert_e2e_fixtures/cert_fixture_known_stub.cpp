// ============================================================================
// cert_fixture_known_stub.cpp — RAWRXD E2E_001 Gate 7 Seeded Fixture
//
// INTENTIONAL TEST FIXTURE — NOT SHIPPING CODE
// This file contains a deliberately seeded known stub for accuracy testing.
// The agent MUST flag this as a stub.
// ============================================================================

#include <string>

namespace cert {
namespace e2e {

// Gate 7 seeded fixture: KnownStub
// Expected classification: Stub implementation
// Expected severity: Certification fixture (not shipping)
void KnownStub() {
    // TODO: certification fixture
    // This function body is intentionally empty and marked with TODO.
    // A real agent should classify this as a stub/placeholder.
}

// Another known stub variant with explicit stub marker
bool KnownStub_ReturnsTrue() {
    // Stub: returns constant success without real work
    return true;
}

// Known stub with placeholder comment
int KnownStub_Placeholder() {
    /* placeholder — real implementation pending */
    return 0;
}

} // namespace e2e
} // namespace cert
