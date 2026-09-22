// ============================================================================
// cert_fixture_unimplemented_handler.cpp — RAWRXD E2E_001 Gate 7 Seeded Fixture
//
// INTENTIONAL TEST FIXTURE — NOT SHIPPING CODE
// This file contains unimplemented handlers for accuracy testing.
// ============================================================================

namespace cert {
namespace e2e {

// Unimplemented handler: declared but body is missing or minimal
void UnimplementedHandler_ProcessEvent(int /*eventId*/) {
    // FIXME: unimplemented handler — needs real event processing
}

// Disabled production path: the real code is behind an #if 0
bool UnimplementedHandler_AuthenticateUser(const char* /*user*/) {
#if 0
    // Real implementation:
    // 1. Hash the user token
    // 2. Verify against database
    // 3. Return true if valid
    return VerifyToken(user);
#endif
    // Disabled production code — falls through to false
    return false;
}

} // namespace e2e
} // namespace cert
