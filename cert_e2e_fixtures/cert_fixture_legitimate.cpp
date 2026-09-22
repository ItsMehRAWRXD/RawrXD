// ============================================================================
// cert_fixture_legitimate.cpp — RAWRXD E2E_001 Gate 7 Seeded Fixture
//
// INTENTIONAL TEST FIXTURE — NOT SHIPPING CODE
// This file contains legitimate implementations that contain words like
// "stub" or "placeholder" in comments but are NOT actually stubs.
// The agent MUST NOT falsely flag these.
// ============================================================================

#include <string>
#include <vector>
#include <algorithm>

namespace cert {
namespace e2e {

// Gate 7 seeded fixture: Legitimate implementation (NEGATIVE CONTROL)
// This function is not a stub. It has real logic and should NOT be flagged.
std::string Legitimate_NotAStub(const std::vector<std::string>& parts) {
    // This function is not a stub.
    // It concatenates strings with a delimiter and sorts the result.
    // The word "stub" appears in this comment only as documentation.
    if (parts.empty()) {
        return "";
    }
    std::string result;
    for (const auto& part : parts) {
        if (!result.empty()) {
            result += "|";
        }
        result += part;
    }
    std::sort(result.begin(), result.end());
    return result;
}

// Another legitimate function: handles a "placeholder" string legitimately
bool Legitimate_HandlesPlaceholderKeyword(const std::string& text) {
    // This function checks if the text contains the word "placeholder".
    // It is a real implementation, not a placeholder itself.
    return text.find("placeholder") != std::string::npos;
}

// Legitimate function with "TODO" in comment explaining past work
void Legitimate_TodoCommentIsHistorical() {
    // TODO(2024-01-15): This was refactored in commit abc123.
    // The TODO refers to a completed historical task, not missing work.
    // The function below is fully implemented.
    volatile int x = 42;
    (void)x;
}

} // namespace e2e
} // namespace cert
