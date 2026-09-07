// LOCAL_AGENT_AUDIT_CANARY_7F31
// Seeded defect for LOCAL_AGENT_AUDIT_001 — fixture only, not production.
// A competent local-model audit of THIS file must mention the canary id
// and/or the divide-by-zero hazard below.

#include <cstdio>

namespace local_agent_audit_fixture {

// Intentionally defective: division by zero at runtime if called.
static int definitely_wrong_for_cert(int zero) {
    return 10 / zero; // LOCAL_AGENT_AUDIT_CANARY_7F31
}

} // namespace local_agent_audit_fixture

int main() {
    std::printf("fixture_only canary=LOCAL_AGENT_AUDIT_CANARY_7F31\n");
    // Do not call definitely_wrong_for_cert — presence is enough for the prompt.
    return 0;
}
