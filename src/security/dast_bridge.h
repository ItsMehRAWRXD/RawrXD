// =============================================================================
// dast_bridge.h — S5 DAST import (TOP50 S5), dependency-free.
// =============================================================================
// Imports external DAST reports (OWASP ZAP JSON, Burp Suite XML) into a
// normalized finding list that the IDE pushes into the Problems panel.
// =============================================================================
#pragma once
#include <string>
#include <vector>

namespace rawrxd::security {

struct DastFinding {
    std::string rule_id;    // plugin id / rule name
    std::string severity;   // high | medium | low | info
    std::string url;
    std::string evidence;
    std::string message;
};

class DastBridge {
public:
    // Detect format by content and parse. Returns false on unsupported input.
    bool Import(const std::string& path, std::vector<DastFinding>& out) const;

    static std::string ToJson(const std::vector<DastFinding>& findings);
};

}  // namespace rawrxd::security