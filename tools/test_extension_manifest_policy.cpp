#include "../~dev/rawrxd/src/core/extension_manifest_policy.hpp"
#include <array>
#include <iostream>
struct Case { const char* name; const char* publisher; const char* id; const char* version; bool valid; };
int main() {
    constexpr std::array<Case, 15> cases = {{
        {"normal", "acme", "tool", "1.2.3", true},
        {"no_publisher", "", "tool", "0.0.1", true},
        {"underscores", "my_org", "tool_2", "10.20.30", true},
        {"hyphens", "my-org", "tool-2", "1.0.0", true},
        {"empty_name", "acme", "", "1.2.3", false},
        {"empty_version", "acme", "tool", "", false},
        {"missing_segment", "acme", "tool", "1.2", false},
        {"extra_segment", "acme", "tool", "1.2.3.4", false},
        {"trailing_dot", "acme", "tool", "1.2.", false},
        {"negative_version", "acme", "tool", "-1.2.3", false},
        {"shell_name", "acme", "tool;echo", "1.2.3", false},
        {"path_name", "acme", "../tool", "1.2.3", false},
        {"space_publisher", "my org", "tool", "1.2.3", false},
        {"unicode_id", "acme", "t\xC3\xB6ol", "1.2.3", false},
        {"long_version", "acme", "tool", "11111111111111111111111111111111111111111111111111111111111111111.2.3", false}
    }};
    int passed=0;
    for (const auto& c : cases) {
        const bool actual=rawrxd::extensions::validManifestIdentity(c.publisher,c.id,c.version);
        const bool ok=actual==c.valid;
        passed+=ok;
        std::cout<<c.name<<"="<<(ok?"PASS":"FAIL")<<"\n";
    }
    std::cout<<"MANIFEST_IDENTITY="<<passed<<"/"<<cases.size()<<"\n";
    return passed==static_cast<int>(cases.size())?0:1;
}
