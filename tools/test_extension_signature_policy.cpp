#include "../~dev/rawrxd/src/core/extension_signature_policy.hpp"
#include <array>
#include <iostream>
struct Case {const char* name; bool signedOk; const char* flag; bool expected;};
int main() {
    constexpr std::array<Case,15> cases = {{
        {"signed_default",true,"",true},
        {"signed_1",true,"1",true},
        {"signed_0",true,"0",true},
        {"signed_unknown",true,"anything",true},
        {"unsigned_default",false,"",false},
        {"unsigned_0",false,"0",false},
        {"unsigned_1",false,"1",true},
        {"unsigned_Y",false,"Y",true},
        {"unsigned_y",false,"y",true},
        {"unsigned_yes",false,"yes",false},
        {"unsigned_TRUE",false,"TRUE",false},
        {"unsigned_2",false,"2",false},
        {"unsigned_space",false," 1",false},
        {"unsigned_trailing",false,"1 ",false},
        {"unsigned_newline",false,"1\\n",false}
    }};
    int passed=0;
    for (const auto& c : cases) {
        bool got=rawrxd::extensions::mayInstallVSIX(c.signedOk,c.flag);
        bool ok=got==c.expected;
        passed+=ok;
        std::cout<<c.name<<"="<<(ok?"PASS":"FAIL")<<"\\n";
    }
    std::cout<<"VSIX_SIGNATURE_POLICY="<<passed<<"/"<<cases.size()<<"\\n";
    return passed==static_cast<int>(cases.size())?0:1;
}
