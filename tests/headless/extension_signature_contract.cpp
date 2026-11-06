// Headless acceptance contract for the production unsigned VSIX policy.
#include <iostream>
#include "../../~dev/rawrxd/src/core/extension_signature_policy.hpp"
int main() {
 using rawrxd::extensions::allowUnsignedVSIX;
 using rawrxd::extensions::mayInstallVSIX;
 const bool pass = !allowUnsignedVSIX("") && !allowUnsignedVSIX("0") &&
     !allowUnsignedVSIX("true") && !allowUnsignedVSIX("yes") &&
     !allowUnsignedVSIX(" 1") && !allowUnsignedVSIX("1 ") &&
     allowUnsignedVSIX("1") && allowUnsignedVSIX("Y") && allowUnsignedVSIX("y") &&
     !mayInstallVSIX(false, "") && !mayInstallVSIX(false, "0") &&
     mayInstallVSIX(false, "1") && mayInstallVSIX(true, "");
 std::cout << (pass ? "PASS" : "FAIL") << " VSIX signature policy\n";
 return pass ? 0 : 1;
}
