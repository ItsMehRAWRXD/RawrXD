// Headless contract for the actual extension manifest identity policy.
#include <iostream>
#include <string>
#include "../../~dev/rawrxd/src/core/extension_manifest_policy.hpp"
using namespace rawrxd::extensions;
int main() {
 const bool pass = validManifestIdentity("publisher", "extension_1", "1.2.3") &&
 validManifestIdentity("", "extension", "0.0.0") &&
 !validManifestIdentity("../escape", "extension", "1.2.3") &&
 !validManifestIdentity("publisher", "../escape", "1.2.3") &&
 !validManifestIdentity("publisher", "extension", "1.2") &&
 !validManifestIdentity("publisher", "extension", "1.2.3.4") &&
 !validManifestIdentity("publisher", "extension", "1..3") &&
 !validManifestIdentity("publisher", "extension", "1.2.x") &&
 !validIdentifier(std::string(129, 'a')) &&
 !validVersion(std::string(65, '1'));
 std::cout << (pass ? "PASS" : "FAIL") << " manifest identity policy\n";
 return pass ? 0 : 1;
}
