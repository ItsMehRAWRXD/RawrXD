// Deterministic, model-free extension policy acceptance tests.
// Compile: c++ -std=c++17 -Wall -Wextra -Werror -I~dev/rawrxd/src/core tools/ci/extension_policy_smoke.cpp -o extension_policy_smoke
#include "extension_manifest_policy.hpp"
#include "extension_entry_policy.hpp"
#include <filesystem>
#include <iostream>
#include <string>
namespace fs = std::filesystem;
static int failures = 0;
static void check(bool ok, const char* label) {
    if (!ok) { std::cerr << "FAIL " << label << '\n'; ++failures; }
    else std::cout << "PASS " << label << '\n';
}
int main() {
    using namespace rawrxd::extensions;
    check(validManifestIdentity("publisher", "extension", "1.2.3"), "valid manifest identity");
    check(validManifestIdentity("", "extension_2", "0.0.1"), "optional publisher");
    check(!validManifestIdentity("bad/publisher", "extension", "1.2.3"), "reject publisher separator");
    check(!validManifestIdentity("publisher", "../escape", "1.2.3"), "reject name traversal");
    check(!validManifestIdentity("publisher", "extension", "1.2"), "reject incomplete version");
    check(!validManifestIdentity("publisher", "extension", "1.2.3.4"), "reject extra version segment");
    check(!validManifestIdentity("publisher", "extension", "1.2.x"), "reject nonnumeric version");
    check(!validIdentifier(std::string(129, 'a')), "reject overlong identifier");
    check(!validVersion(std::string(65, '1')), "reject overlong version");
    const fs::path root = fs::temp_directory_path() / "rawrxd_extension_policy_fixture";
    const fs::path child = root / "plugin" / "main.js";
    check(entryWithinRoot(root, child), "accept nested entry");
    check(!entryWithinRoot(root, root), "reject root as entry");
    check(!entryWithinRoot(root, root / ".." / "outside.js"), "reject traversal");
    check(!entryWithinRoot(root, root.parent_path() / "rawrxd_extension_policy_fixture_evil" / "main.js"), "reject prefix sibling");
    check(!entryWithinRoot(fs::path("relative"), child), "reject relative root");
    check(!entryWithinRoot(root, fs::path("relative.js")), "reject relative entry");
    std::cout << "RESULT " << (failures ? "FAIL" : "PASS") << " failures=" << failures << '\n';
    return failures ? 1 : 0;
}
