// Standalone real C++ acceptance gates for extension security policies.
// No model, QuickJS, Ollama, or GUI required.
#include "../../~dev/rawrxd/src/core/extension_manifest_policy.hpp"
#include "../../~dev/rawrxd/src/core/extension_entry_policy.hpp"
#include "../../~dev/rawrxd/src/core/extension_signature_policy.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <chrono>
#include <string>
namespace fs = std::filesystem;
static int assertions = 0;
static void require(bool ok, const char* name) {
    ++assertions;
    if (!ok) { std::cerr << "FAIL: " << name << '\n'; std::exit(1); }
}
int main() {
    using namespace rawrxd::extensions;
    require(validIdentifier("publisher_123"), "identifier valid");
    require(!validIdentifier(""), "identifier empty");
    require(!validIdentifier("../escape"), "identifier traversal");
    require(!validIdentifier("with space"), "identifier whitespace");
    require(!validIdentifier(std::string(129, 'a')), "identifier length");
    require(validVersion("1.2.3"), "version valid");
    require(validVersion("0.0.0"), "zero version valid");
    require(!validVersion("1.2.3."), "version trailing dot");
    require(!validVersion("1.2.-3"), "version negative segment");
    require(!validVersion("1.2"), "version short");
    require(!validVersion("1.2.3.4"), "version long");
    require(!validVersion("1..3"), "version empty segment");
    require(!validVersion("1.2.x"), "version alphabetic");
    require(validManifestIdentity("vendor", "plugin", "0.0.1"), "manifest valid");
    require(!validManifestIdentity("vendor", "../plugin", "0.0.1"), "manifest traversal");
    require(!allowUnsignedVSIX("true"), "unsigned default deny");
    require(!allowUnsignedVSIX("0"), "unsigned explicit false");
    require(allowUnsignedVSIX("1"), "unsigned explicit opt in");
    require(mayInstallVSIX(true, ""), "verified signed VSIX");
    require(!mayInstallVSIX(false, ""), "unverified unsigned VSIX denied");
    require(mayInstallVSIX(false, "Y"), "unverified explicitly opted in");
    const auto unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const fs::path base = fs::temp_directory_path() / ("rawrxd-extension-policy-" + unique);
    const fs::path root = base / "extensions";
    const fs::path outside = base / "outside";
    fs::create_directories(root / "plugin");
    fs::create_directories(outside);
    struct Cleanup { fs::path path; ~Cleanup() { std::error_code ec; fs::remove_all(path, ec); } } cleanup{base};
    require(entryWithinRoot(root, root / "plugin" / "index.js"), "entry inside root");
    require(!entryWithinRoot(root, root), "root itself not entry");
    require(!entryWithinRoot(root, outside / "index.js"), "entry outside root");
    require(!entryWithinRoot(root, root / ".." / "outside" / "index.js"), "parent traversal");
    require(!entryWithinRoot({}, root / "plugin" / "index.js"), "empty root");
    require(!entryWithinRoot(root, {}), "empty entry");
    std::error_code ec;
    fs::create_directory_symlink(outside, root / "plugin" / "linked", ec);
    if (!ec) {
        require(!entryWithinRoot(root, root / "plugin" / "linked" / "index.js"), "symlink escape");
    } else {
        std::cout << "SKIP: symlink escape (platform privileges unavailable): " << ec.message() << '\n';
    }
    std::cout << "PASS_REAL_POLICY: " << assertions << " assertions (policy only, not VSIX execution)\n";
}
