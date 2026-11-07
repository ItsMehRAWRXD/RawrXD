// Portable regression gates for the actual extension policy headers.
// This is NOT a VSIX installation or full IDE acceptance test.
#include "../src/core/extension_manifest_policy.hpp"
#include "../src/core/extension_entry_policy.hpp"
#include <filesystem>
#include <iostream>
#include <string_view>
#include <system_error>
namespace fs = std::filesystem;
static int failed = 0, executed = 0;
static void check(std::string_view name, bool ok) {
    ++executed;
    std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
    if (!ok) ++failed;
}
int main() {
    using namespace rawrxd::extensions;
    check("identifier-normal", validIdentifier("publisher_42"));
    check("identifier-empty-rejected", !validIdentifier(""));
    check("identifier-slash-rejected", !validIdentifier("bad/name"));
    check("identifier-length-rejected", !validIdentifier(std::string(129, 'a')));
    check("version-three-components", validVersion("1.20.300"));
    check("version-two-components-rejected", !validVersion("1.2"));
    check("version-extra-components-rejected", !validVersion("1.2.3.4"));
    check("version-nondigit-rejected", !validVersion("1.2.beta"));
    check("manifest-identity-valid", validManifestIdentity("acme","lint","1.0.0"));
    check("manifest-name-invalid", !validManifestIdentity("acme","../lint","1.0.0"));
    check("entry-normal", validRelativeMain("dist/extension.js"));
    check("entry-parent-rejected", !validRelativeMain("../escape.js"));
    check("entry-windows-parent-rejected", !validRelativeMain("dist\\..\\escape.js"));
    check("entry-drive-rejected", !validRelativeMain("C:\\escape.js"));
    check("entry-unc-rejected", !validRelativeMain("\\\\server\\share"));
    check("entry-ads-rejected", !validRelativeMain("main.js:stream"));
    check("entry-device-rejected", !validRelativeMain("CON.txt"));
    check("entry-empty-segment-rejected", !validRelativeMain("dist//main.js"));
    check("entry-trailing-dot-rejected", !validRelativeMain("dist/main."));
    check("entry-trailing-space-rejected", !validRelativeMain("dist/main "));
    std::error_code ec;
    auto base = fs::temp_directory_path(ec);
    if (ec) { std::cerr << "FAIL temp_directory_path: " << ec.message() << '\n'; return 2; }
    base /= "rawrxd-extension-policy-test";
    fs::remove_all(base, ec);
    ec.clear();
    fs::create_directories(base / "installed" / "dist", ec);
    if (ec) { std::cerr << "FAIL fixture creation: " << ec.message() << '\n'; return 2; }
    const auto root = fs::absolute(base / "installed");
    check("containment-child", entryWithinRoot(root, root / "dist" / "main.js"));
    check("containment-parent-rejected", !entryWithinRoot(root, root / ".." / "outside.js"));
    check("containment-sibling-prefix-rejected", !entryWithinRoot(root, base / "installed-other" / "main.js"));
    check("containment-root-itself-rejected", !entryWithinRoot(root, root));
    check("containment-relative-root-rejected", !entryWithinRoot("installed", root / "dist" / "main.js"));
    check("containment-relative-entry-rejected", !entryWithinRoot(root, "dist/main.js"));
    fs::remove_all(base, ec);
    std::cout << "RESULT " << (executed - failed) << "/" << executed << " passed\n";
    return failed ? 1 : 0;
}
