// Standalone extension policy regression gates. No model, Ollama, Win32 or QuickJS required.
// Compile from repository root:
// c++ -std=c++17 -Wall -Wextra -pedantic -I~dev/rawrxd/src/core tests/extension_policy_gates.cpp -o extension_policy_gates
// ./extension_policy_gates
#include "extension_manifest_policy.hpp"
#include "extension_entry_policy.hpp"
#include "extension_signature_policy.hpp"
#include <filesystem>
#include <iostream>
#include <string>
#include <cstdlib>
namespace fs = std::filesystem;
int main() {
    int failed = 0, passed = 0, skipped = 0;
    auto gate = [&](const char* name, bool ok) {
        std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
        ok ? ++passed : ++failed;
    };
    using namespace rawrxd::extensions;
    gate("01_valid_manifest", validManifestIdentity("publisher", "extension_1", "1.2.3"));
    gate("02_empty_name_rejected", !validManifestIdentity("publisher", "", "1.2.3"));
    gate("03_bad_publisher_rejected", !validManifestIdentity("../bad", "extension", "1.2.3"));
    gate("04_bad_version_rejected", !validManifestIdentity("publisher", "extension", "1.2"));
    gate("05_version_suffix_rejected", !validManifestIdentity("publisher", "extension", "1.2.3-beta"));
    gate("06_identifier_limit", validIdentifier(std::string(128, 'a')) && !validIdentifier(std::string(129, 'a')));
    gate("07_version_limit", !validVersion(std::string(65, '1')));
    gate("08_empty_version_rejected", !validVersion(""));
    const fs::path root = fs::temp_directory_path() / "rawrxd_policy_gates_root";
    gate("09_child_path_allowed", entryWithinRoot(root, root / "extension.js"));
    gate("10_traversal_rejected", !entryWithinRoot(root, root / ".." / "escape.js"));
    gate("11_sibling_prefix_rejected", !entryWithinRoot(root, fs::path(root.string() + "_evil") / "extension.js"));
    gate("12_root_itself_rejected", !entryWithinRoot(root, root));
    gate("13_empty_path_rejected", !entryWithinRoot({}, root / "extension.js") && !entryWithinRoot(root, {}));
    gate("14_unsigned_default_denied", !mayInstallVSIX(false, "") && !mayInstallVSIX(false, "true"));
    gate("15_signed_or_explicit_optin", mayInstallVSIX(true, "") && mayInstallVSIX(false, "1") && mayInstallVSIX(false, "Y") && !mayInstallVSIX(false, "0"));
    gate("16_absolute_outside_rejected", !entryWithinRoot(root, fs::temp_directory_path() / "rawrxd_outside" / "extension.js"));
    gate("17_nested_child_allowed", entryWithinRoot(root, root / "dist" / "main.js"));
    gate("18_four_part_version_rejected", !validVersion("1.2.3.4"));
    gate("19_version_letters_rejected", !validVersion("a.b.c"));
    gate("20_signed_override", mayInstallVSIX(true, "0"));
    gate("21_empty_publisher_allowed", validManifestIdentity("", "extension", "0.0.1"));
    gate("22_unicode_identifier_rejected", !validIdentifier("ext\xC3\xA9"));
    gate("23_version_leading_dot_rejected", !validVersion(".1.2.3"));
    gate("24_version_trailing_dot_rejected", !validVersion("1.2.3."));
    gate("25_unsigned_case_sensitive", !mayInstallVSIX(false, "YES") && mayInstallVSIX(false, "y"));
    gate("27_relative_main_allowed", validRelativeMain("./dist/extension.js"));
    gate("28_drive_main_rejected", !validRelativeMain("C:/outside.js"));
    gate("29_backslash_root_rejected", !validRelativeMain("\\\\server\\share\\main.js"));
    gate("30_posix_root_rejected", !validRelativeMain("/tmp/main.js"));
    gate("31_control_char_main_rejected", !validRelativeMain(std::string("main") + char(10) + ".js"));
    gate("32_parent_component_rejected", !validRelativeMain("dist/../main.js"));
    gate("33_windows_parent_component_rejected", !validRelativeMain("dist\\\\..\\\\main.js"));
    gate("34_ads_colon_rejected", !validRelativeMain("dist/main.js:stream"));
    gate("35_empty_component_rejected", !validRelativeMain("dist//main.js"));
    gate("36_trailing_separator_rejected", !validRelativeMain("dist/"));
    gate("37_relative_root_rejected", !entryWithinRoot("relative", root / "main.js"));
    // Exercise a real filesystem symlink, not only lexical ".." traversal.
    // Windows runners without symlink privileges report SKIP, never a false PASS.
    {
        const fs::path sandbox = fs::temp_directory_path() / "rawrxd_policy_symlink_gate";
        const fs::path outside = fs::temp_directory_path() / "rawrxd_policy_symlink_outside";
        std::error_code ec;
        fs::remove_all(sandbox, ec);
        fs::remove_all(outside, ec);
        fs::create_directories(sandbox, ec);
        if (!ec) fs::create_directories(outside, ec);
        if (!ec) fs::create_directory_symlink(outside, sandbox / "escape", ec);
        if (ec) {
            ++skipped;
            std::cout << "SKIP 26_symlink_escape_rejected: " << ec.message() << '\n';
        } else {
            gate("26_symlink_escape_rejected", !entryWithinRoot(sandbox, sandbox / "escape" / "evil.js"));
        }
        fs::remove_all(sandbox, ec);
        fs::remove_all(outside, ec);
    }
    std::cout << "SUMMARY " << passed << " PASS; " << failed << " FAIL; " << skipped << " SKIP\n";
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
