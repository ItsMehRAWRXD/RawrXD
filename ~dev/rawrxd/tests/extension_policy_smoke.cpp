// Standalone C++17 extension-policy smoke tests. No model, Ollama, or Win32 GUI required.
// Compile from this directory:
//   c++ -std=c++17 -Wall -Wextra -Werror -pedantic extension_policy_smoke.cpp -o extension_policy_smoke
//   ./extension_policy_smoke
// On Windows/MSVC:
//   cl /std:c++17 /EHsc /W4 extension_policy_smoke.cpp
// Results apply to these policy helpers only, not to full extension execution.
#include "../src/core/extension_entry_policy.hpp"
#include "../src/core/extension_manifest_policy.hpp"
#include "../src/core/extension_signature_policy.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
namespace fs = std::filesystem;
int main() {
    int passed = 0, failed = 0;
    auto check = [&](bool ok, const char* label) {
        std::cout << (ok ? "PASS " : "FAIL ") << label << '\n';
        if (ok) ++passed; else ++failed;
    };
    using namespace rawrxd::extensions;
    check(validRelativeMain("out/extension.js"), "relative manifest entry accepted");
    check(!validRelativeMain(""), "empty manifest entry rejected");
    check(!validRelativeMain("/absolute/main.js"), "POSIX absolute manifest entry rejected");
    check(!validRelativeMain("\\absolute\\main.js"), "Windows rooted manifest entry rejected");
    check(!validRelativeMain("C:/absolute/main.js"), "Windows drive manifest entry rejected");
    check(!validRelativeMain("C:\\absolute\\main.js"), "Windows drive backslash manifest entry rejected");
    check(!validRelativeMain("out/evil\n.js"), "control character manifest entry rejected");
    check(!validRelativeMain("../escape.js"), "parent traversal rejected");
    check(!validRelativeMain("./main.js"), "leading dot segment rejected");
    check(!validRelativeMain("out/./main.js"), "nested dot segment rejected");
    check(!validRelativeMain("out\\.\\main.js"), "Windows dot segment rejected");
    check(!validRelativeMain("out/../escape.js"), "nested parent traversal rejected");
    check(!validRelativeMain("..\\escape.js"), "Windows parent traversal rejected");
    check(!validRelativeMain("out\\..\\escape.js"), "nested Windows parent traversal rejected");
    check(!validRelativeMain("out//main.js"), "empty path component rejected");
    check(!validRelativeMain("out:stream/main.js"), "colon path syntax rejected");
    check(!validRelativeMain("out/file?.js"), "Windows question mark rejected");
    check(!validRelativeMain("out/file*.js"), "Windows wildcard rejected");
    check(!validRelativeMain("out/file|name.js"), "Windows pipe rejected");
    check(!validRelativeMain("out/file<name.js"), "Windows angle bracket rejected");
    check(!validRelativeMain("out/file\"name.js"), "Windows quote rejected");
    check(!validRelativeMain("out/folder./main.js"), "trailing dot component rejected");
    check(!validRelativeMain("out/folder /main.js"), "trailing space component rejected");
    check(!validRelativeMain("out/main.js."), "trailing dot filename rejected");
    check(validRelativeMain("out/main-file_2.js"), "ordinary entry remains accepted");
    check(!validRelativeMain("CON"), "Windows CON device rejected");
    check(!validRelativeMain("out/nul.js"), "Windows NUL device with extension rejected");
    check(!validRelativeMain("out/PRN.txt"), "Windows PRN device with extension rejected");
    check(!validRelativeMain("out/aux"), "Windows AUX device rejected");
    check(!validRelativeMain("out/com1.js"), "Windows COM1 device rejected");
    check(!validRelativeMain("out/LPT9.js"), "Windows LPT9 device rejected");
    check(validRelativeMain("out/COM0.js"), "nonreserved COM0 allowed");
    check(validRelativeMain("out/console.js"), "ordinary console name allowed");
    check(validIdentifier("sample_extension-1"), "identifier valid");
    check(!validIdentifier("../escape"), "identifier traversal rejected");
    check(!validIdentifier(""), "identifier empty rejected");
    check(!validIdentifier(std::string(129, 'x')), "identifier oversized rejected");
    check(validVersion("1.2.3"), "version valid");
    check(!validVersion("1.2"), "version incomplete rejected");
    check(!validVersion("1.2.3.4"), "version extra segment rejected");
    check(!validVersion("1.2.x"), "version nondigit rejected");
    check(validManifestIdentity("vendor", "name", "1.0.0"), "manifest valid");
    check(!validManifestIdentity("../vendor", "name", "1.0.0"), "manifest invalid publisher rejected");
    check(!allowUnsignedVSIX("true"), "unsigned requires explicit flag");
    check(!mayInstallVSIX(false, ""), "unsigned default rejected");
    check(mayInstallVSIX(false, "1"), "unsigned opt-in accepted");
    check(mayInstallVSIX(true, ""), "verified accepted");
    const fs::path base = fs::temp_directory_path() / ("rawrxd_extension_policy_smoke_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base / "extension", ec);
    if (ec) { std::cerr << "BLOCKED: cannot create fixture root\n"; return 2; }
    fs::create_directories(base / "outside", ec);
    if (ec) { std::cerr << "BLOCKED: cannot create outside fixture\n"; return 2; }
    { std::ofstream out(base / "extension" / "main.js"); out << "fixture"; }
    check(entryWithinRoot(base / "extension", base / "extension" / "main.js"), "entry inside root accepted");
    check(!entryWithinRoot(base / "extension", base / "outside" / "main.js"), "entry outside root rejected");
    check(!entryWithinRoot(base / "extension", base / "extension"), "root itself rejected");
    check(!entryWithinRoot({}, base / "extension" / "main.js"), "empty root rejected");
    check(!entryWithinRoot(base / "extension", {}), "empty entry rejected");
    check(!entryWithinRoot(base / "extension", fs::path("relative.js")), "relative entry rejected");
    check(!entryWithinRoot(fs::path("relative-root"), base / "extension" / "main.js"), "relative root rejected");
    fs::create_directories(base / "extension-sibling", ec);
    if (ec) { std::cerr << "BLOCKED: cannot create sibling fixture\\n"; return 2; }
    check(!entryWithinRoot(base / "extension", base / "extension-sibling" / "main.js"), "sibling prefix rejected");
    ec.clear();
    fs::create_directory_symlink(base / "outside", base / "extension" / "link", ec);
    if (!ec) check(!entryWithinRoot(base / "extension", base / "extension" / "link" / "main.js"), "symlink escape rejected");
    else {
#ifdef _WIN32
        std::cout << "SKIP symlink fixture unavailable on Windows: " << ec.message() << '\n';
#else
        std::cerr << "FAIL symlink fixture unavailable: " << ec.message() << '\n';
        ++failed;
#endif
    }
    fs::remove_all(base, ec);
    std::cout << "RESULT " << passed << " passed " << failed << " failed\n";
    return failed ? 1 : 0;
}
