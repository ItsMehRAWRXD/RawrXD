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
