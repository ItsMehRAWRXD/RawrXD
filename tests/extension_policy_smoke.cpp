// Deterministic, model-free acceptance tests for extension path and manifest policies.
// Compile from the repository root:
//   c++ -std=c++20 -Wall -Wextra -pedantic tests/extension_policy_smoke.cpp -o extension_policy_smoke
//   ./extension_policy_smoke
// This is a POLICY gate, not proof of a working QuickJS/VSIX runtime.
#include "../~dev/rawrxd/src/core/extension_entry_policy.hpp"
#include "../~dev/rawrxd/src/core/extension_manifest_policy.hpp"
#include "../~dev/rawrxd/src/core/extension_read_policy.hpp"
#include <algorithm>
#include <cstring>
#include <string>
#include <filesystem>
#include <iostream>
#include <string_view>

static int failures = 0;
static int assertions = 0;
static void check(bool actual, bool expected, std::string_view name) {
    ++assertions;
    if (actual != expected) {
        ++failures;
        std::cerr << "FAIL " << name << "\n";
    }
}
int main() {
    using namespace rawrxd::extensions;
    check(validRelativeMain("dist/extension.js"), true, "normal entry");
    check(validRelativeMain("extension.js"), true, "single file");
    check(validRelativeMain("../escape.js"), false, "parent traversal");
    check(validRelativeMain("dist/../escape.js"), false, "nested traversal");
    check(validRelativeMain("/tmp/escape.js"), false, "absolute POSIX");
    check(validRelativeMain("C:\\escape.js"), false, "absolute Windows");
    check(validRelativeMain("\\\\server\\share.js"), false, "UNC");
    check(validRelativeMain("dist//file.js"), false, "empty segment");
    check(validRelativeMain("dist/CON.txt"), false, "Windows device");
    check(validRelativeMain("dist/COM1.txt"), false, "Windows serial device");
    check(validRelativeMain("dist/name:stream"), false, "ADS");
    check(validRelativeMain("dist/trailing."), false, "trailing dot");
    check(validRelativeMain("dist/trailing "), false, "trailing space");
    check(validRelativeMain(""), false, "empty entry");
    check(validManifestIdentity("publisher", "extension", "1.2.3"), true, "valid identity");
    check(validManifestIdentity("", "extension", "0.0.1"), true, "optional publisher");
    check(validManifestIdentity("bad.publisher", "extension", "1.2.3"), false, "bad publisher");
    check(validManifestIdentity("publisher", "../bad", "1.2.3"), false, "bad name");
    check(validManifestIdentity("publisher", "extension", "1.2"), false, "short version");
    check(validManifestIdentity("publisher", "extension", "1.2.3.4"), false, "long version");
    check(validManifestIdentity("publisher", "extension", "1.2.x"), false, "nonnumeric version");
    const auto root = std::filesystem::temp_directory_path() / "rawrxd_extension_policy_gate";
    check(entryWithinRoot(root, root / "dist" / "extension.js"), true, "inside root");
    check(entryWithinRoot(root, root / ".." / "escape.js"), false, "outside root");
    check(entryWithinRoot(root, root), false, "root not child");
    check(entryWithinRoot("relative", root / "file.js"), false, "relative root");
    check(entryWithinRoot(root, "relative/file.js"), false, "relative entry");
    // A symlink within the extension directory must never allow an entry
    // point to escape into a sibling directory. Skip only when the OS
    // explicitly refuses symlink creation (common on restricted Windows CI).
    {
        std::error_code ec;
        const auto sandbox = std::filesystem::temp_directory_path() /
                             "rawrxd_extension_policy_symlink";
        const auto extensionRoot = sandbox / "installed";
        const auto outside = sandbox / "outside";
        std::filesystem::create_directories(extensionRoot, ec);
        if (ec) {
            check(false, true, "create extension fixture directory");
        } else {
            ec.clear();
            std::filesystem::create_directories(outside, ec);
            if (ec) {
                check(false, true, "create external fixture directory");
            } else {
                const auto link = extensionRoot / "linked";
                std::filesystem::remove(link, ec);
                ec.clear();
                std::filesystem::create_directory_symlink(outside, link, ec);
                if (!ec) {
                    check(entryWithinRoot(extensionRoot, link / "payload.js"),
                          false, "symlink escape rejected");
                } else {
                    std::cout << "SKIP symlink escape fixture: OS denied symlink creation\n";
                }
            }
        }
        ec.clear();
        std::filesystem::remove_all(sandbox, ec);
    }
    // Exercise the production readExactly template with short reads, EOF and overflow.
    {
        std::string bytes = "hello";
        char output[5]{};
        std::size_t offset = 0;
        const bool ok = readExactly(output, sizeof(output), [&](char* dst, std::size_t remaining) {
            const auto n = std::min<std::size_t>({2, remaining, bytes.size() - offset});
            std::memcpy(dst, bytes.data() + offset, n);
            offset += n;
            return n;
        });
        check(ok && std::string(output, sizeof(output)) == bytes, true, "short reads assembled");
        check(readExactly(output, sizeof(output),
              [](char*, std::size_t) { return std::size_t{0}; }), false, "premature EOF");
        check(readExactly(output, sizeof(output),
              [](char*, std::size_t n) { return n + 1; }), false, "oversized reader result");
        check(readExactly(nullptr, 1,
              [](char*, std::size_t) { return std::size_t{1}; }), false, "null destination");
        check(readExactly(nullptr, 0,
              [](char*, std::size_t) { return std::size_t{0}; }), true, "zero-length read");
    }
    std::cout << "EXTENSION_POLICY_GATE assertions=" << assertions
              << " failures=" << failures << (failures ? " FAIL" : " PASS") << "\n";
    return failures ? 1 : 0;
}
