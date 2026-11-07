// Standalone, model-free extension security policy acceptance gates.
// Compile: c++ -std=c++17 -Wall -Wextra -pedantic -I~dev/rawrxd/src/core tests/extension_policy_acceptance.cpp -o extension_policy_acceptance
#include "extension_entry_policy.hpp"
#include "extension_manifest_policy.hpp"
#include "extension_signature_policy.hpp"
#include <filesystem>
#include <iostream>
#include <string_view>
#include <vector>

struct Case { const char* name; bool actual; bool expected; };
int main() {
    using namespace rawrxd::extensions;
    const std::vector<Case> cases = {
        {"valid relative JS entry", validRelativeMain("dist/extension.js"), true},
        {"valid backslash entry", validRelativeMain("dist\\extension.js"), true},
        {"reject empty entry", validRelativeMain(""), false},
        {"reject parent traversal", validRelativeMain("../outside.js"), false},
        {"reject nested traversal", validRelativeMain("dist/../outside.js"), false},
        {"reject dot segment", validRelativeMain("dist/./main.js"), false},
        {"reject drive path", validRelativeMain("C:\\evil.js"), false},
        {"reject UNC path", validRelativeMain("\\\\server\\share"), false},
        {"reject absolute path", validRelativeMain("/tmp/main.js"), false},
        {"reject NTFS ADS", validRelativeMain("main.js:stream"), false},
        {"reject device name", validRelativeMain("con.txt"), false},
        {"reject console alias", validRelativeMain("CONOUT$.txt"), false},
        {"reject trailing dot", validRelativeMain("main."), false},
        {"reject trailing space", validRelativeMain("main.js "), false},
        {"reject double separator", validRelativeMain("a//b"), false},
        {"reject control character", validRelativeMain(std::string_view("a\0b",3)), false},
        {"valid identity", validManifestIdentity("publisher", "extension_name", "1.2.3"), true},
        {"reject malformed version", validManifestIdentity("publisher", "extension", "1.2"), false},
        {"reject invalid publisher", validManifestIdentity("bad.publisher", "extension", "1.2.3"), false},
        {"reject invalid name", validManifestIdentity("publisher", "../bad", "1.2.3"), false},
        {"unsigned default denied", mayInstallVSIX(false, ""), false},
        {"unsigned opt in accepted", mayInstallVSIX(false, "1"), true},
        {"verified signature accepted", mayInstallVSIX(true, ""), true},
        {"arbitrary opt in denied", mayInstallVSIX(false, "true"), false},
    };
    int failed = 0;
    for (const auto& c : cases) {
        if (c.actual != c.expected) {
            std::cerr << "FAIL " << c.name << " expected=" << c.expected << " actual=" << c.actual << '\n';
            ++failed;
        }
    }
    namespace fs = std::filesystem;
    const fs::path root = fs::temp_directory_path() / "rawrxd-extension-policy-fixture";
    const std::vector<Case> pathCases = {
        {"child within root", entryWithinRoot(root, root / "dist/main.js"), true},
        {"root itself denied", entryWithinRoot(root, root), false},
        {"sibling prefix denied", entryWithinRoot(root, root.parent_path() / "rawrxd-extension-policy-fixture-evil/main.js"), false},
        {"parent denied", entryWithinRoot(root, root.parent_path() / "outside.js"), false},
        {"relative root denied", entryWithinRoot("relative", root / "main.js"), false},
        {"relative entry denied", entryWithinRoot(root, "main.js"), false},
    };
    for (const auto& c : pathCases) {
        if (c.actual != c.expected) {
            std::cerr << "FAIL " << c.name << " expected=" << c.expected << " actual=" << c.actual << '\n';
            ++failed;
        }
    }
    std::cout << "extension policy cases=" << (cases.size()+pathCases.size())
              << " failed=" << failed << '\n';
    return failed ? 1 : 0;
}
