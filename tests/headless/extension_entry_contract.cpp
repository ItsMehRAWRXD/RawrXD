// Contract against the production extension entry containment policy.
#include <filesystem>
#include <iostream>
#include <system_error>
#include "../../~dev/rawrxd/src/core/extension_entry_policy.hpp"
int main() {
 namespace fs = std::filesystem;
 using rawrxd::extensions::entryWithinRoot;
 const auto root = fs::temp_directory_path() / "rawrxd-entry-contract";
 const auto outside = fs::temp_directory_path() / "rawrxd-outside-entry";
 std::error_code ec;
 fs::create_directories(root / "inside", ec);
 if (ec) return 2;
 fs::create_directories(outside, ec);
 if (ec) return 2;
 fs::create_directory_symlink(outside, root / "escape-link", ec);
 const bool linkCreated = !ec;
 const bool pass =
     entryWithinRoot(root, root / "inside" / "index.js") &&
     !entryWithinRoot(root, root / ".." / "outside.js") &&
     !entryWithinRoot(root, root) &&
     !entryWithinRoot({}, root / "inside") &&
     (!linkCreated || !entryWithinRoot(root, root / "escape-link" / "index.js"));
 fs::remove_all(root, ec);
 fs::remove_all(outside, ec);
 std::cout << (pass ? "PASS" : "FAIL") << " extension entry containment\n";
 return pass ? 0 : 1;
}
