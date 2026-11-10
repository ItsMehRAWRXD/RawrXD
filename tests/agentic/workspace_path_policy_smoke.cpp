#include <cstdio>
#include <filesystem>
#include <string>

#include "../../src/agentic/WorkspaceToolHost.h"

namespace fs = std::filesystem;

static int failures = 0;

static void expect(bool condition, const char* name) {
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) ++failures;
}

int main() {
    const fs::path root = fs::temp_directory_path() / "rawrxd_workspace_policy_smoke";
    std::error_code ec;
    fs::remove_all(root, ec);
    fs::create_directories(root / "src", ec);

    RawrXD::Agent::WorkspaceToolHost host(root.string());
    std::string error;

    expect(host.ResolveInWorkspace(root.string() + "-escape\\file.txt", error).empty(),
           "sibling_prefix_denied");
    error.clear();
    expect(!host.ResolveInWorkspace("src\\file.txt", error).empty(),
           "workspace_child_allowed");
    error.clear();
    expect(!host.ResolveInWorkspace(root.string(), error).empty(),
           "workspace_root_allowed");

    std::printf("FAIL_COUNT=%d\n", failures);
    std::printf("PROMOTE=0\n");
    fs::remove_all(root, ec);
    return failures == 0 ? 0 : 1;
}
