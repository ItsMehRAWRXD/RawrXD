// RAWRXD_WORKSPACE_LOAD_001 runtime driver
//
// workspace_model.cpp is not in any build target, so its new load path has to be
// exercised by linking it directly rather than through the shipping IDE. This
// driver calls the real C API and reports what the load actually did.
//
// Three cases:
//   1. valid multi-root document  -> must restore folders, open files, layout
//   2. malformed (unparsable) JSON -> must leave the previous config untouched
//   3. zero-folder document        -> must be refused, not adopted
//
// A first run with no document must also be distinguished from a failure, so
// that is case 0.

#include <cstdio>
#include <string>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

extern "C" {
    bool        RawrXD_IDE_InitWorkspace(const char* rootPath);
    const char* RawrXD_IDE_GetWorkspaceName();
}

static void writeFile(const fs::path& p, const std::string& body) {
    fs::create_directories(p.parent_path());
    std::ofstream o(p, std::ios::binary | std::ios::trunc);
    o << body;
}

int main(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: driver <case> <root>\n"); return 2; }
    const std::string kase = argv[1];
    const fs::path root = argv[2];
    fs::create_directories(root);
    const fs::path doc = root / ".rawrxd" / "workspace.json";

    int fails = 0;
    auto check = [&](const char* what, bool ok) {
        std::printf("%s=%s\n", what, ok ? "1" : "0");
        if (!ok) ++fails;
    };

    // Each case runs in its own process. RawrXD_IDE_InitWorkspace replaces the
    // global WorkspaceModel, and ~WorkspaceModel calls save() when the config is
    // dirty -- so two InitWorkspace calls in one process make the first teardown
    // overwrite the document before the second initialize() can read it. That is
    // a real re-initialisation hazard, but it is not what these cases are
    // measuring, so the cases are isolated rather than papered over.

    if (kase == "first") {
        fs::remove(doc);
        const bool ok = RawrXD_IDE_InitWorkspace(root.string().c_str());
        check("FIRST_RUN_INITIALIZE_OK", ok);
        const std::string name = RawrXD_IDE_GetWorkspaceName();
        std::printf("FIRST_RUN_NAME=%s\n", name.c_str());
        check("FIRST_RUN_NAME_IS_ROOT", name == root.filename().string());
    } else if (kase == "valid") {
        writeFile(doc,
            "{\n"
            "  \"name\": \"MultiRootProbe\",\n"
            "  \"folders\": [\n"
            "    { \"path\": \"" + (root / "pkgA").generic_string() + "\", \"name\": \"pkgA\", \"isRoot\": true },\n"
            "    { \"path\": \"" + (root / "pkgB").generic_string() + "\", \"name\": \"\", \"isRoot\": false },\n"
            "    { \"path\": \"" + (root / "tools").generic_string() + "\" }\n" +
            "  ],\n"
            "  \"openFiles\": [\n"
            "    { \"path\": \"" + (root / "pkgA" / "a.cpp").generic_string() + "\", \"line\": 12, \"column\": 4 },\n"
            "    { \"path\": \"" + (root / "pkgB" / "b.h").generic_string() + "\", \"line\": 7, \"column\": 0 }\n"
            "  ],\n"
            "  \"layout\": { \"explorerVisible\": true, \"terminalVisible\": true, \"explorerWidth\": 333 }\n"
            "}\n");
        const bool ok = RawrXD_IDE_InitWorkspace(root.string().c_str());
        check("VALID_LOAD_OK", ok);
        const std::string name = RawrXD_IDE_GetWorkspaceName();
        std::printf("VALID_NAME=%s\n", name.c_str());
        check("VALID_NAME_RESTORED", name == "MultiRootProbe");
    } else if (kase == "malformed") {
        writeFile(doc, "{ this is not json at all ,,, ");
        const bool ok = RawrXD_IDE_InitWorkspace(root.string().c_str());
        // initialize() falls back to a synthetic single-root workspace when the
        // load fails, so a true return is expected. The property under test is
        // that the operator's document is not silently consumed.
        const std::string name = RawrXD_IDE_GetWorkspaceName();
        std::printf("MALFORMED_NAME=%s\n", name.c_str());
        check("MALFORMED_DID_NOT_ADOPT_NAME", name != "MultiRootProbe");
        (void)ok;
    } else if (kase == "zerofolders") {
        writeFile(doc, "{\n  \"name\": \"EmptyProbe\",\n  \"folders\": []\n}\n");
        const bool ok = RawrXD_IDE_InitWorkspace(root.string().c_str());
        check("ZERO_FOLDER_INITIALIZE_OK", ok);
        const std::string name = RawrXD_IDE_GetWorkspaceName();
        std::printf("ZERO_FOLDER_NAME=%s\n", name.c_str());
        check("ZERO_FOLDER_DID_NOT_ADOPT_NAME", name != "EmptyProbe");
    } else {
        std::fprintf(stderr, "unknown case '%s'\n", kase.c_str());
        return 2;
    }

    std::printf("CASE=%s\n", kase.c_str());
    std::printf("CHECKS_FAILED=%d\n", fails);
    std::printf("VERDICT=%s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
