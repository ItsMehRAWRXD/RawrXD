#include "../src/agentic/MotdAuthorization.h"
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using rawrxd::agentic::MotdAuthorization;
static void write(const fs::path& file, const std::string& body) {
    std::ofstream out(file, std::ios::binary);
    assert(static_cast<bool>(out));
    out.write(body.data(), static_cast<std::streamsize>(body.size()));
    assert(static_cast<bool>(out));
}
int main() {
    const fs::path root = fs::temp_directory_path() /
        ("rawrxd-motd-smoke-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    const fs::path rules = root / ".cursor" / "rules";
    fs::create_directories(rules);
    const fs::path motd = rules / "PassiveRoleNotRoleplay.md";
    write(motd, "# Local test policy\nDo not execute tools before acknowledgment.\n");
    try {
        MotdAuthorization auth(root);
        std::string reason, body, digest, error;
        assert(!auth.BeginTurn("", 1));
        assert(auth.BeginTurn("session-A", 1));
        assert(!auth.AuthorizeTool("write_file", "session-A", 1, reason));
        assert(!reason.empty());
        assert(!auth.AuthorizeTool("write_file", "session-B", 1, reason));
        assert(!auth.AuthorizeTool("write_file", "session-A", 2, reason));
        assert(auth.AuthorizeTool("read_motd", "session-A", 1, reason));
#ifdef _WIN32
        assert(auth.ReadMotd("session-A", 1, body, digest, error));
        assert(!digest.empty());
        assert(auth.IsAcknowledged("session-A", 1));
        assert(auth.AuthorizeTool("write_file", "session-A", 1, reason));
        write(motd, "Changed local policy\n");
        assert(!auth.AuthorizeTool("write_file", "session-A", 1, reason));
        assert(!auth.IsAcknowledged("session-A", 1));
        assert(auth.ReadMotd("session-A", 1, body, digest, error));
        assert(auth.AuthorizeTool("write_file", "session-A", 1, reason));
#else
        // Without a supported crypto provider the policy must stay unacknowledged.
        assert(!auth.ReadMotd("session-A", 1, body, digest, error));
        assert(!auth.IsAcknowledged("session-A", 1));
        assert(!auth.AuthorizeTool("write_file", "session-A", 1, reason));
#endif
        // An oversized MOTD must fail *before* streaming into memory.
        write(motd, std::string(1024 * 1024 + 1, 'x'));
        assert(!auth.ReadMotd("session-A", 1, body, digest, error));
        assert(error == "MOTD_CONTENT_INVALID");
        assert(!auth.IsAcknowledged("session-A", 1));
        assert(!auth.AuthorizeTool("write_file", "session-A", 1, reason));
        auth.EndTurn("session-A", 1);
        assert(!auth.AuthorizeTool("read_motd", "session-A", 1, reason));
        assert(auth.BeginTurn("session-A", 2));
        assert(!auth.AuthorizeTool("write_file", "session-A", 2, reason));
        auth.SetWorkspaceRoot(root / "nonexistent");
        assert(!auth.AuthorizeTool("read_motd", "session-A", 2, reason));

        // Reparse/symlink escapes must never be accepted as a policy file.
        fs::path outside = root.parent_path() / (root.filename().string() + "-outside");
        write(outside, "external policy\n");
        fs::remove(motd);
        std::error_code ec;
        fs::create_symlink(outside, motd, ec);
        if (!ec) {
            MotdAuthorization separate(root);
            assert(separate.BeginTurn("session-A", 3));
            assert(!separate.ReadMotd("session-A", 3, body, digest, error));
            assert(error == "MOTD_PATH_INVALID");
            fs::remove(motd);
        }
        fs::remove(outside);
    } catch (...) {
        fs::remove_all(root);
        throw;
    }
    fs::remove_all(root);
}
