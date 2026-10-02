// ============================================================================
// RepoIntelCli.hpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// The production surface. This is not a test-only island: it is the same code
// path the certification harness uses, reached from the `rawr` CLI, and it is
// where the scope guard becomes visible to whoever asks a question.
//
//   rawr repo scope  [--root <dir>] [--out <file>]
//   rawr repo index  [--root <dir>] [--cache <dir>] [--out <file>]
//   rawr repo search <query> [--root <dir>] [--limit N]
//   rawr repo context <query> [--root <dir>] [--file <rel>] [--limit N]
//   rawr repo symbol <name> [--root <dir>]
//   rawr repo callers <name> | callees <name> | reachable <name>
//   rawr repo includes <rel> | dependents <rel> | impact <rel>
//   rawr repo refresh  [--root <dir>] [--cache <dir>]
//
// Every subcommand prints its scope and its exclusions, and refuses to print
// "absent" from a narrowed scope. Exit code 0 only when the subcommand's own
// measured result succeeded.
// ============================================================================
#pragma once

#include <string>
#include <vector>

namespace rawrxd {
namespace repointel {

struct RepoCliResult {
    int         exitCode = 0;
    std::string receiptPath;
};

// argv/argc are the arguments AFTER `repo`. `defaultRoot` is used when --root is
// absent; pass an empty string to require --root.
RepoCliResult runRepoIntelCli(const std::vector<std::string>& args,
                              const std::string& defaultRoot);

}  // namespace repointel
}  // namespace rawrxd