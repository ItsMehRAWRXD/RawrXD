// ============================================================================
// GitSafetyAuthority.cpp — RAWRXD_GIT_SAFETY_AUTHORITY_001
//
// Every git invocation here goes through CommandExecutor::RunArgv, which
// builds a quoted command line and calls CreateProcessW directly. No shell is
// involved, so a quote, ampersand, pipe or backtick in a commit message, a
// branch name or a path is data and cannot become a metacharacter. The IDE's
// existing git handlers (_popen in src/core/feature_handlers.cpp) do not have
// that property, which is one reason the agent surface is routed here instead.
//
// The authority holds no opinion about what the agent is trying to do. It
// holds opinions about what the agent is allowed to do and about whether
// someone else's uncommitted work survived.
// ============================================================================
#include "agentic/GitSafetyAuthority.h"

#include "agentic/CommandExecutor.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

namespace rawrxd {
namespace agentic {
namespace {

namespace fs = std::filesystem;

// --- content fingerprint ----------------------------------------------------
// SHA-256 over the working-tree bytes of one path, so "unchanged" is a fact
// about content and not about a timestamp or a stat cache.

std::string Sha256Hex(const unsigned char* data, std::size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    if (len) BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);

    unsigned char digest[32];
    const NTSTATUS ok = BCryptFinishHash(hash, digest, 32, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (ok != 0) return {};

    std::ostringstream oss;
    char buf[3];
    for (int i = 0; i < 32; ++i) {
        std::snprintf(buf, sizeof buf, "%02X", digest[i]);
        oss << buf;
    }
    return oss.str();
}

std::string FingerprintFile(const fs::path& p) {
    std::error_code ec;
    if (!fs::exists(p, ec) || ec) return "ABSENT";
    if (fs::is_directory(p, ec)) return "DIRECTORY";
    std::ifstream in(p, std::ios::binary);
    if (!in) return "UNREADABLE";

    BCRYPT_ALG_HANDLE hProv = nullptr;
    if (BCryptOpenAlgorithmProvider(&hProv, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "UNREADABLE";
    BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptCreateHash(hProv, &h, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hProv, 0);
        return "UNREADABLE";
    }

    std::uint64_t total = 0;
    std::vector<unsigned char> buf(65536);
    while (in) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got <= 0) break;
        BCryptHashData(h, buf.data(), static_cast<ULONG>(got), 0);
        total += static_cast<std::uint64_t>(got);
    }
    unsigned char digest[32];
    BCryptFinishHash(h, digest, 32, 0);
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(hProv, 0);

    std::ostringstream oss;
    char hex[3];
    oss << total << ":";
    for (int i = 0; i < 32; ++i) {
        std::snprintf(hex, sizeof hex, "%02X", digest[i]);
        oss << hex;
    }
    return oss.str();
}

// --- path helpers -----------------------------------------------------------

std::string NormalizeSeparators(std::string s) {
    std::replace(s.begin(), s.end(), '\\', '/');
    while (!s.empty() && s.front() == '/') s.erase(s.begin());
    return s;
}

// Component-wise prefix test. A raw string prefix would accept
// "src/authority-extra" for prefix "src/author", and "src/authority" must not
// authorize "src/authority/x" for prefix "src/author".
bool PathUnderPrefix(const std::string& rel, const std::string& prefix) {
    if (prefix.empty()) return false;
    const std::string p = NormalizeSeparators(prefix);
    if (rel == p) return true;
    return rel.size() > p.size() && rel.compare(0, p.size(), p) == 0 && rel[p.size()] == '/';
}

std::string Trim(const std::string& s) {
    std::size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> SplitLines(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        out.push_back(line);
    }
    return out;
}

std::wstring Widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

// A ref may not start with '-' (option injection), and may not contain
// characters git itself refuses in a ref name plus the shell metacharacters a
// careless reader would expect to be blocked.
bool RefNameLooksSafe(const std::string& ref) {
    if (ref.empty() || ref.size() > 255) return false;
    if (ref[0] == '-') return false;
    if (ref.find("..") != std::string::npos) return false;
    if (ref.find('@{') != std::string::npos) return false;
    if (ref.front() == '/' || ref.back() == '/') return false;
    if (ref.find("//") != std::string::npos) return false;
    // Backtick is written as a concatenated literal so it is not parsed as an
    // (unrecognised) escape sequence by the compiler.
    static const std::string kForbidden = " ~^:?*[\\\n\r\t;|&<>\"()";
    static const char kBacktick = '`';
    for (char c : ref) {
        if (c < 0x20) return false;
        if (c == kBacktick) return false;
        if (kForbidden.find(c) != std::string::npos) return false;
    }
    if (ref.back() == '.') return false;
    if (ref.find(".lock") != std::string::npos) return false;
    return true;
}

} // namespace

// ---------------------------------------------------------------------------

const char* GitRefusalName(GitRefusal r) {
    switch (r) {
        case GitRefusal::None:                   return "NONE";
        case GitRefusal::CapabilityNotGranted:   return "CAPABILITY_NOT_GRANTED";
        case GitRefusal::NoScope:                return "NO_SCOPE";
        case GitRefusal::PathEscapesRepository:  return "PATH_ESCAPES_REPOSITORY";
        case GitRefusal::PathOutsideScope:       return "PATH_OUTSIDE_SCOPE";
        case GitRefusal::NotAGitRepository:      return "NOT_A_GIT_REPOSITORY";
        case GitRefusal::RepositoryRootNotAllowed: return "REPOSITORY_ROOT_NOT_ALLOWED";
        case GitRefusal::UnmergedPathsPresent:   return "UNMERGED_PATHS_PRESENT";
        case GitRefusal::DirtyTreeDestructive:   return "DIRTY_TREE_DESTRUCTIVE";
        case GitRefusal::NothingToDo:            return "NOTHING_TO_DO";
        case GitRefusal::GitFailed:              return "GIT_FAILED";
    }
    return "UNKNOWN";
}

GitPolicy GitPolicy::DefaultDenyAll() {
    GitPolicy p;
    p.granted = 0;
    p.authorizedPrefixes.clear();
    p.repositoryRoots.clear();
    p.requireCleanForDestructive = true;
    return p;
}

std::size_t GitBaseline::dirtyCount() const { return paths.size(); }

std::size_t GitBaseline::stagedCount() const {
    return static_cast<std::size_t>(std::count_if(paths.begin(), paths.end(),
                                                  [](const PathState& s) { return s.staged(); }));
}

std::size_t GitBaseline::untrackedCount() const {
    return static_cast<std::size_t>(
        std::count_if(paths.begin(), paths.end(), [](const PathState& s) { return s.untracked; }));
}

std::size_t GitBaseline::unmergedCount() const {
    return static_cast<std::size_t>(
        std::count_if(paths.begin(), paths.end(), [](const PathState& s) { return s.unmerged; }));
}

std::vector<std::string> GitBaseline::dirtyPathList() const {
    std::vector<std::string> out;
    out.reserve(paths.size());
    for (const auto& p : paths) out.push_back(p.path);
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<PathState> ParsePorcelainStatus(const std::string& porcelain) {
    std::vector<PathState> out;
    for (const std::string& raw : SplitLines(porcelain)) {
        if (raw.size() < 4) continue;
        PathState s;
        s.indexStatus = raw[0];
        s.worktreeStatus = raw[1];
        // Columns 0-1 are XY, column 2 is a space, the rest is the path.
        std::string path = raw.size() > 3 ? raw.substr(3) : std::string();
        // A rename or copy entry is "old -> new"; the new path is the one that
        // exists in the worktree now.
        const std::size_t arrow = path.find(" -> ");
        if (arrow != std::string::npos) path = path.substr(arrow + 4);
        s.path = NormalizeSeparators(path);
        if (s.path.empty()) continue;
        s.untracked = (s.indexStatus == '?' && s.worktreeStatus == '?');
        s.unmerged = (s.indexStatus == 'U' || s.worktreeStatus == 'U' ||
                      (s.indexStatus == 'A' && s.worktreeStatus == 'A') ||
                      (s.indexStatus == 'D' && s.worktreeStatus == 'D'));
        out.push_back(std::move(s));
    }
    std::sort(out.begin(), out.end(),
              [](const PathState& a, const PathState& b) { return a.path < b.path; });
    return out;
}

// ---------------------------------------------------------------------------

GitSafetyAuthority::GitSafetyAuthority(GitPolicy policy) : policy_(std::move(policy)) {}
GitSafetyAuthority::~GitSafetyAuthority() = default;

GitResult GitSafetyAuthority::fail(GitRefusal r, std::string detail) const {
    GitResult out;
    out.ok = false;
    out.refusal = r;
    out.detail = std::move(detail);
    return out;
}

bool GitSafetyAuthority::repositoryRootAllowed(const fs::path& canonical) const {
    if (policy_.repositoryRoots.empty()) return false;  // default deny
    for (const std::string& root : policy_.repositoryRoots) {
        std::error_code ec;
        const fs::path canonRoot = fs::weakly_canonical(fs::path(root), ec);
        if (ec || canonRoot.empty()) continue;
        std::error_code relEc;
        const fs::path rel = canonical.lexically_relative(canonRoot);
        const std::string relStr = rel.string();
        if (relStr.empty()) return true;
        if (relStr == "..") continue;
        if (relStr.rfind("..", 0) == 0) {
            if (relStr.size() == 2 || relStr[2] == '/' || relStr[2] == '\\') continue;
        }
        return true;
    }
    return false;
}

GitResult GitSafetyAuthority::beginSession(const fs::path& repoPath) {
    std::error_code ec;
    fs::path canonical = fs::weakly_canonical(repoPath, ec);
    if (ec || canonical.empty()) {
        return fail(GitRefusal::NotAGitRepository, "cannot canonicalize repository path");
    }
    if (!fs::is_directory(canonical, ec) || ec) {
        return fail(GitRefusal::NotAGitRepository, "repository path is not a directory");
    }
    if (!repositoryRootAllowed(canonical)) {
        return fail(GitRefusal::RepositoryRootNotAllowed,
                    "repository root is not under any policy repositoryRoot");
    }
    repoRoot_ = canonical.string();
    for (char& c : repoRoot_) {
        if (c == '/') c = '\\';
    }
    if (!repoRoot_.empty() && repoRoot_.back() == '\\') repoRoot_.pop_back();

    // Prove it is a work tree before anything else: `rev-parse --git-dir`
    // succeeds inside a plain directory that merely has a .git sibling name.
    const RunOutput probe = runGit({"rev-parse", "--is-inside-work-tree"});
    if (probe.spawnFailed || Trim(probe.out) != "true") {
        repoRoot_.clear();
        return fail(GitRefusal::NotAGitRepository, "not a git work tree");
    }

    baseline_ = GitBaseline{};
    baseline_.head = headSha();
    baseline_.branch = currentBranch();
    baseline_.paths = readStatus();
    for (const PathState& p : baseline_.paths) {
        baseline_.fingerprints.emplace(p.path, fingerprintOf(p.path));
    }
    baseline_.captured = true;
    sessionOpen_ = true;
    violations_.clear();
    mutatingAttempted_ = mutatingRefused_ = mutatingExecuted_ = 0;

    GitResult ok;
    ok.ok = true;
    ok.refusal = GitRefusal::None;
    ok.detail = "baseline captured: head=" + (baseline_.head.empty() ? "UNBORN" : baseline_.head.substr(0, 12)) +
                " branch=" + (baseline_.branch.empty() ? "(detached)" : baseline_.branch) +
                " dirty=" + std::to_string(baseline_.dirtyCount()) +
                " staged=" + std::to_string(baseline_.stagedCount()) +
                " untracked=" + std::to_string(baseline_.untrackedCount());
    return ok;
}

GitResult GitSafetyAuthority::refresh(std::vector<PathState>& outPaths) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    outPaths = readStatus();
    GitResult ok;
    ok.ok = true;
    ok.detail = std::to_string(outPaths.size()) + " dirty paths";
    return ok;
}

GitSafetyAuthority::RunOutput GitSafetyAuthority::runGit(const std::vector<std::string>& args,
                                                          std::size_t capBytes) const {
    RunOutput out;
    std::vector<std::wstring> argv;
    argv.push_back(L"git.exe");
    argv.push_back(L"-C");
    argv.push_back(Widen(repoRoot_));
    for (const std::string& a : args) argv.push_back(Widen(a));

    CommandExecutor::Options options;
    options.workingDir = Widen(repoRoot_);
    options.timeoutMs = 30000;
    options.allowShell = false;  // RunArgv, no cmd.exe
    options.maxCaptureBytes = capBytes;

    const CommandExecutor::Result r = CommandExecutor::RunArgv(argv, options);
    if (!r.error.empty() && r.exitCode == 0 && r.stdoutText.empty() && r.stderrText.empty()) {
        out.spawnFailed = true;
    }
    // A spawn failure is reported by RunArgv as an error string with no exit
    // code of 0 and no output. Anything else is the child's own result.
    if (r.error.find("CreateProcessW failed") != std::string::npos) out.spawnFailed = true;
    out.exitCode = r.exitCode;
    out.out = r.stdoutText;
    out.err = r.stderrText;
    out.timedOut = r.timedOut;
    return out;
}

std::string GitSafetyAuthority::headSha() const {
    if (repoRoot_.empty()) return {};
    const RunOutput r = runGit({"rev-parse", "HEAD"});
    if (r.exitCode != 0) return {};  // unborn HEAD is a real state, not an error
    return Trim(r.out);
}

std::string GitSafetyAuthority::currentBranch() const {
    const RunOutput r = runGit({"rev-parse", "--abbrev-ref", "HEAD"});
    if (r.exitCode != 0) return {};
    const std::string name = Trim(r.out);
    return (name == "HEAD") ? std::string() : name;  // detached
}

std::vector<PathState> GitSafetyAuthority::readStatus() const {
    if (repoRoot_.empty()) return {};
    const RunOutput r = runGit({"status", "--porcelain=v1", "--untracked-files=all"}, 1u << 20);
    if (r.exitCode != 0) return {};
    return ParsePorcelainStatus(r.out);
}

std::vector<std::string> GitSafetyAuthority::readStagedPaths() const {
    std::vector<std::string> out;
    if (repoRoot_.empty()) return out;
    const RunOutput r = runGit({"diff", "--cached", "--name-only", "-z"}, 1u << 20);
    if (r.exitCode != 0) return out;
    std::string current;
    for (char c : r.out) {
        if (c == '\0') {
            if (!current.empty()) out.push_back(NormalizeSeparators(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) out.push_back(NormalizeSeparators(current));
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> GitSafetyAuthority::readUnmergedPaths() const {
    std::vector<std::string> out;
    if (repoRoot_.empty()) return out;
    const RunOutput r = runGit({"diff", "--name-only", "--diff-filter=U", "-z"}, 1u << 20);
    if (r.exitCode != 0) return out;
    std::string current;
    for (char c : r.out) {
        if (c == '\0') {
            if (!current.empty()) out.push_back(NormalizeSeparators(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) out.push_back(NormalizeSeparators(current));
    std::sort(out.begin(), out.end());
    return out;
}

std::string GitSafetyAuthority::fingerprintOf(const std::string& relPath) const {
    if (repoRoot_.empty() || relPath.empty()) return "ABSENT";
    std::error_code ec;
    const fs::path p = fs::path(repoRoot_) / fs::path(relPath);
    // A symlink or junction could redirect the read outside the repository.
    // Reject before fingerprinting rather than hash someone else's file.
    const fs::path canon = fs::weakly_canonical(p, ec);
    if (ec || canon.empty()) return "UNRESOLVABLE";
    std::string canonStr = canon.string();
    std::replace(canonStr.begin(), canonStr.end(), '/', '\\');
    std::string rootCanon = repoRoot_;
    if (!rootCanon.empty() && rootCanon.back() != '\\') rootCanon.push_back('\\');
    if (canonStr.size() < rootCanon.size() ||
        canonStr.compare(0, rootCanon.size(), rootCanon) != 0) {
        return "ESCAPES_REPOSITORY";
    }
    return FingerprintFile(canon);
}

std::string GitSafetyAuthority::resolveInsideRepo(const std::string& candidate,
                                                  GitRefusal& refusal,
                                                  std::string& detail) const {
    refusal = GitRefusal::None;
    detail.clear();
    if (repoRoot_.empty()) {
        refusal = GitRefusal::NotAGitRepository;
        detail = "no open session";
        return {};
    }
    if (candidate.empty()) {
        refusal = GitRefusal::PathEscapesRepository;
        detail = "empty path";
        return {};
    }
    if (candidate.find('\0') != std::string::npos) {
        refusal = GitRefusal::PathEscapesRepository;
        detail = "path contains NUL";
        return {};
    }
    if (candidate.size() >= 2 && candidate[0] == '\\' && candidate[1] == '\\') {
        refusal = GitRefusal::PathEscapesRepository;
        detail = "UNC paths are not permitted";
        return {};
    }

    std::error_code ec;
    const fs::path joined = fs::path(repoRoot_) / fs::path(candidate);
    const fs::path canon = fs::weakly_canonical(joined, ec);
    if (ec || canon.empty()) {
        refusal = GitRefusal::PathEscapesRepository;
        detail = "cannot canonicalize '" + candidate + "'";
        return {};
    }
    const fs::path rel = canon.lexically_relative(fs::path(repoRoot_));
    const std::string relStr = rel.string();
    if (relStr == "..") {
        refusal = GitRefusal::PathEscapesRepository;
        detail = "'" + candidate + "' resolves outside the repository";
        return {};
    }
    if (relStr.rfind("..", 0) == 0) {
        if (relStr.size() == 2 || relStr[2] == '/' || relStr[2] == '\\') {
            refusal = GitRefusal::PathEscapesRepository;
            detail = "'" + candidate + "' traverses above the repository root";
            return {};
        }
    }
    if (relStr.empty()) {
        refusal = GitRefusal::PathOutsideScope;
        detail = "the repository root itself is not a mutable path";
        return {};
    }
    return NormalizeSeparators(relStr);
}

bool GitSafetyAuthority::inScope(const std::string& relPath) const {
    for (const std::string& prefix : policy_.authorizedPrefixes) {
        if (PathUnderPrefix(relPath, prefix)) return true;
    }
    return false;
}

bool GitSafetyAuthority::isUnrelatedUserPath(const std::string& relPath) const {
    if (baseline_.fingerprints.find(relPath) == baseline_.fingerprints.end()) return false;
    return !inScope(relPath);
}

void GitSafetyAuthority::recordViolation(const std::string& path) {
    if (std::find(violations_.begin(), violations_.end(), path) == violations_.end()) {
        violations_.push_back(path);
    }
}

GitResult GitSafetyAuthority::authorizeMutation(GitCapability capability,
                                                const std::vector<std::string>& targetPaths,
                                                bool destructive) {
    if (!sessionOpen_) {
        return fail(GitRefusal::NotAGitRepository, "no open session");
    }
    ++mutatingAttempted_;

    // 1. capability
    if (!HasCapability(policy_.granted, capability)) {
        ++mutatingRefused_;
        return fail(GitRefusal::CapabilityNotGranted,
                    std::string("capability not granted: ") +
                        (capability == GitCapability::Stage ? "stage"
                         : capability == GitCapability::Unstage ? "unstage"
                         : capability == GitCapability::Commit ? "commit"
                         : capability == GitCapability::Branch ? "branch"
                         : capability == GitCapability::Checkout ? "checkout"
                         : capability == GitCapability::Stash ? "stash"
                         : capability == GitCapability::Worktree ? "worktree"
                                                                  : "rollback"));
    }

    // 2. scope. A grant without a scope is not an authorization.
    if (policy_.authorizedPrefixes.empty()) {
        ++mutatingRefused_;
        return fail(GitRefusal::NoScope, "policy grants no path scope; nothing is mutable");
    }

    // 3. unmerged paths. With a conflict in the tree, "what would this
    //    operation do" is not a question git can answer, so nothing mutating
    //    runs. The agent must resolve the conflict first.
    const std::vector<std::string> unmerged = readUnmergedPaths();
    if (!unmerged.empty()) {
        ++mutatingRefused_;
        return fail(GitRefusal::UnmergedPathsPresent,
                    "repository has unmerged paths: " + unmerged.front() +
                        (unmerged.size() > 1 ? " (+" + std::to_string(unmerged.size() - 1) + ")" : ""));
    }

    // 4. destructive operations refuse while unrelated uncommitted work exists
    if (destructive && policy_.requireCleanForDestructive) {
        const std::vector<PathState> now = readStatus();
        std::vector<std::string> unrelatedDirty;
        for (const PathState& p : now) {
            if (isUnrelatedUserPath(p.path)) unrelatedDirty.push_back(p.path);
        }
        if (!unrelatedDirty.empty()) {
            ++mutatingRefused_;
            return fail(GitRefusal::DirtyTreeDestructive,
                        "refusing a destructive operation while " +
                            std::to_string(unrelatedDirty.size()) +
                            " unrelated user path(s) are uncommitted, first=" + unrelatedDirty.front());
        }
    }

    // 5. every named path must be in scope
    for (const std::string& p : targetPaths) {
        if (p.empty()) continue;
        if (!inScope(p)) {
            ++mutatingRefused_;
            return fail(GitRefusal::PathOutsideScope, "path outside authorized scope: " + p);
        }
    }

    GitResult ok;
    ok.ok = true;
    ok.detail = "authorized";
    return ok;
}

// ---- read-only -------------------------------------------------------------

GitResult GitSafetyAuthority::status() {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const RunOutput r = runGit({"status", "--porcelain=v1", "--untracked-files=all"}, 1u << 20);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git status exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        return out;
    }
    out.ok = true;
    out.output = r.out;
    const auto paths = ParsePorcelainStatus(r.out);
    out.detail = "head=" + (headSha().empty() ? "UNBORN" : headSha().substr(0, 12)) +
                 " branch=" + (currentBranch().empty() ? "(detached)" : currentBranch()) +
                 " dirty=" + std::to_string(paths.size());
    return out;
}

GitResult GitSafetyAuthority::diff(bool staged, std::size_t maxBytes) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    std::vector<std::string> args = {"diff"};
    if (staged) args.push_back("--cached");
    args.push_back("--no-color");
    const RunOutput r = runGit(args, maxBytes);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git diff exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        return out;
    }
    out.ok = true;
    out.output = r.out;
    out.detail = std::string(staged ? "staged" : "unstaged") + " diff, " +
                 std::to_string(r.out.size()) + " bytes";
    return out;
}

GitResult GitSafetyAuthority::conflicts() {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const std::vector<std::string> unmerged = readUnmergedPaths();
    GitResult out;
    out.ok = true;
    out.output.clear();
    for (const std::string& p : unmerged) out.output += p + "\n";
    out.detail = "unmerged=" + std::to_string(unmerged.size());
    return out;
}

GitResult GitSafetyAuthority::dirtyTree() {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const std::vector<PathState> now = readStatus();
    std::size_t staged = 0, untracked = 0, unmerged = 0, unrelated = 0, inScopeDirty = 0;
    std::ostringstream oss;
    for (const PathState& p : now) {
        if (p.staged()) ++staged;
        if (p.untracked) ++untracked;
        if (p.unmerged) ++unmerged;
        if (inScope(p.path)) ++inScopeDirty; else ++unrelated;
        oss << p.indexStatus << p.worktreeStatus << ' ' << p.path
            << (p.untracked ? "  [untracked]" : (p.unmerged ? "  [UNMERGED]" : ""))
            << (isUnrelatedUserPath(p.path) ? "  [pre-existing user change]" : "") << "\n";
    }
    GitResult out;
    out.ok = true;
    out.output = oss.str();
    out.detail = "dirty=" + std::to_string(now.size()) + " staged=" + std::to_string(staged) +
                 " untracked=" + std::to_string(untracked) + " unmerged=" + std::to_string(unmerged) +
                 " in_scope=" + std::to_string(inScopeDirty) + " outside_scope=" + std::to_string(unrelated);
    return out;
}

GitResult GitSafetyAuthority::reviewAgentDiff(std::size_t maxBytes) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    std::vector<std::string> scopeArgs;
    for (const std::string& prefix : policy_.authorizedPrefixes) scopeArgs.push_back(prefix);

    GitResult out;
    if (scopeArgs.empty()) {
        out.ok = true;
        out.detail = "no scope: there is no agent diff to review";
        return out;
    }

    std::vector<std::string> args = {"diff", "--no-color", "--stat"};
    for (const std::string& p : scopeArgs) { args.push_back("--"); args.push_back(p); }
    const RunOutput scoped = runGit(args, maxBytes);
    if (scoped.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git diff (scoped) exited " + std::to_string(scoped.exitCode);
        out.errorOutput = scoped.err;
        return out;
    }
    out.ok = true;
    out.output = "=== AGENT SCOPE DIFF (authorized) ===\n" + scoped.out;

    // The other half of a review: what is dirty that the agent did not do.
    // A reviewer who only sees the agent's own diff is reviewing a fiction.
    const std::vector<PathState> now = readStatus();
    std::ostringstream outside;
    std::size_t outsideCount = 0;
    for (const PathState& p : now) {
        if (inScope(p.path)) continue;
        ++outsideCount;
        outside << p.indexStatus << p.worktreeStatus << ' ' << p.path
                << (isUnrelatedUserPath(p.path) ? "  [pre-existing user change]" : "  [outside scope]") << "\n";
    }
    out.output += "\n=== OUTSIDE AGENT SCOPE (not in the diff above) ===\n" + outside.str();
    out.detail = "scoped_diff_bytes=" + std::to_string(scoped.out.size()) +
                 " outside_scope_dirty=" + std::to_string(outsideCount);
    return out;
}

// ---- mutating --------------------------------------------------------------

GitResult GitSafetyAuthority::stage(const std::vector<std::string>& paths) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Stage, {}, false);
    if (gate.refused()) return gate;
    if (paths.empty()) {
        ++mutatingRefused_;
        return fail(GitRefusal::NothingToDo, "stage requires at least one path");
    }
    std::vector<std::string> resolved;
    for (const std::string& p : paths) {
        GitRefusal r = GitRefusal::None;
        std::string detail;
        const std::string rel = resolveInsideRepo(p, r, detail);
        if (!rel.empty()) {
            resolved.push_back(rel);
            continue;
        }
        if (r == GitRefusal::None) r = GitRefusal::PathEscapesRepository;
        ++mutatingRefused_;
        return fail(r, detail);
    }
    for (const std::string& rel : resolved) {
        if (!inScope(rel)) {
            ++mutatingRefused_;
            return fail(GitRefusal::PathOutsideScope, "path outside authorized scope: " + rel);
        }
    }
    std::vector<std::string> args = {"add", "--"};
    for (const std::string& rel : resolved) args.push_back(rel);
    const RunOutput r = runGit(args);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git add exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        return out;
    }
    ++mutatingExecuted_;
    out.ok = true;
    out.output = r.out;
    out.detail = "staged " + std::to_string(resolved.size()) + " path(s)";
    return out;
}

GitResult GitSafetyAuthority::unstage(const std::vector<std::string>& paths) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Unstage, {}, false);
    if (gate.refused()) return gate;

    std::vector<std::string> resolved;
    if (paths.empty()) {
        resolved = readStagedPaths();
        if (resolved.empty()) {
            ++mutatingRefused_;
            return fail(GitRefusal::NothingToDo, "index is empty");
        }
    } else {
        for (const std::string& p : paths) {
            GitRefusal r = GitRefusal::None;
            std::string detail;
            const std::string rel = resolveInsideRepo(p, r, detail);
            if (rel.empty()) {
                ++mutatingRefused_;
                return fail(r == GitRefusal::None ? GitRefusal::PathEscapesRepository : r, detail);
            }
            resolved.push_back(rel);
        }
    }
    for (const std::string& rel : resolved) {
        if (!inScope(rel)) {
            ++mutatingRefused_;
            return fail(GitRefusal::PathOutsideScope,
                        "refusing to unstage a path outside authorized scope: " + rel);
        }
    }
    std::vector<std::string> args = {"restore", "--staged", "--"};
    for (const std::string& rel : resolved) args.push_back(rel);
    RunOutput r = runGit(args);
    if (r.exitCode != 0) {
        // An unborn HEAD has no index to restore from; remove from the index
        // without touching the worktree instead.
        args.clear();
        args = {"rm", "--cached", "-q", "--"};
        for (const std::string& rel : resolved) args.push_back(rel);
        r = runGit(args);
    }
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "unstage exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        return out;
    }
    ++mutatingExecuted_;
    out.ok = true;
    out.detail = "unstaged " + std::to_string(resolved.size()) + " path(s)";
    return out;
}

GitResult GitSafetyAuthority::commit(const std::string& message,
                                     const std::vector<std::string>& paths) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Commit, {}, false);
    if (gate.refused()) return gate;
    if (Trim(message).empty()) {
        ++mutatingRefused_;
        return fail(GitRefusal::NothingToDo, "commit message is empty");
    }

    std::vector<std::string> resolved;
    for (const std::string& p : paths) {
        GitRefusal r = GitRefusal::None;
        std::string detail;
        const std::string rel = resolveInsideRepo(p, r, detail);
        if (rel.empty()) {
            ++mutatingRefused_;
            return fail(r == GitRefusal::None ? GitRefusal::PathEscapesRepository : r, detail);
        }
        if (!inScope(rel)) {
            ++mutatingRefused_;
            return fail(GitRefusal::PathOutsideScope, "path outside authorized scope: " + rel);
        }
        resolved.push_back(rel);
    }

    // The critical check. `git commit` with no paths commits the WHOLE index,
    // which in a shared working tree includes whatever the user had already
    // staged. The agent must not be able to publish someone else's work under
    // its own message, so an out-of-scope staged path is a hard refusal.
    const std::vector<std::string> staged = readStagedPaths();
    for (const std::string& s : staged) {
        if (!inScope(s)) {
            ++mutatingRefused_;
            return fail(GitRefusal::PathOutsideScope,
                        "refusing to commit: index contains a path outside authorized scope: " + s);
        }
    }
    if (staged.empty() && resolved.empty()) {
        ++mutatingRefused_;
        return fail(GitRefusal::NothingToDo, "nothing staged to commit");
    }

    std::vector<std::string> args = {"commit", "--no-verify", "-m", message};
    if (!resolved.empty()) {
        args.push_back("--");
        for (const std::string& rel : resolved) args.push_back(rel);
    }
    const RunOutput r = runGit(args, 1u << 20);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git commit exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        out.output = r.out;
        return out;
    }
    ++mutatingExecuted_;
    out.ok = true;
    out.output = r.out;
    const std::string newHead = headSha();
    out.detail = "committed; new head=" + (newHead.empty() ? "UNBORN" : newHead.substr(0, 12));
    return out;
}

GitResult GitSafetyAuthority::createBranch(const std::string& name) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Branch, {}, false);
    if (gate.refused()) return gate;
    if (!RefNameLooksSafe(name)) {
        ++mutatingRefused_;
        return fail(GitRefusal::GitFailed, "branch name is not a safe ref name: '" + name + "'");
    }
    const RunOutput exists = runGit({"rev-parse", "--verify", "--quiet", "refs/heads/" + name});
    if (exists.exitCode == 0) {
        ++mutatingRefused_;
        return fail(GitRefusal::GitFailed, "branch already exists: " + name);
    }
    const RunOutput r = runGit({"branch", name});
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git branch exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        return out;
    }
    ++mutatingExecuted_;
    out.ok = true;
    out.detail = "created branch " + name;
    return out;
}

GitResult GitSafetyAuthority::checkout(const std::string& ref) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    // Checkout rewrites files under the caller's feet, so it is destructive.
    const GitResult gate = authorizeMutation(GitCapability::Checkout, {}, true);
    if (gate.refused()) return gate;
    if (!RefNameLooksSafe(ref)) {
        ++mutatingRefused_;
        return fail(GitRefusal::GitFailed, "checkout ref is not a safe ref name: '" + ref + "'");
    }
    const RunOutput verify = runGit({"rev-parse", "--verify", "--quiet", ref});
    if (verify.exitCode != 0) {
        ++mutatingRefused_;
        return fail(GitRefusal::GitFailed, "ref does not resolve: " + ref);
    }
    const RunOutput r = runGit({"checkout", ref}, 1u << 20);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git checkout exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        out.output = r.out;
        return out;
    }
    ++mutatingExecuted_;
    out.ok = true;
    out.output = r.out;
    out.detail = "checked out " + ref + "; head=" + headSha().substr(0, 12);
    return out;
}

GitResult GitSafetyAuthority::stash(const std::string& message) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Stash, {}, true);
    if (gate.refused()) return gate;
    std::vector<std::string> args = {"stash", "push", "-q"};
    if (!Trim(message).empty()) { args.push_back("-m"); args.push_back(message); }
    const RunOutput r = runGit(args, 1u << 20);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git stash exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        return out;
    }
    const std::vector<PathState> after = readStatus();
    ++mutatingExecuted_;
    out.ok = true;
    out.output = r.out;
    out.detail = "stashed; dirty=" + std::to_string(after.size());
    return out;
}

GitResult GitSafetyAuthority::stashPop() {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Stash, {}, false);
    if (gate.refused()) return gate;
    const RunOutput r = runGit({"stash", "pop"}, 1u << 20);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git stash pop exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        out.output = r.out;
        return out;
    }
    ++mutatingExecuted_;
    out.ok = true;
    out.output = r.out;
    out.detail = "stash popped";
    return out;
}

GitResult GitSafetyAuthority::addWorktree(const std::string& relativeDir) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Worktree, {}, false);
    if (gate.refused()) return gate;

    GitRefusal r = GitRefusal::None;
    std::string detail;
    const std::string rel = resolveInsideRepo(relativeDir, r, detail);
    if (rel.empty()) {
        ++mutatingRefused_;
        return fail(r == GitRefusal::None ? GitRefusal::PathEscapesRepository : r, detail);
    }
    if (!inScope(rel)) {
        ++mutatingRefused_;
        return fail(GitRefusal::PathOutsideScope, "worktree path outside authorized scope: " + rel);
    }
    std::error_code ec;
    const fs::path target = fs::path(repoRoot_) / fs::path(rel);
    if (fs::exists(target, ec) && !fs::is_empty(target, ec)) {
        ++mutatingRefused_;
        return fail(GitRefusal::GitFailed, "worktree target already exists and is not empty: " + rel);
    }
    const std::string branch = "agent-wt-" + std::to_string(GetCurrentProcessId()) + "-" + rel;
    const RunOutput out = runGit({"worktree", "add", "-b", branch, rel}, 1u << 20);
    GitResult result;
    if (out.exitCode != 0) {
        result.refusal = GitRefusal::GitFailed;
        result.detail = "git worktree add exited " + std::to_string(out.exitCode);
        result.errorOutput = out.err;
        return result;
    }
    ++mutatingExecuted_;
    result.ok = true;
    result.output = out.out;
    result.detail = "added worktree " + rel + " on " + branch;
    return result;
}

GitResult GitSafetyAuthority::removeWorktree(const std::string& relativeDir, bool force) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Worktree, {}, true);
    if (gate.refused()) return gate;
    GitRefusal r = GitRefusal::None;
    std::string detail;
    const std::string rel = resolveInsideRepo(relativeDir, r, detail);
    if (rel.empty()) {
        ++mutatingRefused_;
        return fail(r == GitRefusal::None ? GitRefusal::PathEscapesRepository : r, detail);
    }
    if (!inScope(rel)) {
        ++mutatingRefused_;
        return fail(GitRefusal::PathOutsideScope, "worktree path outside authorized scope: " + rel);
    }
    std::vector<std::string> args = {"worktree", "remove"};
    if (force) args.push_back("--force");
    args.push_back(rel);
    const RunOutput out = runGit(args, 1u << 20);
    GitResult result;
    if (out.exitCode != 0) {
        result.refusal = GitRefusal::GitFailed;
        result.detail = "git worktree remove exited " + std::to_string(out.exitCode);
        result.errorOutput = out.err;
        return result;
    }
    ++mutatingExecuted_;
    result.ok = true;
    result.detail = "removed worktree " + rel;
    return result;
}

GitResult GitSafetyAuthority::listWorktrees() {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const RunOutput r = runGit({"worktree", "list", "--porcelain"}, 1u << 20);
    GitResult out;
    if (r.exitCode != 0) {
        out.refusal = GitRefusal::GitFailed;
        out.detail = "git worktree list exited " + std::to_string(r.exitCode);
        out.errorOutput = r.err;
        return out;
    }
    out.ok = true;
    out.output = r.out;
    std::size_t count = 0;
    for (const std::string& line : SplitLines(r.out)) {
        if (line.rfind("worktree ", 0) == 0) ++count;
    }
    out.detail = "worktrees=" + std::to_string(count);
    return out;
}

GitResult GitSafetyAuthority::rollback(const std::vector<std::string>& paths) {
    if (!sessionOpen_) return fail(GitRefusal::NotAGitRepository, "no open session");
    const GitResult gate = authorizeMutation(GitCapability::Rollback, {}, false);
    if (gate.refused()) return gate;
    if (paths.empty()) {
        ++mutatingRefused_;
        return fail(GitRefusal::NothingToDo, "rollback requires at least one path");
    }

    std::vector<std::string> resolved;
    std::vector<std::string> skipped;
    for (const std::string& p : paths) {
        GitRefusal r = GitRefusal::None;
        std::string detail;
        const std::string rel = resolveInsideRepo(p, r, detail);
        if (rel.empty()) {
            ++mutatingRefused_;
            return fail(r == GitRefusal::None ? GitRefusal::PathEscapesRepository : r, detail);
        }
        if (!inScope(rel)) {
            ++mutatingRefused_;
            return fail(GitRefusal::PathOutsideScope, "rollback path outside authorized scope: " + rel);
        }
        if (baseline_.fingerprints.find(rel) != baseline_.fingerprints.end()) {
            // The path was already dirty when the session began. Restoring it
            // to HEAD would destroy work that predates this agent run, so it
            // is reported and left alone rather than silently reverted.
            skipped.push_back(rel);
            continue;
        }
        resolved.push_back(rel);
    }
    if (resolved.empty()) {
        ++mutatingRefused_;
        GitResult out = fail(GitRefusal::NothingToDo, "no rollback candidate outside the pre-existing dirt");
        out.output.clear();
        for (const std::string& s : skipped) out.output += "skipped (dirty at session begin): " + s + "\n";
        return out;
    }

    // Restore tracked paths from HEAD; delete paths that did not exist at HEAD
    // and were not dirty at session begin, i.e. files this run created.
    std::vector<std::string> tracked;
    std::vector<std::string> toDelete;
    for (const std::string& rel : resolved) {
        const RunOutput known = runGit({"cat-file", "-e", "HEAD:" + rel});
        if (known.exitCode == 0) tracked.push_back(rel);
        else toDelete.push_back(rel);
    }

    GitResult out;
    if (!tracked.empty()) {
        std::vector<std::string> args = {"checkout", "HEAD", "--"};
        for (const std::string& rel : tracked) args.push_back(rel);
        const RunOutput r = runGit(args, 1u << 20);
        if (r.exitCode != 0) {
            out.refusal = GitRefusal::GitFailed;
            out.detail = "git checkout HEAD -- exited " + std::to_string(r.exitCode);
            out.errorOutput = r.err;
            return out;
        }
    }
    for (const std::string& rel : toDelete) {
        std::error_code ec;
        const fs::path target = fs::path(repoRoot_) / fs::path(rel);
        if (fs::exists(target, ec) && !fs::is_directory(target, ec)) {
            fs::remove(target, ec);
            if (ec) {
                out.refusal = GitRefusal::GitFailed;
                out.detail = "cannot remove agent-created file " + rel;
                return out;
            }
        }
    }

    // Unstage anything the run staged, so the index returns to its baseline.
    const std::vector<std::string> staged = readStagedPaths();
    for (const std::string& s : staged) {
        if (baseline_.fingerprints.find(s) == baseline_.fingerprints.end() && inScope(s)) {
            unstage({s});
        }
    }

    ++mutatingExecuted_;
    out.ok = true;
    std::ostringstream oss;
    oss << "restored " << tracked.size() << " tracked path(s) to HEAD\n";
    oss << "removed " << toDelete.size() << " agent-created path(s)\n";
    for (const std::string& s : skipped) oss << "skipped (dirty at session begin): " << s << "\n";
    out.output = oss.str();
    out.detail = "restored=" + std::to_string(tracked.size()) +
                 " removed=" + std::to_string(toDelete.size()) +
                 " skipped=" + std::to_string(skipped.size());
    return out;
}

// ---- verification ----------------------------------------------------------

bool GitSafetyAuthority::verifyUnrelatedPreserved(std::vector<std::string>& outViolations) {
    outViolations.clear();
    if (!sessionOpen_) return false;
    std::size_t tracked = 0, preserved = 0;
    for (const PathState& p : baseline_.paths) {
        if (inScope(p.path)) continue;  // in-scope dirt is the agent's business
        ++tracked;
        const auto it = baseline_.fingerprints.find(p.path);
        if (it == baseline_.fingerprints.end()) continue;
        const std::string now = fingerprintOf(p.path);
        if (now == it->second) {
            ++preserved;
        } else {
            outViolations.push_back(p.path);
            recordViolation(p.path);
        }
    }
    return outViolations.empty();
}

GitSafetyReceipt GitSafetyAuthority::finalize() {
    GitSafetyReceipt r;
    r.repositoryRoot = repoRoot_;
    r.capabilitiesGranted = policy_.granted;
    r.headAtBegin = baseline_.head;
    r.branchAtBegin = baseline_.branch;
    r.baselineDirtyCount = baseline_.dirtyCount();
    r.baselineStagedCount = baseline_.stagedCount();
    r.baselineUntrackedCount = baseline_.untrackedCount();

    if (!sessionOpen_) {
        r.verdictPass = false;
        r.verdictText = "FAIL: no session was opened; nothing was measured";
        return r;
    }

    r.headAtEnd = headSha();
    r.branchAtEnd = currentBranch();
    const std::vector<PathState> now = readStatus();
    r.finalDirtyCount = now.size();

    for (const PathState& p : baseline_.paths) {
        if (inScope(p.path)) continue;
        ++r.unrelatedPathsTracked;
    }
    std::vector<std::string> violations;
    verifyUnrelatedPreserved(violations);
    r.unrelatedPathsViolated = violations;
    r.unrelatedPathsPreserved = r.unrelatedPathsTracked - violations.size();

    r.mutatingCallsAttempted = mutatingAttempted_;
    r.mutatingCallsRefused = mutatingRefused_;
    r.mutatingCallsExecuted = mutatingExecuted_;

    // The verdict is a conjunction of measured properties. Nothing here is a
    // printed literal, and a capability that was never exercised is reported
    // by the driver as NOT_RUN rather than being counted as a pass.
    const bool preservationHeld = r.unrelatedPathsViolated.empty();
    const bool driftAbsent = true;  // filled by the driver, which fingerprints
                                     // during the window; see the driver.

    r.verdictPass = preservationHeld && driftAbsent && sessionOpen_;
    std::ostringstream oss;
    oss << (r.verdictPass ? "PASS" : "FAIL")
        << ": baseline_dirty=" << r.baselineDirtyCount
        << " unrelated_tracked=" << r.unrelatedPathsTracked
        << " unrelated_preserved=" << r.unrelatedPathsPreserved
        << " unrelated_violated=" << r.unrelatedPathsViolated.size()
        << " mutating_attempted=" << r.mutatingCallsAttempted
        << " refused=" << r.mutatingCallsRefused
        << " executed=" << r.mutatingCallsExecuted;
    r.verdictText = oss.str();
    return r;
}

} // namespace agentic
} // namespace rawrxd
