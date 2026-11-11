#pragma once

// Per-user-turn MOTD authorization for model-originated tool dispatch.
// The state is deliberately in-memory and bound to (session, turn, SHA-256).
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#endif

namespace rawrxd::agentic {

class MotdAuthorization {
public:
    enum class State {
        Standby,
        TurnStart,
        MotdRead,
        Acknowledged,
        ToolAuthorized,
        Execution,
        Revoked
    };

    class TurnGuard {
    public:
        TurnGuard(const TurnGuard&) = delete;
        TurnGuard& operator=(const TurnGuard&) = delete;
        TurnGuard(TurnGuard&& other) noexcept
            : owner_(std::exchange(other.owner_, nullptr)),
              sessionId_(std::move(other.sessionId_)), turnId_(other.turnId_) {}
        TurnGuard& operator=(TurnGuard&&) = delete;
        ~TurnGuard() { if (owner_) owner_->EndTurn(sessionId_, turnId_); }
    private:
        friend class MotdAuthorization;
        TurnGuard(MotdAuthorization& owner, std::string sessionId, uint64_t turnId)
            : owner_(&owner), sessionId_(std::move(sessionId)), turnId_(turnId) {}
        MotdAuthorization* owner_;
        std::string sessionId_;
        uint64_t turnId_;
    };

    explicit MotdAuthorization(std::filesystem::path workspaceRoot = {})
        : workspaceRoot_(std::move(workspaceRoot)) {}

    void SetWorkspaceRoot(std::filesystem::path workspaceRoot) {
        std::lock_guard<std::mutex> lock(mutex_);
        workspaceRoot_ = std::move(workspaceRoot);
        Reset();
    }

    // Beginning every new user-originated turn invalidates the previous ACK.
    bool BeginTurn(const std::string& sessionId, uint64_t turnId) {
        std::lock_guard<std::mutex> lock(mutex_);
        Reset();
        if (sessionId.empty() || turnId == 0 || workspaceRoot_.empty())
            return false;
        sessionId_ = sessionId;
        turnId_ = turnId;
        state_ = State::TurnStart;
        return true;
    }

    TurnGuard GuardTurn(const std::string& sessionId, uint64_t turnId) {
        return TurnGuard(*this, sessionId, turnId);
    }

    // Explicitly revoke an ACK on normal return and exception unwinding.
    void EndTurn(const std::string& sessionId, uint64_t turnId) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!MatchesTurn(sessionId, turnId)) return;
        sessionId_.clear();
        turnId_ = 0;
        acknowledgedSha256_.clear();
        state_ = State::Revoked;
    }

    // This is the only operation that can acknowledge the MOTD. It reads the
    // configured policy file itself and returns exactly the bytes it hashed.
    bool ReadMotd(const std::string& sessionId, uint64_t turnId,
                  std::string& contents, std::string& sha256,
                  std::string& error) {
        std::lock_guard<std::mutex> lock(mutex_);
        contents.clear();
        sha256.clear();
        error.clear();
        if (!MatchesTurn(sessionId, turnId)) {
            error = "MOTD_TURN_MISMATCH";
            return false;
        }

        if (!LoadPolicy(contents, sha256, error)) return false;

        acknowledgedSha256_ = sha256;
        state_ = State::MotdRead;
        state_ = State::Acknowledged;
        return true;
    }

    // The reserved read_motd tool is available only after BeginTurn. Every
    // other model tool is denied until ReadMotd succeeds in this exact turn.
    bool AuthorizeTool(const std::string& toolName, const std::string& sessionId,
                       uint64_t turnId, std::string& reason) {
        std::lock_guard<std::mutex> lock(mutex_);
        reason.clear();
        if (!MatchesTurn(sessionId, turnId)) {
            reason = "MOTD_REQUIRED: begin a new user turn and read the workspace MOTD";
            return false;
        }
        if (toolName == "read_motd") {
            state_ = State::ToolAuthorized;
            return true;
        }
        if (acknowledgedSha256_.empty() ||
            (state_ != State::Acknowledged && state_ != State::ToolAuthorized &&
             state_ != State::Execution)) {
            reason = "MOTD_REQUIRED: call read_motd before any other tool this turn";
            return false;
        }
        std::string currentContents, currentDigest, currentError;
        if (!LoadPolicy(currentContents, currentDigest, currentError) ||
            currentDigest != acknowledgedSha256_) {
            acknowledgedSha256_.clear();
            state_ = State::TurnStart;
            reason = currentError.empty() ? "MOTD_POLICY_CHANGED: read the current workspace policy again"
                                          : "MOTD_POLICY_UNAVAILABLE: " + currentError;
            return false;
        }
        state_ = State::ToolAuthorized;
        return true;
    }

    void NoteExecution(const std::string& sessionId, uint64_t turnId) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (MatchesTurn(sessionId, turnId) && !acknowledgedSha256_.empty())
            state_ = State::Execution;
    }

    bool IsAcknowledged(const std::string& sessionId, uint64_t turnId) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return MatchesTurn(sessionId, turnId) && !acknowledgedSha256_.empty();
    }

    State GetState() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_;
    }
    std::string GetAcknowledgedHash() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return acknowledgedSha256_;
    }

private:
    static constexpr size_t kMaxMotdBytes = 1024 * 1024;

    std::filesystem::path workspaceRoot_;
    std::string sessionId_;
    uint64_t turnId_ = 0;
    std::string acknowledgedSha256_;
    State state_ = State::Standby;
    mutable std::mutex mutex_;

    void Reset() {
        sessionId_.clear();
        turnId_ = 0;
        acknowledgedSha256_.clear();
        state_ = State::Standby;
    }

    bool MatchesTurn(const std::string& sessionId, uint64_t turnId) const {
        return state_ != State::Standby && !sessionId_.empty() &&
               sessionId == sessionId_ && turnId == turnId_;
    }

    bool LoadPolicy(std::string& contents, std::string& sha256, std::string& error) const {
        contents.clear();
        sha256.clear();
        error.clear();
        std::error_code ec;
        const auto root = std::filesystem::weakly_canonical(workspaceRoot_, ec);
        if (ec || root.empty()) {
            error = "MOTD_WORKSPACE_UNAVAILABLE";
            return false;
        }

        std::filesystem::path policyPath = root / ".cursor" / "rules" / "PassiveRoleNotRoleplay.md";
        if (!std::filesystem::is_regular_file(policyPath, ec) || ec) {
            ec.clear();
            policyPath = root / ".cursor" / "rules" / "PassiveRoleNotRoleplay.mdc";
            if (!std::filesystem::is_regular_file(policyPath, ec) || ec) {
                error = "MOTD_NOT_FOUND";
                return false;
            }
        }

        const auto canonicalPolicy = std::filesystem::canonical(policyPath, ec);
        if (ec || !IsWithinRoot(root, canonicalPolicy)) {
            error = "MOTD_PATH_INVALID";
            return false;
        }

        std::ifstream input(canonicalPolicy, std::ios::binary);
        if (!input) {
            error = "MOTD_READ_FAILED";
            return false;
        }
        contents.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
        if (input.bad() || contents.empty() || contents.size() > kMaxMotdBytes) {
            contents.clear();
            error = "MOTD_CONTENT_INVALID";
            return false;
        }
        if (!ComputeSha256(contents, sha256)) {
            contents.clear();
            error = "MOTD_HASH_FAILED";
            return false;
        }
        return true;
    }

    static bool IsWithinRoot(const std::filesystem::path& root,
                             const std::filesystem::path& file) {
        auto r = root.lexically_normal().generic_string();
        auto f = file.lexically_normal().generic_string();
#ifdef _WIN32
        std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(f.begin(), f.end(), f.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
#endif
        if (!r.empty() && r.back() != '/') r.push_back('/');
        return f.size() >= r.size() && f.compare(0, r.size(), r) == 0;
    }

    static bool ComputeSha256(const std::string& bytes, std::string& hexDigest) {
#ifdef _WIN32
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objectBytes = 0, digestBytes = 0, copied = 0;
        std::vector<UCHAR> objectBuffer;
        std::vector<UCHAR> digest;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status < 0) return false;
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &copied, 0);
        if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&digestBytes), sizeof(digestBytes), &copied, 0);
        if (status >= 0) {
            objectBuffer.resize(objectBytes);
            digest.resize(digestBytes);
            status = BCryptCreateHash(algorithm, &hash, objectBuffer.data(), objectBytes, nullptr, 0, 0);
        }
        if (status >= 0) status = BCryptHashData(hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())),
            static_cast<ULONG>(bytes.size()), 0);
        if (status >= 0) status = BCryptFinishHash(hash, digest.data(), digestBytes, 0);
        if (hash) BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (status < 0) return false;

        static constexpr char kHex[] = "0123456789abcdef";
        hexDigest.clear();
        hexDigest.reserve(digest.size() * 2);
        for (UCHAR byte : digest) {
            hexDigest.push_back(kHex[byte >> 4]);
            hexDigest.push_back(kHex[byte & 0x0f]);
        }
        return true;
#else
        (void)bytes;
        (void)hexDigest;
        return false; // No cryptographic provider: fail closed.
#endif
    }
};

} // namespace rawrxd::agentic
