#pragma once

#include "modelgenie/universal_gguf.hpp"

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

namespace RawrXD::Deep2 {

enum class ProvenanceVerificationState { Pending, Verifying, Verified, Failed, Cancelled };

class ModelProvenanceVerifier final {
public:
    ModelProvenanceVerifier() = default;
    ~ModelProvenanceVerifier() { Cancel(); Join(); }
    ModelProvenanceVerifier(const ModelProvenanceVerifier&) = delete;
    ModelProvenanceVerifier& operator=(const ModelProvenanceVerifier&) = delete;

    bool Start(const std::string& path, const std::string& trusted_sha256) {
        std::error_code ec;
        const auto p = std::filesystem::absolute(path, ec);
        if (ec || !std::filesystem::is_regular_file(p, ec) || trusted_sha256.size() != 64)
            return false;
        std::lock_guard<std::mutex> lock(mu_);
        if (worker_.joinable()) return false;
        path_ = p.string();
        trusted_ = trusted_sha256;
        identity_size_ = std::filesystem::file_size(p, ec);
        identity_time_ = std::filesystem::last_write_time(p, ec);
        if (ec) return false;
        cancel_.store(false, std::memory_order_release);
        state_ = ProvenanceVerificationState::Pending;
        error_.clear();
        worker_ = std::thread(&ModelProvenanceVerifier::Run, this);
        return true;
    }

    void Cancel() noexcept { cancel_.store(true, std::memory_order_release); }
    void Join() noexcept { if (worker_.joinable()) worker_.join(); }

    bool WaitVerified() noexcept {
        Join();
        return Verified();
    }

    ProvenanceVerificationState State() const noexcept {
        std::lock_guard<std::mutex> lock(mu_); return state_;
    }
    bool Verified() const noexcept { return State() == ProvenanceVerificationState::Verified; }
    std::string Error() const { std::lock_guard<std::mutex> lock(mu_); return error_; }

private:
    void Set(ProvenanceVerificationState s, std::string e = {}) {
        { std::lock_guard<std::mutex> lock(mu_); state_ = s; error_ = std::move(e); }
        cv_.notify_all();
    }
    void Run() {
        Set(ProvenanceVerificationState::Verifying);
        std::error_code ec;
        const auto p = std::filesystem::path(path_);
        const auto before_size = std::filesystem::file_size(p, ec);
        const auto before_time = std::filesystem::last_write_time(p, ec);
        if (ec || before_size != identity_size_ || before_time != identity_time_) {
            Set(ProvenanceVerificationState::Failed, "model identity changed before hashing"); return;
        }
        const std::string actual = Universal::Sha256File(path_);
        if (cancel_.load(std::memory_order_acquire)) {
            Set(ProvenanceVerificationState::Cancelled); return;
        }
        const auto after_size = std::filesystem::file_size(p, ec);
        const auto after_time = std::filesystem::last_write_time(p, ec);
        if (ec || after_size != identity_size_ || after_time != identity_time_) {
            Set(ProvenanceVerificationState::Failed, "model identity changed during hashing"); return;
        }
        if (actual.empty() || actual.size() != 64 || actual != trusted_) {
            Set(ProvenanceVerificationState::Failed, "trusted SHA-256 mismatch"); return;
        }
        Set(ProvenanceVerificationState::Verified);
    }

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::thread worker_;
    std::atomic<bool> cancel_{false};
    ProvenanceVerificationState state_{ProvenanceVerificationState::Pending};
    std::string path_, trusted_, error_;
    uintmax_t identity_size_ = 0;
    std::filesystem::file_time_type identity_time_{};
};

} // namespace RawrXD::Deep2
