#pragma once
/**
 * @file SovereignSecurityHardening.hpp
 * @brief At-rest encryption, input validation, and an append-only audit trail.
 *
 * Security surface for the RawrXD IDE, which by design loads arbitrary model
 * files and executes arbitrary commands. The controls here are the minimum
 * set needed to run that safely:
 *
 *   - AES-256-GCM encryption via the Windows CNG (bcrypt) Provider, so state
 *     written to disk (audit records, cached credentials, checkpoints) is not
 *     plaintext. No OpenSSL dependency is introduced for this.
 *   - Key file management: a 256-bit key generated on first use, stored with
 *     restrictive ACLs.
 *   - Input validation for paths, sizes and model extensions.
 *   - Audit logging: append-only, hash-chained, so tampering is detectable.
 *   - Constant-time comparison for anything compared against a secret.
 *
 * Everything is opt-in via config but on by default in production.
 */

#include "SovereignObservability.hpp"
#include "SovereignReliabilityFaultTolerance.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace Sovereign::Production {

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

/// Compares byte ranges without early exit. Returns true when equal.
bool constant_time_equal(std::span<const uint8_t> a, std::span<const uint8_t> b);

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/// Cryptographically secure random bytes from the OS CSPRNG.
bool secure_random(std::span<uint8_t> out);
std::string secure_random_hex(size_t bytes);

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

struct EncryptedBlob {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;      // 12 bytes for GCM
    std::vector<uint8_t> tag;        // 16 bytes
    std::string algorithm = "AES-256-GCM";
    /// Serialized as: version | algorithm | nonce | tag | ciphertext
    std::vector<uint8_t> serialize() const;
    static std::optional<EncryptedBlob> deserialize(
        std::span<const uint8_t> bytes);
};

/// AES-256-GCM via bcrypt. The key is held only in memory for the process
/// lifetime and is never written anywhere except the operator-controlled
/// key file.
class EncryptionManager {
public:
    static EncryptionManager& instance() {
        static EncryptionManager m;
        return m;
    }

    /// Loads (or generates) the 256-bit key. `path` empty means "in-memory
    /// only", which persists nothing and cannot decrypt across restarts.
    bool initialize(const std::string& path);

    bool ready() const { return ready_; }

    std::optional<EncryptedBlob> encrypt(std::span<const uint8_t> plaintext,
                                        std::span<const uint8_t> aad = {});
    /// Returns the plaintext, or nullopt when authentication fails (tampered
    /// ciphertext, wrong key, or truncated data).
    std::optional<std::vector<uint8_t>> decrypt(
        const EncryptedBlob& blob, std::span<const uint8_t> aad = {});

    /// Convenience helpers for text configuration values.
    std::optional<std::string> encrypt_text(const std::string& plaintext);
    std::optional<std::string> decrypt_text(const std::string& base64_blob);

    /// Rotates to a fresh key, re-encrypting `rehome` with it. Returns false
    /// if any rehome fails, leaving the previous key in place.
    bool rotate_key(std::function<bool(const std::vector<uint8_t>& new_key)> rehome);

    bool has_key() const { return ready_; }

    /// False when the key was generated in memory only (no key file), which
    /// means data encrypted with it is unreadable after a restart. Callers
    /// must not persist ciphertext in that mode.
    bool key_is_persistent() const { return ready_ && persistent_; }

private:
    EncryptionManager() = default;
    EncryptionManager(const EncryptionManager&) = delete;
    EncryptionManager& operator=(const EncryptionManager&) = delete;

    bool load_or_create_key(const std::string& path);
    static std::vector<uint8_t> generate_aes_key();

    std::mutex mutex_;
    std::vector<uint8_t> key_;
    bool ready_ = false;
    bool persistent_ = false;
};

// base64 helpers (needed by the text convenience API)
std::string base64_encode(std::span<const uint8_t> data);
std::optional<std::vector<uint8_t>> base64_decode(std::string_view text);

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

struct ValidationOptions {
    std::vector<std::string> allowed_extensions;
    int64_t max_bytes = 8 * 1024 * 1024;
    bool allow_network = true;
    bool allow_devices = false;
};

/// Result of a validated request, carrying either the accepted value or the
/// reason it was refused. Never throws: callers must decide how to fail.
struct ValidationReport {
    bool ok = true;
    std::string reason;
    std::string normalized_path;

    explicit operator bool() const { return ok; }
    ValidationReport& reject(std::string why) {
        if (ok) {
            ok = false;
            reason = std::move(why);
        }
        return *this;
    }
};

class InputValidator {
public:
    explicit InputValidator(ValidationOptions opts);

    /// Validates a model file path: extension whitelist, size cap, and
    /// rejected device/UNC paths.
    ValidationReport validate_model_path(const std::filesystem::path& path);
    /// Validates arbitrary untrusted input length.
    ValidationReport validate_size(std::span<const uint8_t> input);
    /// Rejects control characters and NUL in user-supplied text.
    ValidationReport validate_text(std::string_view text, int64_t max_len);
    /// Validates an integer within a range.
    ValidationReport validate_int(int64_t value, int64_t lo, int64_t hi,
                                 const char* name);

    const ValidationOptions& options() const { return opts_; }

private:
    ValidationOptions opts_;
};

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// Append-only, hash-chained audit record. Each record commits to the
/// previous one, so a truncated or edited log is detectable after the fact.
struct AuditRecord {
    int64_t ts_ms = 0;
    std::string actor;            // who did it (user/service/component)
    std::string action;           // what happened
    std::string resource;         // what it happened to
    std::string outcome;          // success | failure | denied
    std::string detail;
    std::string trace_id;
    std::string prev_hash;        // hash chain link
    std::string hash;             // SHA-256 over the canonical form

    std::string canonical() const;
    std::string to_json() const;
};

class AuditLogger {
public:
    static AuditLogger& instance() {
        static AuditLogger a;
        return a;
    }

    /// Opens (or creates) the append-only log. `encrypt_at_rest` wraps the
    /// canonical JSON through the encryption manager.
    bool initialize(const std::string& dir, bool encrypt_at_rest = true);

    /// Appends a record. Returns false when the write failed; the caller
    /// decides whether that is fatal (it should be for privileged actions).
    bool append(std::string actor, std::string action, std::string resource,
                std::string outcome = "success", std::string detail = {},
                std::string trace_id = {});

    /// Verifies the hash chain. Returns the index of the first broken link,
    /// or nullopt when intact.
    ///
    /// `max_records` bounds the work: the audit log is append-only, so on a
    /// live check it is enough (and fast) to verify the most recent records.
    /// The full chain is verified by the startup readiness gate, where a
    /// one-off full walk is affordable. Pass 0 for an unlimited walk.
    std::optional<size_t> verify_chain(size_t max_records = 0);

    /// Number of records the last bounded verification covered.
    size_t last_verified_records() const { return last_verified_records_; }

    struct Stats {
        uint64_t records = 0;
        uint64_t chain_failures = 0;
        uint64_t bytes_written = 0;
    };
    Stats stats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stats_;
    }

    std::filesystem::path path() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return path_;
    }

    /// Flushes and closes; a subsequent append re-opens and continues the
    /// chain from the last recovered record.
    void close();

private:
    AuditLogger() = default;
    AuditLogger(const AuditLogger&) = delete;
    AuditLogger& operator=(const AuditLogger&) = delete;

    bool recover_last_hash_locked();
    /// Re-opens a closed log and continues the chain. Declared separately
    /// because append() may need to re-open while already holding mutex_.
    bool open_for_append();

    mutable std::mutex mutex_;
    std::filesystem::path path_;
    std::ofstream out_;
    std::string last_hash_;       // empty until the first record is written
    bool encrypt_at_rest_ = false;
    bool initialized_ = false;
    Stats stats_;
    /// How many records the most recent verify_chain() call covered. Used by
    /// the health check to report what was actually checked.
    size_t last_verified_records_ = 0;
};

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Masks secrets in a text blob so it can be logged or shown safely.
std::string redact_secrets(std::string_view text);

// ---------------------------------------------------------------------------
// Security facade
// ---------------------------------------------------------------------------

/// Wires the security components to configuration and registers the health
/// checks, so a broken key or log is visible through the health endpoint.
class SecurityRuntime {
public:
    static SecurityRuntime& instance() {
        static SecurityRuntime r;
        return r;
    }

    /// Idempotent: safe to call from several subsystems' initialisers.
    void init(const ConfigManager& cfg);

    bool is_ready() const { return ready_; }
    InputValidator& validator() { return *validator_; }
    AuditLogger& audit() { return AuditLogger::instance(); }
    EncryptionManager& encryption() { return EncryptionManager::instance(); }

    struct Status {
        bool encryption_ready = false;
        bool audit_ready = false;
        uint64_t audit_records = 0;
        std::optional<size_t> audit_chain_broken_at;
    };
    Status status() const;

private:
    SecurityRuntime() = default;
    SecurityRuntime(const SecurityRuntime&) = delete;
    SecurityRuntime& operator=(const SecurityRuntime&) = delete;

    bool ready_ = false;
    std::unique_ptr<InputValidator> validator_;
};

} // namespace Sovereign::Production
