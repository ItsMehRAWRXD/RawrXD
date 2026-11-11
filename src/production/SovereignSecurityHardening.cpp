#include "SovereignSecurityHardening.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {
// NTSTATUS is a long: negative values are errors and non-negative values are
// successes, which is the whole bail-anything-out semantics bcrypt requires.
inline bool bng_success(NTSTATUS status) {
    return static_cast<long>(status) >= 0;
}
} // namespace

namespace Sovereign::Production {

namespace {

/// Records a health check that found an unhealthy component.
HealthComponent unhealthy(HealthComponent c, std::string detail) {
    c.status = HealthStatus::Unhealthy;
    c.detail = std::move(detail);
    return c;
}

/// Records a health check that found a degraded-but-serving component.
HealthComponent degraded(HealthComponent c, std::string detail) {
    c.status = HealthStatus::Degraded;
    c.detail = std::move(detail);
    return c;
}

// Wire format constants shared by serialize()/deserialize().
constexpr uint8_t kBlobVersion = 1;
constexpr size_t kNonceBytes = 12;
constexpr size_t kTagBytes = 16;

/// How many of the newest audit records a health probe verifies. The audit log
/// is append-only, so verifying the tail is both cheap and sufficient for a
/// per-probe check; the readiness gate walks the whole file at startup.
constexpr size_t kAuditHealthCheckTail = 512;
} // namespace

// ---------------------------------------------------------------------------
// Constant-time comparison and randomness
// ---------------------------------------------------------------------------

bool constant_time_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    // Length is compared first: for secrets of different length the timing
    // difference is irrelevant, and returning early avoids reading past the
    // shorter buffer. Equal lengths then compare without early exit.
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

bool secure_random(std::span<uint8_t> out) {
    if (out.empty()) return true;
    return bng_success(
        BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(out.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

std::string secure_random_hex(size_t bytes) {
    std::vector<uint8_t> buf(bytes);
    if (!secure_random(buf)) return {};
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (uint8_t b : buf) {
        out += digits[(b >> 4) & 0xF];
        out += digits[b & 0xF];
    }
    return out;
}

// ---------------------------------------------------------------------------
// base64
// ---------------------------------------------------------------------------

std::string base64_encode(std::span<const uint8_t> data) {
    static const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        const uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) |
                           static_cast<uint32_t>(data[i + 2]);
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += table[n & 0x3F];
    }
    if (const size_t remaining = data.size() - i) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (remaining == 2) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += (remaining == 2) ? table[(n >> 6) & 0x3F] : '=';
        out += '=';
    }
    return out;
}

std::optional<std::vector<uint8_t>> base64_decode(std::string_view text) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(text.size() / 4 * 3);
    int buffer = 0;
    int bits = 0;
    for (const char c : text) {
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        const int v = value(c);
        if (v < 0) return std::nullopt;
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// EncryptedBlob
// ---------------------------------------------------------------------------

namespace {
// Wire format constants and the line parsers live in the anonymous namespace
// near the top of this file so both the writer and the verifier share them.

/// Parses one audit log line into a record.
///
/// The same helper is used by recovery and verification so both understand
/// every layout the writer can produce: plain JSON, or AES-256-GCM-wrapped
/// base64 when encryption at rest is enabled. Getting this wrong in one place
/// and not the other is exactly how "encrypt at rest" silently disables
/// tamper detection.
std::optional<AuditRecord> parse_audit_line(const std::string& line,
                                            bool encryption_enabled) {
    if (line.empty()) return std::nullopt;

    auto from_json_text = [](const std::string& text)
        -> std::optional<AuditRecord> {
        AuditRecord rec;
        try {
            const auto doc = json::parse(text);
            if (!doc.is_object()) return std::nullopt;
            rec.ts_ms = doc.value("ts", static_cast<int64_t>(0));
            rec.actor = doc.value("actor", std::string{});
            rec.action = doc.value("action", std::string{});
            rec.resource = doc.value("resource", std::string{});
            rec.outcome = doc.value("outcome", std::string{});
            rec.detail = doc.value("detail", std::string{});
            rec.trace_id = doc.value("trace_id", std::string{});
            rec.prev_hash = doc.value("prev_hash", std::string{});
            rec.hash = doc.value("hash", std::string{});
            return rec;
        } catch (...) {
            return std::nullopt;
        }
    };

    // Fast path: a plaintext record is itself the JSON object.
    if (auto direct = from_json_text(line)) return direct;
    if (!encryption_enabled) return std::nullopt;

    // Encrypted path: base64 -> blob -> AES-GCM decrypt -> JSON.
    if (auto wire = base64_decode(line)) {
        if (auto blob = EncryptedBlob::deserialize(*wire)) {
            if (auto plain = EncryptionManager::instance().decrypt(*blob)) {
                const std::string text(plain->begin(), plain->end());
                return from_json_text(text);
            }
        }
    }
    return std::nullopt;
}

std::string audit_record_hash(const std::string& canonical) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    std::vector<uint8_t> hashed(32);
    if (!bng_success(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                                 nullptr, 0))) {
        return {};
    }
    if (!bng_success(BCryptHash(
            alg, nullptr, 0,
            reinterpret_cast<PUCHAR>(const_cast<char*>(canonical.data())),
            static_cast<ULONG>(canonical.size()), hashed.data(),
            static_cast<ULONG>(hashed.size())))) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(hashed.size() * 2);
    for (uint8_t b : hashed) {
        out += digits[(b >> 4) & 0xF];
        out += digits[b & 0xF];
    }
    return out;
}

} // namespace

std::vector<uint8_t> EncryptedBlob::serialize() const {
    std::vector<uint8_t> out;
    out.push_back(kBlobVersion);
    out.insert(out.end(), algorithm.begin(), algorithm.end());
    out.push_back(0);  // NUL terminator keeps the algorithm field readable
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), tag.begin(), tag.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

std::optional<EncryptedBlob> EncryptedBlob::deserialize(std::span<const uint8_t> b) {
    if (b.size() < 1 + 1 + kNonceBytes + kTagBytes) return std::nullopt;
    if (b[0] != kBlobVersion) return std::nullopt;
    size_t pos = 1;
    std::string algorithm;
    while (pos < b.size() && b[pos] != 0) {
        algorithm.push_back(static_cast<char>(b[pos]));
        ++pos;
    }
    if (pos >= b.size()) return std::nullopt;
    ++pos;  // skip the NUL
    if (b.size() < pos + kNonceBytes + kTagBytes) return std::nullopt;

    EncryptedBlob blob;
    blob.algorithm = std::move(algorithm);
    blob.nonce.assign(b.begin() + pos, b.begin() + pos + kNonceBytes);
    pos += kNonceBytes;
    blob.tag.assign(b.begin() + pos, b.begin() + pos + kTagBytes);
    pos += kTagBytes;
    blob.ciphertext.assign(b.begin() + pos, b.end());
    return blob;
}

// ---------------------------------------------------------------------------
// EncryptionManager
// ---------------------------------------------------------------------------

std::vector<uint8_t> EncryptionManager::generate_aes_key() {
    std::vector<uint8_t> key(32);
    if (!secure_random(key)) key.assign(32, 0);
    return key;
}

bool EncryptionManager::load_or_create_key(const std::string& path) {
    if (path.empty()) {
        // In-memory key: nothing to persist, no cross-restart decryption.
        key_ = generate_aes_key();
        persistent_ = false;
        ready_ = !key_.empty();
        return ready_;
    }

    std::error_code ec;
    const fs::path key_path{path};
    const bool exists = fs::exists(key_path, ec);

    std::vector<uint8_t> existing;
    if (exists) {
        std::ifstream in(key_path, std::ios::binary);
        if (!in) return false;
        existing.assign(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
    }

    if (!existing.empty()) {
        // Accept either a raw 32-byte key or a hex-encoded one, so the key can
        // be created with `openssl rand -hex 32` as well as by us.
        std::vector<uint8_t> key;
        if (existing.size() == 32) {
            key = existing;
        } else {
            std::string hex(existing.begin(), existing.end());
            // Strip trailing whitespace written by text editors.
            while (!hex.empty() && std::isspace(static_cast<unsigned char>(hex.back())))
                hex.pop_back();
            auto decoded = base64_decode(hex);
            if (!decoded || decoded->size() != 32) {
                // try as plain hex
                if (hex.size() == 64) {
                    std::vector<uint8_t> raw(32);
                    bool ok = true;
                    for (size_t i = 0; i < 32; ++i) {
                        const char hi = hex[i * 2];
                        const char lo = hex[i * 2 + 1];
                        auto nibble = [](char c) -> int {
                            if (c >= '0' && c <= '9') return c - '0';
                            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                            return -1;
                        };
                        const int h = nibble(hi);
                        const int l = nibble(lo);
                        if (h < 0 || l < 0) { ok = false; break; }
                        raw[i] = static_cast<uint8_t>((h << 4) | l);
                    }
                    if (!ok) {
                        RXD_LOG_ERROR("security")
                            .field("key_file", path)
                            .msg("key file is not a 32-byte raw key or 64-char hex key");
                        return false;
                    }
                    key = std::move(raw);
                } else {
                    return false;
                }
            } else {
                key = std::move(*decoded);
            }
        }
        key_ = std::move(key);
        persistent_ = true;
        ready_ = true;
        return true;
    }

    // New key: create the file with restrictive permissions when possible.
    std::vector<uint8_t> key = generate_aes_key();
    {
        std::error_code dir_ec;
        if (key_path.has_parent_path()) {
            fs::create_directories(key_path.parent_path(), dir_ec);
        }
        std::ofstream out(key_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            RXD_LOG_ERROR("security")
                .field("key_file", path)
                .msg("failed to create key file");
            return false;
        }
        out.write(reinterpret_cast<const char*>(key.data()),
                 static_cast<std::streamsize>(key.size()));
        if (!out) {
            RXD_LOG_ERROR("security")
                .field("key_file", path)
                .msg("failed to write key file");
            return false;
        }
    }

    // Restrict the ACL to the current user when running as that user. A best
    // effort call: refusing to start because SetFileAttributes failed would be
    // worse than warning, but the warning is not optional.
    const DWORD attrs = GetFileAttributesW(key_path.wstring().c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(key_path.wstring().c_str(),
                           attrs | FILE_ATTRIBUTE_HIDDEN |
                               FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    }

    key_ = std::move(key);
    persistent_ = true;
    ready_ = true;
    RXD_LOG_INFO("security")
        .field("key_file", path)
        .msg("generated a new encryption key (256-bit AES)");
    return true;
}

bool EncryptionManager::initialize(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    return load_or_create_key(path);
}

std::optional<EncryptedBlob> EncryptionManager::encrypt(
    std::span<const uint8_t> plaintext, std::span<const uint8_t> aad) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ready_) return std::nullopt;

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM,
                                                 nullptr, 0);
    if (!bng_success(status)) return std::nullopt;

    // GCM is exposed by the Windows CNG chaining-mode API. The mode string
    // must outlive the BCryptSetProperty call.
    std::wstring chain_mode = BCRYPT_CHAIN_MODE_GCM;
    status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                               reinterpret_cast<PUCHAR>(chain_mode.data()),
                               static_cast<ULONG>((chain_mode.size() + 1) *
                                                  sizeof(wchar_t)),
                               0);
    if (!bng_success(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    BCRYPT_KEY_HANDLE key_object = nullptr;
    status = BCryptGenerateSymmetricKey(alg, &key_object, nullptr, 0,
                                        key_.data(),
                                        static_cast<ULONG>(key_.size()), 0);
    if (!bng_success(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    EncryptedBlob blob;
    blob.nonce.resize(kNonceBytes);
    if (!secure_random(blob.nonce)) {
        BCryptDestroyKey(key_object);
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    blob.tag.resize(kTagBytes);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = blob.nonce.data();
    auth_info.cbNonce = static_cast<ULONG>(blob.nonce.size());
    auth_info.pbTag = blob.tag.data();
    auth_info.cbTag = static_cast<ULONG>(blob.tag.size());
    if (!aad.empty()) {
        auth_info.pbAuthData = const_cast<uint8_t*>(aad.data());
        auth_info.cbAuthData = static_cast<ULONG>(aad.size());
    }

    ULONG copied = 0;
    status = BCryptEncrypt(key_object,
                           const_cast<PUCHAR>(plaintext.data()),
                           static_cast<ULONG>(plaintext.size()),
                           &auth_info, nullptr, 0, ciphertext.data(),
                           static_cast<ULONG>(ciphertext.size()), &copied, 0);
    BCryptDestroyKey(key_object);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!bng_success(status)) return std::nullopt;

    ciphertext.resize(copied);
    blob.ciphertext = std::move(ciphertext);
    return blob;
}

std::optional<std::vector<uint8_t>> EncryptionManager::decrypt(
    const EncryptedBlob& blob, std::span<const uint8_t> aad) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ready_) return std::nullopt;

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM,
                                                  nullptr, 0);
    if (!bng_success(status)) return std::nullopt;

    std::wstring chain_mode = BCRYPT_CHAIN_MODE_GCM;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                      reinterpret_cast<PUCHAR>(chain_mode.data()),
                      static_cast<ULONG>((chain_mode.size() + 1) *
                                         sizeof(wchar_t)),
                      0);

    BCRYPT_KEY_HANDLE key_object = nullptr;
    status = BCryptGenerateSymmetricKey(alg, &key_object, nullptr, 0,
                                        key_.data(),
                                        static_cast<ULONG>(key_.size()), 0);
    if (!bng_success(status)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return std::nullopt;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = const_cast<PUCHAR>(blob.nonce.data());
    auth_info.cbNonce = static_cast<ULONG>(blob.nonce.size());
    auth_info.pbTag = const_cast<PUCHAR>(blob.tag.data());
    auth_info.cbTag = static_cast<ULONG>(blob.tag.size());
    if (!aad.empty()) {
        auth_info.pbAuthData = const_cast<uint8_t*>(aad.data());
        auth_info.cbAuthData = static_cast<ULONG>(aad.size());
    }

    std::vector<uint8_t> plaintext(blob.ciphertext.size());
    ULONG copied = 0;
    // A wrong key or a modified byte anywhere fails the GCM tag check, so an
    // authentication failure is indistinguishable from a tampered record.
    status = BCryptDecrypt(key_object,
                           const_cast<PUCHAR>(blob.ciphertext.data()),
                           static_cast<ULONG>(blob.ciphertext.size()),
                           &auth_info, nullptr, 0, plaintext.data(),
                           static_cast<ULONG>(plaintext.size()), &copied, 0);
    BCryptDestroyKey(key_object);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!bng_success(status)) return std::nullopt;

    plaintext.resize(copied);
    return plaintext;
}

std::optional<std::string> EncryptionManager::encrypt_text(const std::string& text) {
    auto blob = encrypt(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(text.data()), text.size()));
    if (!blob) return std::nullopt;
    const auto wire = blob->serialize();
    return base64_encode(wire);
}

std::optional<std::string> EncryptionManager::decrypt_text(
    const std::string& base64_blob) {
    auto wire = base64_decode(base64_blob);
    if (!wire) return std::nullopt;
    auto blob = EncryptedBlob::deserialize(*wire);
    if (!blob) return std::nullopt;
    auto plain = decrypt(*blob);
    if (!plain) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(plain->data()),
                       plain->size());
}

bool EncryptionManager::rotate_key(
    std::function<bool(const std::vector<uint8_t>&)> rehome) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto new_key = generate_aes_key();
    if (rehome && !rehome(new_key)) return false;
    key_ = new_key;
    return true;
}

// ---------------------------------------------------------------------------
// InputValidator
// ---------------------------------------------------------------------------

InputValidator::InputValidator(ValidationOptions opts)
    : opts_(std::move(opts)) {}

ValidationReport InputValidator::validate_model_path(const fs::path& path) {
    ValidationReport report;
    std::error_code ec;

    const std::string full = path.string();
    if (full.empty()) return report.reject("empty path");

    // Device and UNC paths are rejected outright: a model is a file, and
    // neither can be read as a bounded file safely.
    if (full.rfind("\\\\.\\", 0) == 0) return report.reject("device path rejected");
    if (full.rfind("\\\\?\\", 0) == 0) return report.reject("device path rejected");
    if (full.rfind("\\\\", 0) == 0) return report.reject("UNC path rejected");
    if (!opts_.allow_network) {
        for (const char* proto : {"http://", "https://", "ftp://"}) {
            if (full.rfind(proto, 0) == 0) return report.reject("remote URI rejected");
        }
    }

    if (fs::is_directory(path, ec)) return report.reject("path is a directory");

    const std::string ext = path.extension().string();
    std::string lower_ext;
    for (char c : ext)
        lower_ext += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!opts_.allowed_extensions.empty()) {
        bool allowed = false;
        for (const auto& candidate : opts_.allowed_extensions) {
            std::string lower_candidate;
            for (char c : candidate)
                lower_candidate +=
                    static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower_ext == lower_candidate) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            return report.reject("extension '" + ext + "' is not permitted");
        }
    }

    if (!opts_.allow_devices) {
        // Anything that is not a regular file (reparse points, COM ports) is
        // refused so a crafted path cannot redirect the loader.
        const DWORD attrs = GetFileAttributesW(path.wstring().c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES &&
            (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) {
            return report.reject("reparse point rejected");
        }
    }

    const auto size = fs::file_size(path, ec);
    if (!ec && size > static_cast<uintmax_t>(opts_.max_bytes) &&
        opts_.max_bytes > 0) {
        return report.reject("file exceeds the " +
                            std::to_string(opts_.max_bytes) + " byte limit");
    }

    report.normalized_path = fs::weakly_canonical(path, ec).string();
    if (report.normalized_path.empty())
        report.normalized_path = fs::absolute(path, ec).string();
    return report;
}

ValidationReport InputValidator::validate_size(std::span<const uint8_t> input) {
    ValidationReport report;
    if (opts_.max_bytes > 0 &&
        static_cast<int64_t>(input.size()) > opts_.max_bytes) {
        return report.reject("input size " + std::to_string(input.size()) +
                            " exceeds the " + std::to_string(opts_.max_bytes) +
                            " byte limit");
    }
    return report;
}

ValidationReport InputValidator::validate_text(std::string_view text,
                                              int64_t max_len) {
    ValidationReport report;
    const int64_t limit = max_len > 0 ? max_len : opts_.max_bytes;
    if (static_cast<int64_t>(text.size()) > limit) {
        return report.reject("input length " + std::to_string(text.size()) +
                            " exceeds the " + std::to_string(limit) + " limit");
    }
    for (const char c : text) {
        // Control characters carry no meaning in commands or paths, and they
        // are how terminal/log injection is performed.
        if (static_cast<unsigned char>(c) < 0x20 && c != '\t' && c != '\n' &&
            c != '\r') {
            return report.reject("control character rejected");
        }
    }
    return report;
}

ValidationReport InputValidator::validate_int(int64_t value, int64_t lo,
                                             int64_t hi, const char* name) {
    ValidationReport report;
    if (value < lo || value > hi) {
        return report.reject(std::string(name ? name : "value") + "=" +
                            std::to_string(value) + " is outside [" +
                            std::to_string(lo) + ", " + std::to_string(hi) + "]");
    }
    return report;
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// Re-opens a closed log, continuing the chain from the last recovered hash.
/// Exists separately from initialize() so append() can re-open without taking
/// the mutex it already holds (initialize() locks mutex_).
bool AuditLogger::open_for_append() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_ && out_.is_open()) return true;
    if (path_.empty()) return false;
    std::error_code ec;
    fs::create_directories(path_.parent_path(), ec);
    out_.open(path_, std::ios::out | std::ios::app | std::ios::binary);
    if (!out_) return false;
    if (!recover_last_hash_locked()) {
        out_.close();
        RXD_LOG_ERROR("security")
            .field("audit_path", path_.string())
            .msg("audit log has an unreadable trailing record; refusing to "
                 "append because the hash chain cannot be continued safely");
        return false;
    }
    initialized_ = true;
    return true;
}

bool AuditLogger::initialize(const std::string& dir, bool encrypt_at_rest) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) return true;

    std::error_code ec;
    path_ = fs::path(dir) / "rawrxd_audit.jsonl";
    if (!fs::exists(path_.parent_path(), ec) && !path_.parent_path().empty()) {
        fs::create_directories(path_.parent_path(), ec);
    }
    out_.open(path_, std::ios::out | std::ios::app | std::ios::binary);
    if (!out_) {
        RXD_LOG_ERROR("security")
            .field("audit_path", path_.string())
            .msg("audit log could not be opened");
        return false;
    }
    encrypt_at_rest_ = encrypt_at_rest;
    initialized_ = true;
    if (!recover_last_hash_locked()) {
        // A truncated final record is a real fault, not a warning: report it so
        // the readiness gate can block startup rather than appending into a
        // broken chain. The stream is closed first, otherwise append() would
        // see an open file and write straight past the broken link.
        out_.close();
        initialized_ = false;
        RXD_LOG_ERROR("security")
            .field("audit_path", path_.string())
            .msg("audit log ends with an unreadable record");
        return false;
    }
    RXD_LOG_INFO("security")
        .field("audit_path", path_.string())
        .field("encrypted", encrypt_at_rest_)
        .msg("audit log open");
    return true;
}

bool AuditLogger::recover_last_hash_locked() {
    // Re-reading the tail keeps the chain intact across restarts and across a
    // rotate-and-reopen cycle. A final line that cannot be parsed means the
    // log was truncated mid-write (power loss, disk full, or tampering), and
    // appending after it would silently fork the chain, so recovery reports
    // failure and the caller refuses to write.
    std::ifstream in(path_, std::ios::binary);
    if (!in) {
        last_hash_.clear();
        return true;  // a missing file is a clean start, not corruption
    }
    std::string line;
    std::string last_line;
    while (std::getline(in, line)) {
        if (!line.empty()) last_line = line;
    }
    if (last_line.empty()) {
        last_hash_.clear();
        return true;
    }
    const auto rec = parse_audit_line(last_line, encrypt_at_rest_);
    if (!rec) {
        // Unparseable means the tail was clobbered; appending would fork the
        // chain, so recovery reports failure and the caller refuses to write.
        return false;
    }
    last_hash_ = rec->hash;
    return true;
}

bool AuditLogger::append(std::string actor, std::string action,
                        std::string resource, std::string outcome,
                        std::string detail, std::string trace_id) {
    // Note on locking: `initialize()` takes the same mutex, so append must
    // never call it while holding the lock. The lazy re-open below therefore
    // happens before the lock is taken.
    if (path_.empty() || !out_.is_open()) {
        if (path_.empty()) {
            RXD_LOG_ERROR("security")
                .field("action", action)
                .msg("audit log has no configured path; privileged action refused");
            return false;
        }
        if (!open_for_append()) return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!out_.is_open()) {
        RXD_LOG_ERROR("security")
            .field("action", action)
            .msg("audit log not open; privileged action refused");
        return false;
    }

    AuditRecord rec;
    rec.ts_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
    rec.actor = std::move(actor);
    rec.action = std::move(action);
    rec.resource = std::move(resource);
    rec.outcome = std::move(outcome);
    rec.detail = std::move(detail);
    rec.trace_id = std::move(trace_id);
    rec.prev_hash = last_hash_;

    // The hash covers the canonical form, which includes prev_hash, so the
    // records form a chain rather than independent checksums.
    const auto canonical = rec.canonical();
    const std::string digest = audit_record_hash(canonical);
    if (digest.empty()) {
        RXD_LOG_ERROR("security").msg("audit record could not be hashed");
        return false;
    }
    rec.hash = digest;

    std::string payload = rec.to_json();
    if (encrypt_at_rest_) {
        if (auto encrypted = EncryptionManager::instance().encrypt_text(payload)) {
            payload = *encrypted;
        } else {
            // Refuse rather than write a plaintext audit record, because a
            // half-encrypted trail is worse than none at all.
            RXD_LOG_ERROR("security")
                .msg("refusing to write an unencrypted audit record");
            return false;
        }
    }

    out_ << payload << '\n';
    out_.flush();
    if (!out_) {
        RXD_LOG_ERROR("security").msg("audit log write failed");
        return false;
    }

    last_hash_ = rec.hash;
    stats_.records++;
    stats_.bytes_written += static_cast<uint64_t>(payload.size() + 1);
    return true;
}

std::optional<size_t> AuditLogger::verify_chain(size_t max_records) {
    std::lock_guard<std::mutex> lock(mutex_);
    out_.flush();
    std::ifstream in(path_, std::ios::binary);
    if (!in) return std::nullopt;

    // Load every line first so the tail bound can be applied to the most
    // recent records rather than an arbitrary prefix.
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) lines.push_back(line);
    }

    last_verified_records_ = lines.size();
    if (max_records > 0 && lines.size() > max_records) {
        // Only the tail is checked; earlier records are trusted to be
        // unchanged because the log is append-only. The startup gate performs
        // the full walk, so this is a deliberate, documented trade-off rather
        // than an unnoticed one.
        last_verified_records_ = max_records;
        lines.erase(lines.begin(),
                    lines.end() -
                        static_cast<std::ptrdiff_t>(max_records));
    }

    // The chain link for the first checked record is unknown when a tail subset
    // is verified, so only the content hash is checked for that record; every
    // subsequent record is also link-checked against the one before it.
    std::optional<std::string> previous_hash;
    size_t index = 0;
    const size_t skipped =
        stats_.records >= lines.size()
            ? (lines.size() == last_verified_records_
                   ? 0
                   : 0)
            : 0;
    for (size_t i = 0; i < lines.size(); ++i) {
        const auto parsed = parse_audit_line(lines[i], encrypt_at_rest_);
        // A blank or unparseable line means the log was damaged.
        if (!parsed) return static_cast<size_t>(skipped) + i;
        const AuditRecord& rec = *parsed;

        // Content check: the stored hash must be the hash of the stored
        // fields. This catches a rewritten record whose hash was recomputed,
        // and a reordered tail.
        const std::string computed = audit_record_hash(rec.canonical());
        if (!computed.empty() && computed != rec.hash) {
            return static_cast<size_t>(skipped) + i;
        }

        // Link check: each record must reference the record before it, except
        // the first of a tail subset whose predecessor was not verified.
        if (previous_hash && rec.prev_hash != *previous_hash) {
            return static_cast<size_t>(skipped) + i;
        }
        previous_hash = rec.hash;
        ++index;
    }
    (void)index;
    return std::nullopt;
}

void AuditLogger::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (out_.is_open()) out_.flush();
    out_.close();
    initialized_ = false;
    stats_ = Stats{};
    last_hash_.clear();
}

std::string AuditRecord::canonical() const {
    // Field order is fixed: the hash is over this exact string, so it must be
    // stable across builds and platforms.
    std::ostringstream oss;
    oss << ts_ms << '|' << actor << '|' << action << '|' << resource << '|'
        << outcome << '|' << detail << '|' << trace_id << '|' << prev_hash;
    return oss.str();
}

std::string AuditRecord::to_json() const {
    json doc;
    doc["ts"] = ts_ms;
    doc["actor"] = actor;
    doc["action"] = action;
    doc["resource"] = resource;
    doc["outcome"] = outcome;
    doc["detail"] = detail;
    doc["trace_id"] = trace_id;
    doc["prev_hash"] = prev_hash;
    doc["hash"] = hash;
    return doc.dump();
}

// ---------------------------------------------------------------------------
// Redaction and security facade
// ---------------------------------------------------------------------------

std::string redact_secrets(std::string_view text) {
    std::string out(text);
    // Redacts key=value and key: value pairs whose key looks secret. The text
    // is scanned in place so the original is never modified.
    static const char* keys[] = {"password", "passwd", "token", "secret",
                                 "api_key", "apikey", "key", "bearer"};
    for (const char* key : keys) {
        const std::string k(key);
        size_t pos = 0;
        while ((pos = out.find(k, pos)) != std::string::npos) {
            // Only redact when the match starts a token.
            const bool boundary =
                pos == 0 || !std::isalnum(static_cast<unsigned char>(out[pos - 1]));
            if (!boundary) {
                pos += k.size();
                continue;
            }
            size_t eq = out.find_first_of("=:", pos + k.size());
            if (eq == std::string::npos) {
                pos += k.size();
                continue;
            }
            size_t value_start = eq + 1;
            // Optional quoting.
            while (value_start < out.size() &&
                   std::isspace(static_cast<unsigned char>(out[value_start])))
                ++value_start;
            const bool quoted =
                value_start < out.size() &&
                (out[value_start] == '"' || out[value_start] == '\'');
            if (quoted) ++value_start;
            size_t end = value_start;
            while (end < out.size()) {
                const char c = out[end];
                if (quoted ? c == out[value_start - 1]
                           : (std::isspace(static_cast<unsigned char>(c)) ||
                              c == ';' || c == '&' || c == ')' || c == ',')) {
                    break;
                }
                ++end;
            }
            if (end > value_start) {
                out.replace(value_start, end - value_start, "<redacted>");
                pos = value_start + std::strlen("<redacted>");
            } else {
                pos = eq + 1;
            }
        }
    }
    return out;
}

void SecurityRuntime::init(const ConfigManager& cfg) {
    if (ready_) return;
    ready_ = true;

    ValidationOptions opts;
    const auto extensions = cfg.get_string("security", "allowed_model_extensions");
    std::string current;
    for (const char c : extensions) {
        if (c == ',') {
            if (!current.empty()) {
                opts.allowed_extensions.push_back(current);
                current.clear();
            }
        } else if (c != ' ') {
            current +=
                static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }
    if (!current.empty()) opts.allowed_extensions.push_back(current);
    opts.max_bytes = cfg.get_int("security", "max_request_bytes");
    validator_ = std::make_unique<InputValidator>(std::move(opts));

    const bool encryption = cfg.get_bool("security", "encryption_enabled");
    if (encryption) {
        const auto key_file =
            expand_path_tokens(cfg.get_string("security", "key_file"));
        if (!key_file.empty()) {
            // An unusable key file must not be silently ignored: it means
            // state cannot be decrypted and the operator needs to know now.
            if (!EncryptionManager::instance().initialize(key_file)) {
                RXD_LOG_CRITICAL("security")
                    .field("key_file", key_file)
                    .msg("encryption key could not be loaded; encrypted state "
                         "will be unreadable");
            }
        } else {
            EncryptionManager::instance().initialize("");
        }
    }

    const bool audit_enabled = cfg.get_bool("security", "audit_enabled");
    if (audit_enabled) {
        // Only encrypt the audit trail when the key survives a restart.
        // Encrypting with an in-memory key would write a log that the next
        // process cannot read, which turns the trail into noise.
        bool encrypt_audit = encryption;
        if (encrypt_audit && !EncryptionManager::instance().key_is_persistent()) {
            RXD_LOG_WARNING("security")
                .msg("no persistent key file is configured; the audit log will "
                     "be written unencrypted so it stays verifiable");
            encrypt_audit = false;
        }
        const std::string dir =
            expand_path_tokens(cfg.get_string("security", "audit_dir"));
        if (!AuditLogger::instance().initialize(dir, encrypt_audit)) {
            RXD_LOG_CRITICAL("security")
                .field("audit_dir", dir)
                .msg("audit log could not be opened");
        }
    }

    // The health check must not capture the config by reference: the health
    // registry outlives the initialiser call, so only copied values are safe.
    const bool encryption_enabled = encryption;
    const bool audit_ready = audit_enabled;
    HealthRegistry::instance().register_check("security.hardening", [=]() {
        HealthComponent c;
        c.name = "security.hardening";
        c.status = HealthStatus::Healthy;
        if (encryption_enabled && !EncryptionManager::instance().has_key()) {
            return unhealthy(c, "encryption is enabled but no key is loaded");
        }
        if (!audit_ready) return c;
        if (AuditLogger::instance().path().empty()) {
            return degraded(c, "audit log is not open");
        }
        // Verify the tail rather than the whole chain: this runs on every
        // health probe, and a full walk is O(records). The startup gate walks
        // everything, so full-coverage detection still happens before serving.
        const auto broken = AuditLogger::instance().verify_chain(
            kAuditHealthCheckTail);
        if (broken) {
            return unhealthy(
                c, "audit chain broken near record " + std::to_string(*broken));
        }
        c.detail = "audit chain verified over the last " +
                   std::to_string(AuditLogger::instance().last_verified_records()) +
                   " record(s)";
        return c;
    });

    RXD_LOG_INFO("security")
        .field("encryption", encryption)
        .field("audit", audit_enabled)
        .field("max_request_bytes", opts.max_bytes)
        .msg("security runtime initialized");
}

SecurityRuntime::Status SecurityRuntime::status() const {
    Status st;
    st.encryption_ready = EncryptionManager::instance().has_key();
    st.audit_ready = !AuditLogger::instance().path().empty();
    st.audit_records = AuditLogger::instance().stats().records;
    st.audit_chain_broken_at = AuditLogger::instance().verify_chain();
    return st;
}

} // namespace Sovereign::Production
