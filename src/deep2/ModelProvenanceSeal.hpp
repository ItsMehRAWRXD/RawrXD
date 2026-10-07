#pragma once
/*
    MODEL_PROVENANCE_SEAL_001

    Header-only, source-only provenance guard for Deep2 model digestion/bind/runtime.

    Purpose:
      - Keep the user-supplied model locator stable.
      - Treat every other manifest field as dynamically digested from that exact file/shard set.
      - Block schema/authority promotion when a binder, manifest, or runtime receipt inherits facts
        from a different model fingerprint or different digestion run.

    Authority:
      DISCOVERY_AUTHORITY only. Runtime PASS still requires a runtime receipt from the same run.
*/

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace rawr::model_provenance {

static constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
static constexpr std::uint64_t kFnvPrime  = 1099511628211ull;

inline std::uint64_t fnv1a(const void* data, std::size_t len,
                           std::uint64_t h = kFnvOffset) noexcept {
    const unsigned char* p = static_cast<const unsigned char*>(data);
    for (std::size_t i = 0; i < len; ++i) {
        h ^= static_cast<std::uint64_t>(p[i]);
        h *= kFnvPrime;
    }
    return h;
}

inline std::uint64_t mix_u64(std::uint64_t h, std::uint64_t v) noexcept {
    return fnv1a(&v, sizeof(v), h);
}

inline std::uint64_t mix_str(std::uint64_t h, const std::string& s) noexcept {
    h = mix_u64(h, static_cast<std::uint64_t>(s.size()));
    return s.empty() ? h : fnv1a(s.data(), s.size(), h);
}

inline std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

struct FileIdentity {
    std::string userLocator;       // The stable model location supplied by user/config.
    std::string canonicalLocator;  // Best-effort canonical path; falls back to userLocator.
    std::uint64_t fileBytes = 0;   // For directory/sharded models: total bytes of regular files.
    std::uint64_t writeStamp = 0;  // Best-effort last_write_time aggregate.
    std::uint64_t locatorHash = 0;
    bool exists = false;
    bool isDirectory = false;
};

inline std::uint64_t file_time_stamp(const std::filesystem::path& p) noexcept {
    std::error_code ec;
    const auto ft = std::filesystem::last_write_time(p, ec);
    if (ec) return 0;
    return static_cast<std::uint64_t>(ft.time_since_epoch().count());
}

inline FileIdentity identify_file_locator(const std::string& locator) {
    FileIdentity out{};
    out.userLocator = locator;
    out.canonicalLocator = locator;

    std::error_code ec;
    std::filesystem::path p(locator);
    out.exists = std::filesystem::exists(p, ec);
    out.isDirectory = std::filesystem::is_directory(p, ec);

    std::filesystem::path canon = std::filesystem::weakly_canonical(p, ec);
    if (!ec && !canon.empty()) out.canonicalLocator = canon.string();

    if (out.exists && out.isDirectory) {
        for (const auto& e : std::filesystem::directory_iterator(p, ec)) {
            if (ec) break;
            std::error_code ec2;
            if (!e.is_regular_file(ec2)) continue;
            out.fileBytes += static_cast<std::uint64_t>(e.file_size(ec2));
            out.writeStamp ^= file_time_stamp(e.path()) + 0x9e3779b97f4a7c15ull +
                              (out.writeStamp << 6) + (out.writeStamp >> 2);
        }
    } else if (out.exists) {
        out.fileBytes = static_cast<std::uint64_t>(std::filesystem::file_size(p, ec));
        out.writeStamp = file_time_stamp(p);
    }

    std::uint64_t h = kFnvOffset;
    h = mix_str(h, lower_copy(out.canonicalLocator));
    h = mix_u64(h, out.fileBytes);
    h = mix_u64(h, out.writeStamp);
    out.locatorHash = h;
    return out;
}

struct TensorDigestItem {
    std::string name;
    std::uint64_t rows = 0;
    std::uint64_t cols = 0;
    std::uint64_t sizeBytes = 0;
    std::uint64_t offset = 0;
    int type = -1;
};

inline std::uint64_t tensor_name_shape_hash(std::vector<TensorDigestItem> items) {
    std::sort(items.begin(), items.end(),
              [](const TensorDigestItem& a, const TensorDigestItem& b) {
                  return a.name < b.name;
              });

    std::uint64_t h = kFnvOffset;
    h = mix_u64(h, static_cast<std::uint64_t>(items.size()));
    for (const auto& t : items) {
        h = mix_str(h, t.name);
        h = mix_u64(h, t.rows);
        h = mix_u64(h, t.cols);
        h = mix_u64(h, t.sizeBytes);
        h = mix_u64(h, t.offset);
        h = mix_u64(h, static_cast<std::uint64_t>(static_cast<std::int64_t>(t.type)));
    }
    return h;
}

struct Provenance {
    FileIdentity file{};
    std::uint64_t tensorHash = 0;
    std::uint64_t manifestHash = 0;

    // Stage fingerprints must match for authority. They may be filled by the
    // digestion stream, manifest loader, schema binder, and runtime receipt.
    std::uint64_t digestFingerprint = 0;
    std::uint64_t manifestFingerprint = 0;
    std::uint64_t bindFingerprint = 0;
    std::uint64_t authorityFingerprint = 0;
    std::uint64_t runtimeFingerprint = 0;

    std::string manifestId;
    std::string digestRunId;
    std::string runtimeRunId;

    bool manifestLoaded = false;
    bool manifestGeneratedThisRun = false;
    bool schemaAliasFallbackUsed = false;
    bool inheritedSchemaAuthority = false;
    bool runtimeOverlaySeparate = true;

    bool ok = false;
    std::string blockedAt;
    std::string why;
};

inline std::uint64_t compose_model_fingerprint(const FileIdentity& f,
                                               std::uint64_t tensorHash) noexcept {
    std::uint64_t h = kFnvOffset;
    h = mix_u64(h, f.locatorHash);
    h = mix_u64(h, tensorHash);
    return h;
}

inline Provenance begin(const std::string& modelLocator,
                        const std::vector<TensorDigestItem>& tensors = {}) {
    Provenance p{};
    p.file = identify_file_locator(modelLocator);
    p.tensorHash = tensor_name_shape_hash(tensors);
    const std::uint64_t fp = compose_model_fingerprint(p.file, p.tensorHash);
    p.digestFingerprint = fp;
    p.manifestFingerprint = fp;
    p.bindFingerprint = fp;
    p.authorityFingerprint = fp;
    p.runtimeFingerprint = fp;
    return p;
}

inline void mark_manifest_loaded(Provenance& p,
                                 std::uint64_t manifestFingerprint,
                                 const std::string& manifestId,
                                 bool generatedThisRun) {
    p.manifestLoaded = true;
    p.manifestFingerprint = manifestFingerprint;
    p.manifestId = manifestId;
    p.manifestGeneratedThisRun = generatedThisRun;
}

inline void mark_bind(Provenance& p, std::uint64_t bindFingerprint,
                      bool aliasFallbackUsed) {
    p.bindFingerprint = bindFingerprint;
    p.schemaAliasFallbackUsed = aliasFallbackUsed;
}

inline void mark_authority(Provenance& p, std::uint64_t authorityFingerprint,
                           bool inherited) {
    p.authorityFingerprint = authorityFingerprint;
    p.inheritedSchemaAuthority = inherited;
}

inline void mark_runtime(Provenance& p, std::uint64_t runtimeFingerprint,
                         const std::string& runtimeRunId) {
    p.runtimeFingerprint = runtimeFingerprint;
    p.runtimeRunId = runtimeRunId;
}

inline bool same_nonzero(std::uint64_t a, std::uint64_t b) noexcept {
    return a != 0 && b != 0 && a == b;
}

inline bool validate(Provenance& p) {
    const std::uint64_t expected = compose_model_fingerprint(p.file, p.tensorHash);

    p.ok = false;
    p.blockedAt = "PROVENANCE_MISMATCH";
    p.why.clear();

    if (!p.file.exists) {
        p.why = "MODEL_LOCATION_NOT_FOUND";
        return false;
    }
    if (p.inheritedSchemaAuthority) {
        p.why = "INHERITED_SCHEMA_AUTHORITY";
        return false;
    }
    if (!same_nonzero(expected, p.digestFingerprint)) {
        p.why = "DIGEST_FINGERPRINT_MISMATCH";
        return false;
    }
    if (p.manifestLoaded && !same_nonzero(expected, p.manifestFingerprint)) {
        p.why = "MANIFEST_FINGERPRINT_MISMATCH";
        return false;
    }
    if (!same_nonzero(expected, p.bindFingerprint)) {
        p.why = "BIND_FINGERPRINT_MISMATCH";
        return false;
    }
    if (!same_nonzero(expected, p.authorityFingerprint)) {
        p.why = "AUTHORITY_FINGERPRINT_MISMATCH";
        return false;
    }
    if (!same_nonzero(expected, p.runtimeFingerprint)) {
        p.why = "RUNTIME_FINGERPRINT_MISMATCH";
        return false;
    }
    if (!p.runtimeOverlaySeparate) {
        p.why = "RUNTIME_OVERLAY_MUTATED_DISCOVERY";
        return false;
    }

    p.ok = true;
    p.blockedAt.clear();
    p.why = "SAME_MODEL_FINGERPRINT";
    return true;
}

inline void emit(FILE* f, const Provenance& p) noexcept {
    if (!f) return;
    const std::uint64_t expected =
        compose_model_fingerprint(p.file, p.tensorHash);

    std::fprintf(f, "MODEL_PROVENANCE_BEGIN=1\n");
    std::fprintf(f, "MODEL_LOCATION=%s\n", p.file.userLocator.c_str());
    std::fprintf(f, "MODEL_CANONICAL=%s\n", p.file.canonicalLocator.c_str());
    std::fprintf(f, "MODEL_EXISTS=%d MODEL_IS_DIRECTORY=%d MODEL_BYTES=%llu MODEL_WRITE_STAMP=%llu\n",
                 p.file.exists ? 1 : 0,
                 p.file.isDirectory ? 1 : 0,
                 static_cast<unsigned long long>(p.file.fileBytes),
                 static_cast<unsigned long long>(p.file.writeStamp));
    std::fprintf(f, "MODEL_LOCATOR_HASH=%llu TENSOR_NAME_SHAPE_HASH=%llu MODEL_EXPECTED_FP=%llu\n",
                 static_cast<unsigned long long>(p.file.locatorHash),
                 static_cast<unsigned long long>(p.tensorHash),
                 static_cast<unsigned long long>(expected));
    std::fprintf(f, "DIGEST_FP=%llu MANIFEST_FP=%llu BIND_FP=%llu AUTHORITY_FP=%llu RUNTIME_FP=%llu\n",
                 static_cast<unsigned long long>(p.digestFingerprint),
                 static_cast<unsigned long long>(p.manifestFingerprint),
                 static_cast<unsigned long long>(p.bindFingerprint),
                 static_cast<unsigned long long>(p.authorityFingerprint),
                 static_cast<unsigned long long>(p.runtimeFingerprint));
    std::fprintf(f, "MANIFEST_LOADED=%d MANIFEST_THIS_RUN=%d MANIFEST_ID=%s\n",
                 p.manifestLoaded ? 1 : 0,
                 p.manifestGeneratedThisRun ? 1 : 0,
                 p.manifestId.empty() ? "none" : p.manifestId.c_str());
    std::fprintf(f, "SCHEMA_ALIAS_FALLBACK_USED=%d INHERITED_SCHEMA_AUTHORITY=%d RUNTIME_OVERLAY_SEPARATE=%d\n",
                 p.schemaAliasFallbackUsed ? 1 : 0,
                 p.inheritedSchemaAuthority ? 1 : 0,
                 p.runtimeOverlaySeparate ? 1 : 0);
    std::fprintf(f, "MODEL_PROVENANCE_MATCH=%d BLOCKED_AT=%s WHY=%s\n",
                 p.ok ? 1 : 0,
                 p.blockedAt.empty() ? "NONE" : p.blockedAt.c_str(),
                 p.why.empty() ? "NONE" : p.why.c_str());
    std::fprintf(f, "AUTHORITY_CLASS=DISCOVERY_PROVENANCE PROMOTE=0\n");
    std::fprintf(f, "MODEL_PROVENANCE_END=1\n");
    std::fflush(f);
}

} // namespace rawr::model_provenance
