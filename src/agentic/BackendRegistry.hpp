// BackendRegistry.hpp -- shared backend selection contract for RawrXD.
//
// Governs the user-facing choice (Deep2 / Strata / Ollama) independently of the
// underlying engine family (Deep2Engine / Ollama HTTP). Strata is a Deep2
// execution mode, not a third runtime: it selects Deep2 plus expert residency
// and optionally the int8 KV cache.
//
// Rules enforced here:
//   * selection is explicit; there is no implicit substitution;
//   * fallback requires explicit user approval (allowFallback);
//   * an unavailable backend produces an error, never a silent alternative;
//   * capabilities distinguish verified features from unsupported ones.
//
// Header-only and dependency-free so the GUI and the CLI cannot drift apart.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace rawrxd {

enum class BackendId : std::uint8_t { Deep2 = 0, Strata = 1, Ollama = 2 };

enum class EngineKind : std::uint8_t { Deep2 = 0, Ollama = 1 };

enum class Health : std::uint8_t {
    Available = 0,
    Initializing = 1,
    Unavailable = 2,
    Failed = 3,
};

// Capability support is tri-state: a feature is either verified by evidence,
// present but unverified, or unsupported. Reporting "unsupported" as "verified"
// is exactly the failure mode this contract exists to prevent.
enum class Support : std::uint8_t { Verified = 0, Unverified = 1, Unsupported = 2 };

struct Capabilities {
    Support chat = Support::Unverified;
    Support streaming = Support::Unverified;
    Support toolCalls = Support::Unverified;
    Support autonomousRepair = Support::Unverified;
};

struct BackendInfo {
    BackendId id = BackendId::Deep2;
    std::string_view name = "deep2";
    EngineKind engine = EngineKind::Deep2;
    Health health = Health::Unavailable;
    Capabilities capabilities{};
    std::string detail;  // human-readable note, e.g. why unavailable
};

struct BackendSelection {
    BackendId selected = BackendId::Ollama;
    EngineKind engine = EngineKind::Ollama;
    bool strataExpertResidency = false;
    bool strataInt8KVCache = false;
    bool allowFallback = false;
};

constexpr std::string_view ToString(BackendId id) noexcept {
    switch (id) {
        case BackendId::Deep2:  return "deep2";
        case BackendId::Strata: return "strata";
        case BackendId::Ollama: return "ollama";
    }
    return "unknown";
}

constexpr std::string_view ToString(EngineKind e) noexcept {
    return e == EngineKind::Deep2 ? "deep2" : "ollama";
}

constexpr std::string_view ToString(Health h) noexcept {
    switch (h) {
        case Health::Available:    return "available";
        case Health::Initializing: return "initializing";
        case Health::Unavailable:  return "unavailable";
        case Health::Failed:       return "failed";
    }
    return "unknown";
}

constexpr std::string_view ToString(Support s) noexcept {
    switch (s) {
        case Support::Verified:    return "verified";
        case Support::Unverified:  return "unverified";
        case Support::Unsupported: return "unsupported";
    }
    return "unknown";
}

inline std::optional<BackendId> ParseBackendId(std::string_view text) noexcept {
    if (text == "deep2")  return BackendId::Deep2;
    if (text == "strata") return BackendId::Strata;
    if (text == "ollama") return BackendId::Ollama;
    return std::nullopt;
}

// Resolve a user-facing selection into an engine choice plus execution flags.
// `resident` is false when the Strata residency policy could not be activated;
// the caller must treat that as STRATA_NOT_ROUTABLE rather than running a plain
// Deep2 request under the Strata label.
struct Resolution {
    std::optional<BackendSelection> selection;
    std::optional<std::string> error;
};

inline Resolution ResolveSelection(BackendId requested,
                                   const std::array<BackendInfo, 3>& registry,
                                   bool strataResidencyReady,
                                   bool allowFallback) {
    const BackendInfo* info = nullptr;
    for (const auto& b : registry) {
        if (b.id == requested) { info = &b; break; }
    }
    if (info == nullptr) {
        return {std::nullopt, std::string("unknown backend: ") + std::string(ToString(requested))};
    }
    if (info->health != Health::Available) {
        return {std::nullopt,
                std::string("backend ") + std::string(info->name) + " is " +
                    std::string(ToString(info->health)) +
                    (info->detail.empty() ? "" : ": " + info->detail)};
    }

    BackendSelection sel{};
    sel.selected = requested;
    sel.allowFallback = allowFallback;

    switch (requested) {
        case BackendId::Deep2:
            sel.engine = EngineKind::Deep2;
            break;
        case BackendId::Strata:
            if (!strataResidencyReady) {
                return {std::nullopt,
                        "STRATA_NOT_ROUTABLE: expert residency could not be activated"};
            }
            sel.engine = EngineKind::Deep2;
            sel.strataExpertResidency = true;
            break;
        case BackendId::Ollama:
            sel.engine = EngineKind::Ollama;
            break;
    }
    return {sel, std::nullopt};
}

// Persistence is a single line: "<backend>[,strata=1][,int8kv=1][,fallback=1]".
inline std::string SerializeSelection(const BackendSelection& s) {
    std::string out(ToString(s.selected));
    if (s.selected == BackendId::Strata) {
        if (s.strataExpertResidency) out += ",strata=1";
        if (s.strataInt8KVCache) out += ",int8kv=1";
    }
    if (s.allowFallback) out += ",fallback=1";
    return out;
}

inline std::optional<BackendSelection> DeserializeSelection(std::string_view text) {
    std::optional<BackendSelection> parsed;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t comma = text.find(',', pos);
        const std::string_view token =
            text.substr(pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos);
        if (pos == 0) {
            const auto id = ParseBackendId(token);
            if (!id) return std::nullopt;
            parsed = BackendSelection{};
            parsed->selected = *id;
            parsed->engine = (*id == BackendId::Ollama) ? EngineKind::Ollama : EngineKind::Deep2;
        } else if (token == "strata=1") {
            if (!parsed || parsed->selected != BackendId::Strata) return std::nullopt;
            parsed->strataExpertResidency = true;
        } else if (token == "int8kv=1") {
            if (!parsed || parsed->selected != BackendId::Strata) return std::nullopt;
            parsed->strataInt8KVCache = true;
        } else if (token == "fallback=1") {
            if (!parsed) return std::nullopt;
            parsed->allowFallback = true;
        } else if (!token.empty()) {
            return std::nullopt;
        }
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return parsed;
}

}  // namespace rawrxd