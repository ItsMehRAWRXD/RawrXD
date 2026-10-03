#pragma once

// ===========================================================================
// RawrXD Operator System — type-level contract
//
// STATUS: SOURCE_ONLY_DECLARATION
//   This header declares the operator vocabulary and its proof types.
//   It is NOT adopted by any shipping target, NOT executed at runtime, and
//   NOT certified. Declaring the contract is not the same as wiring it.
//
//   Adoption is measured by RAWRXD_COMPUTE_ADOPTION_AUTHORITY_001
//   (see AGENTS.md). Until that gate closes:
//       SOURCE_CREATED != PRODUCT_WIRED
//       PRODUCT_WIRED != RUNTIME_EXECUTED
//       RUNTIME_EXECUTED != CERTIFIED_PASS
//
// MODEL = PASS   (pass-through payload, not a success verdict)
// ENGINE = ON    (the engine owns execution, routing, tools and streaming)
//
// WORD -> DROW -> TOOR
//
//   TOOR executable:  ON -> VERIFY -> *(STAR)
//   TOOR blocked:     SKIP = BY(PASS)E
//                       -> LOOT an existing capability
//                          OR
//                       -> CRE / CREATE the missing capability
//                       -> BIND / HOTPATCH
//                       -> ON -> VERIFY -> *(STAR)
//
//   SEEN   -> LOOT
//   UNSEEN -> NU-DROW = REVERSE-SCRAPE
//
//   UN-BIND  </> = one-line structural scrape (conservative, not NLU)
//   BOW-RAIN("*") = traverse every mapped/reachable node
//
// THE NON-NEGOTIABLE INVARIANT:
//   CREATE != VERIFIED
//   BIND   != VERIFIED
//   PATCH  != VERIFIED
//   RUN    != VERIFIED
//   VERIFIED = measured_execution_that_satisfies_the_root_contract
//
// Scope boundary: HOTPATCH means attaching a capability to a live execution
// path (source, config, registry). It does NOT mean rewriting trained model
// weights or self-modifying a running runtime image.
//   HOTPATCH != LIVE_WEIGHT_PATCHING
//   SELF_SOURCE_MUTATION = 0
// ===========================================================================

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
namespace rawrxd::operators {

// ===========================================================================
// Vocabulary types
// ===========================================================================

enum class ProofState : std::uint8_t {
    Unknown,
    Cold,      // created, not yet bound
    Bound,     // attached to an executable path
    Executed,  // ran and produced output
    Verified,  // measured execution satisfied the root contract
    Failed
};

enum class MapState : std::uint8_t {
    Unseen,
    Seen
};

enum class RootState : std::uint8_t {
    Missing,
    Blocked,
    Executable
};

enum class OperatorKind : std::uint8_t {
    Word,
    Drow,
    NuDrow,
    Toor,
    On,
    Star,
    Skip,
    Bypass,
    Loot,
    Create,
    Cre,
    Bind,
    Unbind,
    Hotpatch,
    Verify,
    BowRain
};

// ===========================================================================
// Display glyphs -- PRESENTATION ONLY
//
//   GLYPH_IS_PRESENTATION       = 1
//   GLYPH_IS_VERDICT            = 0
//   ASCII_OPERATOR_IDENTITY     = AUTHORITATIVE
//   UNICODE_GLYPH               = DISPLAY_ALIAS
//
// The enumerator NAMES below are the operator identity. The glyph is a render
// of that name and nothing else. A font, terminal, source-encoding or receipt
// parser that cannot represent the glyph must not change what the operator
// means -- so no glyph string is ever compared, parsed, stored in a verdict,
// or matched against. Receipts emit both so a human sees the symbol and a
// machine still reads ASCII.
// ===========================================================================

enum class OperatorGlyph : std::uint8_t {
    UN,
    NU,
    EXTEND,
    REACH,
    STATED,
    COLD,
    HOT,
    VERIFIED,
    STAR
};

// ASCII identity. This is the authoritative spelling of the operator.
[[nodiscard]]
constexpr const char* asciiName(OperatorGlyph op) noexcept
{
    switch (op)
    {
        case OperatorGlyph::UN:       return "UN";
        case OperatorGlyph::NU:       return "NU";
        case OperatorGlyph::EXTEND:   return "EXTEND";
        case OperatorGlyph::REACH:    return "REACH";
        case OperatorGlyph::STATED:   return "STATED";
        case OperatorGlyph::COLD:     return "COLD";
        case OperatorGlyph::HOT:      return "HOT";
        case OperatorGlyph::VERIFIED: return "VERIFIED";
        case OperatorGlyph::STAR:     return "STAR";
    }
    return "UNKNOWN";
}

// Display alias. Never an authority; never parsed.
[[nodiscard]]
constexpr const wchar_t* glyph(OperatorGlyph op) noexcept
{
    switch (op)
    {
        case OperatorGlyph::UN:       return L"\u2298"; // circled slash
        case OperatorGlyph::NU:       return L"\u2295"; // circled plus
        case OperatorGlyph::EXTEND:   return L"\u2197"; // north east arrow
        case OperatorGlyph::REACH:    return L"\u2192"; // right arrow
        case OperatorGlyph::STATED:   return L"\u25CE"; // bullseye
        case OperatorGlyph::COLD:     return L"\u25C7"; // white diamond
        case OperatorGlyph::HOT:      return L"\u25C6"; // black diamond
        case OperatorGlyph::VERIFIED: return L"\u2713"; // check mark
        case OperatorGlyph::STAR:     return L"\u2605"; // black star
    }
    return L"";
}

// The NU-extension path, in operator-identity terms.
inline constexpr OperatorGlyph kNuExtensionPath[] = {
    OperatorGlyph::UN,
    OperatorGlyph::NU,
    OperatorGlyph::EXTEND,
    OperatorGlyph::REACH,
    OperatorGlyph::STATED,
    OperatorGlyph::COLD,
    OperatorGlyph::HOT,
    OperatorGlyph::VERIFIED,
    OperatorGlyph::STAR
};

// Renders the ASCII form. This is what a receipt should store.
[[nodiscard]]
inline std::string asciiPath(const OperatorGlyph* path, std::size_t n)
{
    std::string out;
    for (std::size_t i = 0; i < n; ++i)
    {
        if (i != 0)
            out += ',';
        out += asciiName(path[i]);
    }
    return out;
}

// Renders the glyph form. Display only -- never round-tripped back to an
// operator, and never compared to decide anything.
[[nodiscard]]
inline std::wstring glyphPath(const OperatorGlyph* path, std::size_t n)
{
    std::wstring out;
    for (std::size_t i = 0; i < n; ++i)
        out += glyph(path[i]);
    return out;
}

// ===========================================================================
// Evidence
//
// A verdict is never produced by construction. Every field here must come from
// something actually observed. `provesExecution()` is the only path to
// Verified, and it requires a NON-ZERO output count -- an output *string* is
// not proof.
// ===========================================================================

struct Evidence {
    bool executed = false;
    bool producedOutput = false;
    bool measurementPresent = false;
    bool callbacksObserved = false;
    std::uint64_t outputCount = 0;
    std::string detail;

    [[nodiscard]]
    bool provesExecution() const noexcept {
        return executed
            && producedOutput
            && measurementPresent
            && outputCount > 0;
    }
};

struct Root {
    std::string id;
    RootState state = RootState::Missing;
    ProofState proof = ProofState::Unknown;

    // Root-local executable capability.
    std::function<Evidence()> execute;

    [[nodiscard]]
    bool executable() const noexcept {
        return state == RootState::Executable
            && static_cast<bool>(execute);
    }
};

struct Alias {
    std::string mapKey;
    std::string rootId;

    // New aliases enter cold. Creation is never promotion.
    bool cold = true;
    bool hot = false;
};

struct Word {
    // Surface representation / claim.
    std::string text;
};

struct Toor {
    // Actual producer/root behind WORD.
    std::string rootId;
    bool resolved = false;
};

struct ScrapeLine {
    std::string text;
    bool structural = false;
};

struct ExecutionResult {
    bool success = false;
    bool created = false;
    bool looted = false;
    bool bypassed = false;
    bool bound = false;
    bool hotpatched = false;
    bool verified = false;

    std::string rootId;
    Evidence evidence;
    std::string reason;
};

using RootFactory =
    std::function<std::optional<Root>(std::string_view mapKey)>;

using DrowResolver =
    std::function<std::optional<std::string>(std::string_view word)>;

// ===========================================================================
// StaticMap
//
// The ledger / authority inventory is a STATIC MAP. It names known roots and
// aliases. It is not itself execution proof.
// ===========================================================================

class StaticMap {
public:
    bool addRoot(Root root) {
        if (root.id.empty())
            return false;

        return roots_.emplace(root.id, std::move(root)).second;
    }

    bool addAlias(Alias alias) {
        if (alias.mapKey.empty() || alias.rootId.empty())
            return false;

        aliases_[alias.mapKey] = std::move(alias);
        return true;
    }

    [[nodiscard]]
    Root* root(std::string_view id) {
        auto it = roots_.find(std::string(id));
        return it == roots_.end() ? nullptr : &it->second;
    }

    [[nodiscard]]
    const Root* root(std::string_view id) const {
        auto it = roots_.find(std::string(id));
        return it == roots_.end() ? nullptr : &it->second;
    }

    [[nodiscard]]
    Alias* alias(std::string_view key) {
        auto it = aliases_.find(std::string(key));
        return it == aliases_.end() ? nullptr : &it->second;
    }

    [[nodiscard]]
    const Alias* alias(std::string_view key) const {
        auto it = aliases_.find(std::string(key));
        return it == aliases_.end() ? nullptr : &it->second;
    }

    [[nodiscard]]
    MapState state(std::string_view key) const {
        return alias(key) ? MapState::Seen : MapState::Unseen;
    }

    [[nodiscard]]
    const auto& aliases() const noexcept {
        return aliases_;
    }

private:
    std::unordered_map<std::string, Root> roots_;
    std::unordered_map<std::string, Alias> aliases_;
};

// ===========================================================================
// OperatorSystem
// ===========================================================================

class OperatorSystem {
public:
    explicit OperatorSystem(StaticMap& map)
        : map_(map) {}

    void setDrowResolver(DrowResolver resolver) {
        drowResolver_ = std::move(resolver);
    }

    void setRootFactory(RootFactory factory) {
        rootFactory_ = std::move(factory);
    }

    // -------------------------------------------------------------------------
    // DROW — reverse a known WORD to its producer/root.
    //
    //   WORD != TOOR
    //   WORD is surface.  TOOR is cause.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    Toor drow(const Word& word) const {
        if (!drowResolver_)
            return {};

        auto rootId = drowResolver_(word.text);
        if (!rootId)
            return {};

        return Toor{
            .rootId = std::move(*rootId),
            .resolved = true
        };
    }

    // -------------------------------------------------------------------------
    // NU-DROW = REVERSE-SCRAPE
    //
    // Unknown/unmapped reverse traversal. It does NOT manufacture a root; it
    // searches structural material for a root/capability edge.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    static std::optional<ScrapeLine>
    nuDrowReverseScrape(const std::vector<std::string>& lines) {
        // Reverse because NU-DROW walks surface history toward origin.
        for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
            auto scraped = unbindOneLine(*it);

            if (scraped && scraped->structural)
                return scraped;
        }

        return std::nullopt;
    }

    // -------------------------------------------------------------------------
    // UN-BIND </>
    //
    // One-line structural scrape. Plain prose is ignored.
    //
    // This deliberately does NOT attempt full natural-language interpretation.
    // The structural predicate is intentionally conservative and must not be
    // widened into an NLU pass without measurement.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    static std::optional<ScrapeLine>
    unbindOneLine(std::string_view line) {
        auto trim = [](std::string_view v) -> std::string_view {
            while (!v.empty() &&
                   (v.front() == ' ' ||
                    v.front() == '\t' ||
                    v.front() == '\r' ||
                    v.front() == '\n')) {
                v.remove_prefix(1);
            }

            while (!v.empty() &&
                   (v.back() == ' ' ||
                    v.back() == '\t' ||
                    v.back() == '\r' ||
                    v.back() == '\n')) {
                v.remove_suffix(1);
            }

            return v;
        };

        line = trim(line);

        if (line.empty())
            return std::nullopt;

        // "</>" boundary: do not trust prose as executable structure.
        const bool structural =
            line.find("->") != std::string_view::npos ||
            line.find("::") != std::string_view::npos ||
            line.find('(')  != std::string_view::npos ||
            line.find('=')  != std::string_view::npos ||
            line.find("BIND") != std::string_view::npos ||
            line.find("CREATE") != std::string_view::npos ||
            line.find("LOOT") != std::string_view::npos ||
            line.find("DROW") != std::string_view::npos ||
            line.find("TOOR") != std::string_view::npos ||
            line.find("ON") != std::string_view::npos;

        if (!structural)
            return std::nullopt;

        return ScrapeLine{
            .text = std::string(line),
            .structural = true
        };
    }

    // -------------------------------------------------------------------------
    // LOOT — SEEN -> LOOT. Reuse an existing per-map alias/root.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    Root* loot(std::string_view mapKey) {
        Alias* a = map_.alias(mapKey);
        if (!a)
            return nullptr;

        return map_.root(a->rootId);
    }

    // -------------------------------------------------------------------------
    // CRE / CREATE — UNSEEN -> CREATE
    //
    // Creates a new map-local COLD root. CREATE != PASS.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    Root* create(std::string_view mapKey) {
        if (!rootFactory_)
            return nullptr;

        auto candidate = rootFactory_(mapKey);
        if (!candidate)
            return nullptr;

        if (candidate->id.empty())
            return nullptr;

        candidate->proof = ProofState::Cold;

        const std::string rootId = candidate->id;

        if (!map_.addRoot(std::move(*candidate)))
            return nullptr;

        Alias alias{
            .mapKey = std::string(mapKey),
            .rootId = rootId,
            .cold = true,
            .hot = false
        };

        if (!map_.addAlias(std::move(alias)))
            return nullptr;

        return map_.root(rootId);
    }

    // CRE is the explicit compute-authority creation spelling.
    [[nodiscard]]
    Root* cre(std::string_view mapKey) {
        return create(mapKey);
    }

    // -------------------------------------------------------------------------
    // BIND — creation alone is not activation. COLD -> BOUND.
    // -------------------------------------------------------------------------

    bool bind(std::string_view mapKey) {
        Alias* a = map_.alias(mapKey);
        if (!a)
            return false;

        Root* root = map_.root(a->rootId);
        if (!root)
            return false;

        if (!root->execute)
            return false;

        root->state = RootState::Executable;
        root->proof = ProofState::Bound;

        return true;
    }

    // -------------------------------------------------------------------------
    // HOTPATCH — attach a newly created capability into the live path.
    //
    // "hot" means attached to the active execution graph, NOT runtime
    // certified. HOTPATCH != PASS.
    // -------------------------------------------------------------------------

    bool hotpatch(std::string_view mapKey) {
        Alias* a = map_.alias(mapKey);
        if (!a)
            return false;

        Root* root = map_.root(a->rootId);
        if (!root)
            return false;

        if (!bind(mapKey))
            return false;

        a->hot = true;

        return true;
    }

    // -------------------------------------------------------------------------
    // ON — ENGINE = ON. Execute the selected root.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    Evidence on(Root& root) {
        if (!root.executable())
            return Evidence{
                .detail = "root_not_executable"
            };

        Evidence evidence = root.execute();

        root.proof =
            evidence.executed
                ? ProofState::Executed
                : ProofState::Failed;

        return evidence;
    }

    // -------------------------------------------------------------------------
    // VERIFY
    //
    // No output string gets promoted to PASS by construction. Evidence must
    // prove real execution with a non-zero output count.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    bool verify(Root& root, const Evidence& evidence) {
        const bool pass = evidence.provesExecution();

        root.proof =
            pass
                ? ProofState::Verified
                : ProofState::Failed;

        return pass;
    }

    // -------------------------------------------------------------------------
    // SKIP = BY(PASS)E
    //
    // SKIP does NOT drop the branch. It:
    //   1. tries another existing mapped root   (LOOT)
    //   2. otherwise CREATEs its own missing capability
    //   3. BIND / HOTPATCH
    //   4. executes
    //   5. verifies
    //
    // BYPASS = pass by another proven path.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    ExecutionResult bypass(std::string_view mapKey) {
        ExecutionResult result;
        result.bypassed = true;

        Root* root = nullptr;

        if (map_.state(mapKey) == MapState::Seen) {
            root = loot(mapKey);
            result.looted = (root != nullptr);
        } else {
            root = cre(mapKey);
            result.created = (root != nullptr);
        }

        if (!root) {
            result.reason = "no_existing_or_creatable_root";
            return result;
        }

        result.rootId = root->id;

        // A created COLD root still needs activation.
        if (!root->executable()) {
            if (!hotpatch(mapKey)) {
                result.reason = "bind_or_hotpatch_failed";
                return result;
            }

            result.bound = true;
            result.hotpatched = true;
        }

        result.evidence = on(*root);

        if (!verify(*root, result.evidence)) {
            result.reason = "alternate_root_execution_unverified";
            return result;
        }

        // Promote out of cold ONLY after proof. This is per-map; there is no
        // global promotion path.
        if (Alias* alias = map_.alias(mapKey)) {
            alias->cold = false;
            alias->hot = true;
        }

        result.verified = true;
        result.success = true;
        result.reason = "alternate_root_verified";

        return result;
    }

    [[nodiscard]]
    ExecutionResult skip(std::string_view mapKey) {
        return bypass(mapKey);
    }

    // -------------------------------------------------------------------------
    // Resolve a map node:  SEEN -> LOOT,  UNSEEN -> CRE
    // -------------------------------------------------------------------------

    [[nodiscard]]
    Root* resolve(std::string_view mapKey) {
        if (map_.state(mapKey) == MapState::Seen)
            return loot(mapKey);

        return cre(mapKey);
    }

    // -------------------------------------------------------------------------
    // BOW-RAIN("*") — traverse all mapped aliases.
    //
    // STAR does NOT mean "assume all pass." Each node executes and verifies
    // independently; there is no aggregate verdict that can hide a failing
    // node.
    // -------------------------------------------------------------------------

    [[nodiscard]]
    std::vector<ExecutionResult>
    bowRainStar() {
        std::vector<std::string> keys;
        keys.reserve(map_.aliases().size());

        // Snapshot keys because traversal may mutate aliases later.
        for (const auto& entry : map_.aliases()) {
            keys.push_back(entry.first);
        }

        std::vector<ExecutionResult> results;
        results.reserve(keys.size());

        for (const std::string& key : keys) {
            ExecutionResult r;

            Root* root = loot(key);

            if (!root) {
                r = bypass(key);
                results.push_back(std::move(r));
                continue;
            }

            r.rootId = root->id;
            r.looted = true;

            if (!root->executable()) {
                r = bypass(key);
                results.push_back(std::move(r));
                continue;
            }

            r.evidence = on(*root);
            r.verified = verify(*root, r.evidence);
            r.success = r.verified;
            r.reason = r.success ? "star_node_verified"
                                 : "star_node_unverified";

            results.push_back(std::move(r));
        }

        return results;
    }

    // -------------------------------------------------------------------------
    // Full operator chain:
    //
    //   WORD -> DROW -> TOOR -> executable?
    //       YES -> ON -> VERIFY
    //       NO  -> SKIP/BY(PASS)E -> LOOT/CREATE -> BIND -> ON -> VERIFY
    // -------------------------------------------------------------------------

    [[nodiscard]]
    ExecutionResult executeWord(const Word& word) {
        ExecutionResult result;

        Toor toor = drow(word);

        if (!toor.resolved) {
            result.reason = "drow_unresolved";
            return result;
        }

        result.rootId = toor.rootId;

        Root* root = map_.root(toor.rootId);

        // TOOR points somewhere not yet materialised, or the root is blocked.
        if (!root || !root->executable())
            return skip(toor.rootId);

        result.evidence = on(*root);
        result.verified = verify(*root, result.evidence);
        result.success = result.verified;

        result.reason =
            result.success
                ? "root_verified"
                : "root_execution_failed_verification";

        return result;
    }

private:
    StaticMap& map_;
    DrowResolver drowResolver_;
    RootFactory rootFactory_;
};

} // namespace rawrxd::operators