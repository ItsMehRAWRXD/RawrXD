#pragma once
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace RawrXD::Finish {

enum class EndReason : uint8_t {
    Eos,
    MaxTokens,
    Cancelled,
    Error
};

enum class BlockOwner : uint8_t {
    None,
    Discovery,
    FormatShardResolution,
    ArchContract,
    QuantContract,
    TokenizerContract,
    TensorSchema,
    Deep2Session,
    Prefill,
    Stream,
    TokenCallback,
    Cancel,
    Teardown,
    Reload
};

inline const char* OwnerName(BlockOwner o) noexcept {
    switch (o) {
        case BlockOwner::Discovery:             return "DISCOVERY";
        case BlockOwner::FormatShardResolution: return "FORMAT_SHARD_RESOLUTION";
        case BlockOwner::ArchContract:          return "ARCH_CONTRACT";
        case BlockOwner::QuantContract:         return "QUANT_CONTRACT";
        case BlockOwner::TokenizerContract:     return "TOKENIZER_TEMPLATE_EOG_CONTRACT";
        case BlockOwner::TensorSchema:          return "TENSOR_SCHEMA";
        case BlockOwner::Deep2Session:          return "DEEP2_SESSION";
        case BlockOwner::Prefill:               return "PREFILL";
        case BlockOwner::Stream:                return "GENERATE_STREAM";
        case BlockOwner::TokenCallback:         return "TOKEN_CALLBACK";
        case BlockOwner::Cancel:                return "CANCEL";
        case BlockOwner::Teardown:              return "TEARDOWN";
        case BlockOwner::Reload:                return "RELOAD";
        default:                                return "NONE";
    }
}

struct TensorBinding {
    std::string logical_name;
    std::string tensor_name;
    std::string quant_type;
    std::vector<int64_t> shape;
};

struct Authority {
    std::string canonical_model;
    std::vector<std::string> canonical_shards;

    std::string architecture;
    int64_t layers = 0;
    int64_t hidden = 0;
    int64_t ffn = 0;
    int64_t heads = 0;
    int64_t kv_heads = 0;
    int64_t head_dim = 0;
    int64_t context = 0;

    std::string tokenizer_model;
    std::string chat_template;
    std::unordered_set<int64_t> eog_ids;

    std::vector<TensorBinding> mandatory_tensors;

    bool split_model = false;
    bool format_resolved = false;
    bool quant_contract_complete = false;
    bool tokenizer_contract_complete = false;
    bool tensor_schema_complete = false;
};

struct ValidateResult {
    bool ok = false;
    BlockOwner owner = BlockOwner::None;
    std::string reason;
};

inline ValidateResult ValidateAuthority(const Authority& a) {
    if (a.canonical_model.empty())
        return {false, BlockOwner::Discovery, "canonical model path is empty"};
    if (a.split_model && a.canonical_shards.empty())
        return {false, BlockOwner::FormatShardResolution, "split model has no canonical shard set"};
    if (!a.format_resolved)
        return {false, BlockOwner::FormatShardResolution, "format/shard resolution incomplete"};

    if (a.architecture.empty())
        return {false, BlockOwner::ArchContract, "architecture missing"};
    if (a.layers <= 0 || a.hidden <= 0 || a.ffn <= 0 ||
        a.heads <= 0 || a.kv_heads <= 0 || a.head_dim <= 0 || a.context <= 0)
        return {false, BlockOwner::ArchContract, "architecture geometry contains zero/negative field"};
    if (a.kv_heads > a.heads)
        return {false, BlockOwner::ArchContract, "kv_heads > heads"};
    if ((a.heads % a.kv_heads) != 0)
        return {false, BlockOwner::ArchContract, "heads is not divisible by kv_heads"};
    if (a.hidden != a.heads * a.head_dim)
        return {false, BlockOwner::ArchContract, "hidden != heads * head_dim"};

    if (!a.quant_contract_complete)
        return {false, BlockOwner::QuantContract, "quant contract incomplete"};

    if (!a.tokenizer_contract_complete)
        return {false, BlockOwner::TokenizerContract, "tokenizer/template/EOG contract incomplete"};
    if (a.tokenizer_model.empty())
        return {false, BlockOwner::TokenizerContract, "tokenizer model missing"};
    if (a.eog_ids.empty())
        return {false, BlockOwner::TokenizerContract, "EOG token set empty"};

    if (!a.tensor_schema_complete)
        return {false, BlockOwner::TensorSchema, "tensor schema incomplete"};
    if (a.mandatory_tensors.empty())
        return {false, BlockOwner::TensorSchema, "mandatory tensor set empty"};

    std::unordered_set<std::string> logical;
    for (const auto& t : a.mandatory_tensors) {
        if (t.logical_name.empty() || t.tensor_name.empty())
            return {false, BlockOwner::TensorSchema, "tensor binding has empty logical or physical name"};
        if (t.quant_type.empty())
            return {false, BlockOwner::QuantContract, "tensor binding has no quant type: " + t.tensor_name};
        if (t.shape.empty())
            return {false, BlockOwner::TensorSchema, "tensor binding has no shape: " + t.tensor_name};
        if (!logical.insert(t.logical_name).second)
            return {false, BlockOwner::TensorSchema, "duplicate mandatory logical binding: " + t.logical_name};
        for (auto d : t.shape)
            if (d <= 0)
                return {false, BlockOwner::TensorSchema, "non-positive tensor dimension: " + t.tensor_name};
    }

    return {true, BlockOwner::None, {}};
}

struct StreamToken {
    int64_t token_id = -1;
    std::string decoded;
};

struct StreamResult {
    EndReason reason = EndReason::Error;
    uint32_t tokens = 0;
    std::string error;
};

using SessionId = uint64_t;
static constexpr SessionId kInvalidSession = 0;

struct Deep2Binding {
    // All callbacks MUST bind to the real Deep2 product path.
    // No callback may route to a compatibility generator or synthetic decoder.
    std::function<std::optional<SessionId>(const Authority&, std::string&)> create_session;
    std::function<bool(SessionId, std::string_view, std::string&)> prefill;
    std::function<StreamResult(SessionId, uint32_t,
                               const std::function<bool(const StreamToken&)>&)> generate_stream;
    std::function<bool(SessionId, std::string&)> request_cancel;
    std::function<bool(SessionId, std::string&)> unload;
};

struct RunOptions {
    std::string prompt;
    uint32_t max_tokens = 256;
    uint32_t reload_tokens = 8;
    uint32_t cancel_after_tokens = 1;
    bool require_cancel_probe = true;
    bool require_reload_probe = true;
};

struct Receipt {
    bool pass = false;
    BlockOwner blocked_owner = BlockOwner::None;
    std::string blocked_at;
    std::string reason;
    std::string first_delta;

    bool one_local_model_authority = false;
    bool one_active_deep2_session = false;
    bool real_prefill = false;
    bool deep2_generate_stream = false;
    bool real_token_callback = false;
    bool bounded_completion = false;
    bool cancel_works = false;
    bool clean_unload = false;
    bool reload_generate_works = false;

    EndReason baseline_end = EndReason::Error;
    uint32_t baseline_tokens = 0;
    uint32_t decoded_callback_bytes = 0;
    std::string decoded_text;

    std::string ToText() const {
        auto yes = [](bool v) { return v ? "1" : "0"; };
        auto end = [](EndReason e) {
            switch (e) {
                case EndReason::Eos:       return "EOS";
                case EndReason::MaxTokens: return "MAX_TOKENS";
                case EndReason::Cancelled: return "CANCELLED";
                default:                   return "ERROR";
            }
        };

        std::ostringstream o;
        if (pass) {
            o << "LOCAL_MODEL_E2E=PASS\n";
        } else {
            o << "LOCAL_MODEL_E2E=BLOCKED\n";
            o << "BLOCKED_AT=" << blocked_at << "\n";
            o << "BLOCKED_OWNER=" << OwnerName(blocked_owner) << "\n";
            o << "REASON=" << reason << "\n";
            o << "FIRST_DELTA=" << first_delta << "\n";
        }
        o << "ONE_LOCAL_MODEL_AUTHORITY=" << yes(one_local_model_authority) << "\n";
        o << "ONE_ACTIVE_DEEP2_SESSION=" << yes(one_active_deep2_session) << "\n";
        o << "REAL_PREFILL=" << yes(real_prefill) << "\n";
        o << "DEEP2_GENERATE_STREAM=" << yes(deep2_generate_stream) << "\n";
        o << "REAL_TOKEN_CALLBACK=" << yes(real_token_callback) << "\n";
        o << "BASELINE_END=" << end(baseline_end) << "\n";
        o << "BASELINE_TOKENS=" << baseline_tokens << "\n";
        o << "DECODED_CALLBACK_BYTES=" << decoded_callback_bytes << "\n";
        o << "BOUNDED_COMPLETION=" << yes(bounded_completion) << "\n";
        o << "CANCEL_WORKS=" << yes(cancel_works) << "\n";
        o << "CLEAN_UNLOAD=" << yes(clean_unload) << "\n";
        o << "RELOAD_GENERATE_WORKS=" << yes(reload_generate_works) << "\n";
        return o.str();
    }
};

class LocalModelExecutor {
public:
    explicit LocalModelExecutor(Deep2Binding binding)
        : binding_(std::move(binding)) {}

    Receipt Run(const Authority& authority, const RunOptions& opt) {
        Receipt r;

        if (!BindingsComplete()) {
            return Block(r, BlockOwner::Deep2Session, "DEEP2_BINDING",
                         "one or more real Deep2 callbacks are not bound",
                         "bind ProductRuntime/Deep2 callbacks; do not add a fallback generator");
        }

        const auto vr = ValidateAuthority(authority);
        if (!vr.ok) {
            return Block(r, vr.owner, OwnerName(vr.owner), vr.reason,
                         "repair the first incomplete authority contract and rerun the same execution");
        }
        r.one_local_model_authority = true;

        if (opt.prompt.empty())
            return Block(r, BlockOwner::Prefill, "PREFILL", "prompt is empty",
                         "supply the product prompt to the same Deep2 session");
        if (opt.max_tokens == 0)
            return Block(r, BlockOwner::Stream, "GENERATE_STREAM", "max_tokens is zero",
                         "use the canonical positive token budget");

        std::string err;
        SessionId session = Create(authority, r, err, BlockOwner::Deep2Session, "CREATE_SESSION");
        if (session == kInvalidSession) return r;

        if (!binding_.prefill(session, opt.prompt, err)) {
            BestEffortUnload(session);
            return Block(r, BlockOwner::Prefill, "REAL_PREFILL", err.empty() ? "prefill failed" : err,
                         "fix Deep2 prefill on the canonical authority; do not route around it");
        }
        r.real_prefill = true;

        uint32_t decoded_bytes = 0;
        std::string decoded;
        auto baseline_cb = [&](const StreamToken& t) -> bool {
            if (t.token_id < 0) return false;
            if (!t.decoded.empty()) {
                decoded_bytes += static_cast<uint32_t>(t.decoded.size());
                decoded += t.decoded;
            }
            return true;
        };

        auto baseline = binding_.generate_stream(session, opt.max_tokens, baseline_cb);
        r.deep2_generate_stream = true;
        r.baseline_end = baseline.reason;
        r.baseline_tokens = baseline.tokens;
        r.decoded_callback_bytes = decoded_bytes;
        r.decoded_text = decoded;

        if (baseline.reason == EndReason::Error) {
            BestEffortUnload(session);
            return Block(r, BlockOwner::Stream, "DEEP2_GENERATE_STREAM",
                         baseline.error.empty() ? "generateStream returned ERROR" : baseline.error,
                         "fix the first Deep2 stream failure; compatibility paths are not completion");
        }
        if (baseline.tokens == 0) {
            BestEffortUnload(session);
            return Block(r, BlockOwner::TokenCallback, "REAL_TOKEN_CALLBACK",
                         "stream completed without a token callback",
                         "connect the real sampler/token callback from the same Deep2 session");
        }
        if (decoded_bytes == 0) {
            BestEffortUnload(session);
            return Block(r, BlockOwner::TokenCallback, "REAL_TOKEN_CALLBACK",
                         "token callbacks contained no decoded model bytes",
                         "bind the model-derived tokenizer decoder to the Deep2 token callback");
        }
        r.real_token_callback = true;

        if (baseline.reason != EndReason::Eos && baseline.reason != EndReason::MaxTokens) {
            BestEffortUnload(session);
            return Block(r, BlockOwner::Stream, "BOUNDED_COMPLETION",
                         "baseline ended without EOS or max-token completion",
                         "make Deep2 terminate only on model EOG, canonical token budget, cancel, or error");
        }
        r.bounded_completion = true;

        // Cancel is proven against a real active generation, never by toggling an idle flag.
        if (opt.require_cancel_probe) {
            if (!RunCancelProbe(session, opt, r)) {
                BestEffortUnload(session);
                return r;
            }
        } else {
            r.cancel_works = true;
        }

        err.clear();
        if (!binding_.unload(session, err)) {
            return Block(r, BlockOwner::Teardown, "CLEAN_UNLOAD",
                         err.empty() ? "Deep2 unload failed" : err,
                         "fix product-session teardown before constructing a replacement session");
        }
        active_session_ = kInvalidSession;
        r.clean_unload = true;

        if (opt.require_reload_probe) {
            if (!RunReloadProbe(authority, opt, r)) return r;
        } else {
            r.reload_generate_works = true;
        }

        r.pass =
            r.one_local_model_authority &&
            r.one_active_deep2_session &&
            r.real_prefill &&
            r.deep2_generate_stream &&
            r.real_token_callback &&
            r.bounded_completion &&
            r.cancel_works &&
            r.clean_unload &&
            r.reload_generate_works;

        if (!r.pass) {
            return Block(r, BlockOwner::Deep2Session, "FINAL_ACCEPTANCE",
                         "one or more mandatory execution witnesses are false",
                         "fix the first false execution witness; do not add another independent gate");
        }
        return r;
    }

private:
    Deep2Binding binding_;
    SessionId active_session_ = kInvalidSession;

    bool BindingsComplete() const {
        return static_cast<bool>(binding_.create_session) &&
               static_cast<bool>(binding_.prefill) &&
               static_cast<bool>(binding_.generate_stream) &&
               static_cast<bool>(binding_.request_cancel) &&
               static_cast<bool>(binding_.unload);
    }

    Receipt Block(Receipt r, BlockOwner owner, std::string at,
                  std::string reason, std::string first_delta) const {
        r.pass = false;
        r.blocked_owner = owner;
        r.blocked_at = std::move(at);
        r.reason = std::move(reason);
        r.first_delta = std::move(first_delta);
        return r;
    }

    SessionId Create(const Authority& authority, Receipt& r, std::string& err,
                     BlockOwner owner, const char* at) {
        if (active_session_ != kInvalidSession) {
            r = Block(r, owner, at,
                      "attempted to create a second concurrently active Deep2 session",
                      "destroy the previous ProductRuntime session before rebinding");
            return kInvalidSession;
        }

        auto s = binding_.create_session(authority, err);
        if (!s || *s == kInvalidSession) {
            r = Block(r, owner, at, err.empty() ? "Deep2 session creation failed" : err,
                      "fix ProductRuntime→Deep2 session creation for the canonical authority");
            return kInvalidSession;
        }

        active_session_ = *s;
        r.one_active_deep2_session = true;
        return *s;
    }

    bool RunCancelProbe(SessionId session, const RunOptions& opt, Receipt& r) {
        std::string err;
        if (!binding_.prefill(session, opt.prompt, err)) {
            r = Block(r, BlockOwner::Cancel, "CANCEL_PREFILL",
                      err.empty() ? "cancel probe prefill failed" : err,
                      "make repeat prefill/reset use the same active ProductRuntime session");
            return false;
        }

        uint32_t seen = 0;
        bool cancel_request_ok = false;
        auto cb = [&](const StreamToken&) -> bool {
            ++seen;
            if (seen >= std::max<uint32_t>(1, opt.cancel_after_tokens) && !cancel_request_ok) {
                std::string cancel_err;
                cancel_request_ok = binding_.request_cancel(session, cancel_err);
            }
            return true;
        };

        auto sr = binding_.generate_stream(
            session,
            std::max<uint32_t>(opt.max_tokens, opt.cancel_after_tokens + 8),
            cb);

        if (!cancel_request_ok) {
            r = Block(r, BlockOwner::Cancel, "CANCEL_REQUEST",
                      "request_cancel did not succeed during active generation",
                      "wire ProductRuntime cancel to the same Deep2 session used by generateStream");
            return false;
        }
        if (sr.reason != EndReason::Cancelled) {
            r = Block(r, BlockOwner::Cancel, "CANCEL_COMPLETION",
                      "generateStream did not terminate with CANCELLED",
                      "make Deep2 observe ProductRuntime cancellation inside the active stream loop");
            return false;
        }

        r.cancel_works = true;
        return true;
    }

    bool RunReloadProbe(const Authority& authority, const RunOptions& opt, Receipt& r) {
        std::string err;
        SessionId reloaded = Create(authority, r, err, BlockOwner::Reload, "RELOAD_CREATE_SESSION");
        if (reloaded == kInvalidSession) return false;

        if (!binding_.prefill(reloaded, opt.prompt, err)) {
            BestEffortUnload(reloaded);
            r = Block(r, BlockOwner::Reload, "RELOAD_PREFILL",
                      err.empty() ? "reload prefill failed" : err,
                      "fix model/session rebind so the canonical authority can prefill after unload");
            return false;
        }

        uint32_t callbacks = 0;
        uint32_t bytes = 0;
        auto cb = [&](const StreamToken& t) -> bool {
            ++callbacks;
            bytes += static_cast<uint32_t>(t.decoded.size());
            return t.token_id >= 0;
        };

        auto sr = binding_.generate_stream(
            reloaded,
            std::max<uint32_t>(1, opt.reload_tokens),
            cb);

        if (sr.reason == EndReason::Error || callbacks == 0 || bytes == 0) {
            BestEffortUnload(reloaded);
            r = Block(r, BlockOwner::Reload, "RELOAD_GENERATE",
                      sr.error.empty() ? "reload generation produced no real decoded output" : sr.error,
                      "fix unload→reload→prefill→generate on the same canonical model authority");
            return false;
        }
        if (sr.reason != EndReason::Eos && sr.reason != EndReason::MaxTokens) {
            BestEffortUnload(reloaded);
            r = Block(r, BlockOwner::Reload, "RELOAD_COMPLETION",
                      "reload generation did not terminate by EOS/max-token",
                      "fix the reloaded Deep2 stream termination path");
            return false;
        }

        err.clear();
        if (!binding_.unload(reloaded, err)) {
            r = Block(r, BlockOwner::Teardown, "RELOAD_FINAL_UNLOAD",
                      err.empty() ? "final unload after reload failed" : err,
                      "fix final ProductRuntime teardown");
            return false;
        }
        active_session_ = kInvalidSession;
        r.reload_generate_works = true;
        return true;
    }

    void BestEffortUnload(SessionId session) noexcept {
        if (session == kInvalidSession) return;
        try {
            std::string ignored;
            binding_.unload(session, ignored);
        } catch (...) {
        }
        active_session_ = kInvalidSession;
    }
};

} // namespace RawrXD::Finish
