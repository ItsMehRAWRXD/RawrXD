#pragma once
/* Build Finish::Authority from already-sealed olma contracts. ≤99. */
#include "LocalModelExecutionFinish.hpp"
#include "LocalModelAuthority_Seal.hpp"
#include "TensorNameTypeBinding_Bind.hpp"
#include "QuantDispatch_Seal.hpp"
#include "TokenizerTemplateEog_Seal.hpp"
#include "../QuantTypeTable.hpp"
#include <string>

namespace RawrXD::Finish {

struct AuthorityBuildResult {
    Authority a;
    bool ok = false;
    BlockOwner owner = BlockOwner::None;
    std::string reason;
};

inline AuthorityBuildResult BuildAuthorityFromPath(const char* path) {
    AuthorityBuildResult out;
    if (!path || !path[0]) {
        out.owner = BlockOwner::Discovery;
        out.reason = "canonical model path is empty";
        return out;
    }
    rawr::olma::GeomSeal geom{};
    if (!rawr::olma::SealFromPath(path, geom) || !geom.PASS) {
        out.owner = BlockOwner::ArchContract;
        out.reason = geom.REASON.empty() ? "geometry seal failed" : geom.REASON;
        return out;
    }
    Deep2::GGUFLoadResult load = Deep2::GGUFLoader::LoadMetadata(path);
    rawr::olma::SchemaSeal schema{};
    if (!rawr::olma::BindLlamaSchema(load, geom, path, schema) || !schema.PASS) {
        out.owner = BlockOwner::TensorSchema;
        out.reason = schema.REASON.empty() ? "tensor schema bind failed" : schema.REASON;
        return out;
    }
    rawr::olma::QuantDispatchSeal qd{};
    if (!rawr::olma::SealQuantDispatch(schema, qd) || !qd.PASS) {
        out.owner = BlockOwner::QuantContract;
        out.reason = qd.REASON.empty() ? "quant dispatch failed" : qd.REASON;
        return out;
    }
    rawr::olma::TokEogSeal tok{};
    if (!rawr::olma::SealTokEog(load, geom, schema, tok) || !tok.PASS) {
        out.owner = BlockOwner::TokenizerContract;
        out.reason = tok.REASON.empty() ? "tokenizer/EOG seal failed" : tok.REASON;
        return out;
    }
    Authority& a = out.a;
    a.canonical_model = path;
    a.format_resolved = true;
    a.split_model = false;
    a.architecture = geom.ARCH;
    a.layers = geom.LAYERS;
    a.hidden = geom.HIDDEN;
    a.ffn = geom.FFN;
    a.heads = geom.HEADS;
    a.kv_heads = geom.KV_HEADS;
    a.head_dim = geom.HEAD_DIM;
    a.context = geom.CONTEXT;
    a.tokenizer_model = tok.TOKENIZER_MODEL;
    a.eog_ids.insert(static_cast<int64_t>(tok.EOG_TOKEN_ID));
    if (load.rawKv.count("tokenizer.chat_template"))
        a.chat_template = load.rawKv.at("tokenizer.chat_template");
    else
        a.chat_template = load.metadata.chatTemplate;
    a.tokenizer_contract_complete = true;
    a.quant_contract_complete = true;
    for (const auto& b : schema.bindings) {
        TensorBinding t;
        t.logical_name = b.gguf_name; /* unique; roles repeat per layer */
        t.tensor_name = b.gguf_name;
        t.quant_type = Deep2::QuantTypeName(b.ggml_type);
        for (uint64_t d : b.dimensions) t.shape.push_back(static_cast<int64_t>(d));
        a.mandatory_tensors.push_back(std::move(t));
    }
    a.tensor_schema_complete = true;
    out.ok = true;
    return out;
}

} // namespace RawrXD::Finish
