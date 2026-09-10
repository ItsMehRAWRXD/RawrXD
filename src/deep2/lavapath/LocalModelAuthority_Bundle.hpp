#pragma once
/* SealAuthority — geometry+schema+quant+tok on one path. ≤99. */
#include "LocalModelAuthority_Seal.hpp"
#include "TensorNameTypeBinding_Bind.hpp"
#include "QuantDispatch_Seal.hpp"
#include "TokenizerTemplateEog_Seal.hpp"

namespace rawr::olma {

struct AuthorityBundle {
    GeomSeal geom{};
    SchemaSeal schema{};
    QuantDispatchSeal quant{};
    TokEogSeal tok{};
    int PASS = 0;
};

inline bool SealAuthorityBundle(const char* path, AuthorityBundle& a) {
    a = AuthorityBundle{};
    if (!path || !path[0]) return false;
    if (!SealFromPath(path, a.geom) || !a.geom.PASS) return false;
    Deep2::GGUFLoadResult load = Deep2::GGUFLoader::LoadMetadata(path);
    if (!BindLlamaSchema(load, a.geom, path, a.schema) || !a.schema.PASS) return false;
    if (!SealQuantDispatch(a.schema, a.quant) || !a.quant.PASS) return false;
    if (!SealTokEog(load, a.geom, a.schema, a.tok) || !a.tok.PASS) return false;
    a.PASS = 1;
    return true;
}

} // namespace rawr::olma
