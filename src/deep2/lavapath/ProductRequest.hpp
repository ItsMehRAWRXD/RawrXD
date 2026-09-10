#pragma once
/* Canonical product request — CLI/HTTP/IDE/serve map into this. ≤99 lines. */
#include "../Deep2Engine.h"
#include "ProductTokenBudget.hpp"
#include <cstdint>
#include <functional>
#include <string>

namespace rawr::product_run {

struct ProductRuntime;

using TokenFn = std::function<bool(const std::string& piece)>;

struct ProductRequest {
    const char* modelAlias = nullptr;
    const char* prompt = nullptr;
    uint32_t maxTokens = 0; /* 0 → unlimited when DEEP2_UNLIMITED_TOKENS=1 */
    ProductRuntime* runtime = nullptr;
    Deep2::Deep2Engine* engine = nullptr; /* BindExternal only; prefer runtime */
    int keepOpen = 1;
    int stream = 0;
    TokenFn onPiece;
};

inline TokenBudget BudgetFor(const ProductRequest& req, int envOverride = 0) {
    return ResolveTokenBudget(req.maxTokens, envOverride);
}

} // namespace rawr::product_run
