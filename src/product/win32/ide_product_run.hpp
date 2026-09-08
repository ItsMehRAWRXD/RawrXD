#pragma once
#include "../../deep2/lavapath/ProductRun.hpp"
namespace rawr::product {

inline product_run::Result IdeProductRun(const char* alias, const char* prompt) {
    product_run::Request req{};
    req.modelAlias = alias;
    req.prompt = prompt;
    req.maxTokens = 256;
    return product_run::ProductRun(req);
}

} // namespace rawr::product
