#pragma once
#include "../../deep2/lavapath/ProductRun.hpp"
namespace rawr::product {

inline product_run::Result go(int agent, product_run::Request r) {
    return product_run::ProductRun(r);
}

inline product_run::Result AgentGenerate(const char* alias, const char* prompt) {
    product_run::Request r{};
    r.modelAlias = alias;
    r.prompt = prompt;
    r.maxTokens = 256;
    return go(1, r);
}

} // namespace rawr::product
