#pragma once
#include "change_detector.hpp"
#include "context_cache.hpp"
#include "file_window.hpp"
#include "priority_ranker.hpp"
#include "prompt_compiler.hpp"
#include "token_budget.hpp"
#include <string>
#include <vector>
namespace rawr::product {

struct Assembled {
    std::string prompt;
    uint32_t tokens = 0;
    int cacheHit = 0;
    int changed = 0;
    std::vector<std::string> files;
};

struct ContextEngine {
    TokenBudget budget;
    ContextCache cache;
    ChangeDet change;
    uint64_t gen = 1;

    Assembled assemble(const EditorSnap& e, CtxStrategy st,
                       const std::vector<CtxItem>& extra,
                       const std::string& query) {
        Assembled a{};
        FileWindow w = FileWindow::fromSnap(e);
        std::string body = e.prefix + "\n" + e.suffix;
        a.changed = change.note(e.path, body, e.line, e.col) ? 1 : 0;
        if (a.changed) gen++;
        uint32_t key = ContextCache::makeKey(e.path, e.prefix, e.line);
        if (cache.get(key, gen, a.prompt)) {
            a.cacheHit = 1;
            a.tokens = EstTokens(a.prompt);
            return a;
        }
        std::vector<CtxItem> items = extra;
        CtxItem cur{CtxPri::Crit, "cursor", e.path, w.before, 0};
        items.insert(items.begin(), cur);
        for (const auto& d : e.diagnostics)
            items.push_back(CtxItem{CtxPri::High, "diag", e.path, d, 0});
        RankItems(items, e);
        TokenBudget b = budget;
        auto packed = PackBudget(items, b);
        a.prompt = CompilePrompt(st, w, packed, query);
        a.tokens = b.used;
        cache.put(key, gen, a.prompt);
        a.files.push_back(e.path);
        return a;
    }
};

} // namespace rawr::product
