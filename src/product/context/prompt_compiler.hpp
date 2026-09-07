#pragma once
#include "file_window.hpp"
#include "priority_ranker.hpp"
#include <string>
#include <vector>
namespace rawr::product {

enum class CtxStrategy : uint8_t { Completion = 0, Chat = 1, Agent = 2, Debug = 3 };

inline std::string CompilePrompt(CtxStrategy st, const FileWindow& w,
                                 const std::vector<CtxItem>& packed,
                                 const std::string& query) {
    std::string p;
    if (st == CtxStrategy::Completion) {
        p += "<PRE>\n" + w.before + "\n<SUF>\n" + w.after + "\n<MID>\n";
        return p;
    }
    p += "FILE " + w.path + " L" + std::to_string(w.cursorLine) + "\n";
    for (const auto& it : packed) {
        p += "## " + it.kind + " " + it.source + "\n" + it.text + "\n";
    }
    if (st == CtxStrategy::Debug) p += "DIAGNOSE AND FIX WITH EVIDENCE.\n";
    if (st == CtxStrategy::Agent) p += "PLAN THEN EDIT THEN BUILD THEN TEST.\n";
    if (!query.empty()) p += "USER:\n" + query + "\n";
    if (!w.before.empty()) {
        p += "CURSOR_PREFIX:\n";
        p += w.before.size() > 1200 ? w.before.substr(w.before.size() - 1200)
                                    : w.before;
        p += "\n";
    }
    return p;
}

} // namespace rawr::product
