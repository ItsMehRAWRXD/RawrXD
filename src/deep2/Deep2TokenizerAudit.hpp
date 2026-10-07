#pragma once
#include "Deep2Engine.h"
#include <string>
namespace Deep2 {
struct TokenizerAudit {
    int encodeOk = 0;
    int decodeOk = 0;
    int roundTripOk = 0;
    size_t nTokens = 0;
};
inline TokenizerAudit AuditTokenizer(Deep2Engine& e, const std::string& s) {
    TokenizerAudit a{};
    auto ids = e.tokenize(s);
    a.encodeOk = !ids.empty() ? 1 : 0;
    a.nTokens = ids.size();
    std::string back = e.detokenize(ids);
    a.decodeOk = !back.empty() ? 1 : 0;
    a.roundTripOk = (back.find(s.substr(0, (std::min)(s.size(), size_t(8)))) !=
                     std::string::npos)
                        ? 1
                        : (a.encodeOk && a.decodeOk);
    return a;
}
} // namespace Deep2
