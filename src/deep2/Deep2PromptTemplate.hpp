#pragma once
#include "ChatTemplate.hpp"
#include "Deep2Engine.h"
#include <string>
#include <vector>
namespace Deep2 {
inline std::string Deep2ApplyPromptTemplate(const ModelMetadata& meta,
                                            const std::string& alias,
                                            const std::string& user) {
    ChatTemplate t;
    t.initFromMetadata(meta.architecture, alias.c_str(), meta.chatTemplate,
                       meta.bosToken, meta.eosToken);
    std::vector<ChatMessage> msgs{{"user", user, ""}};
    std::string out = t.format(msgs);
    return out.empty() ? user : out;
}
} // namespace Deep2
