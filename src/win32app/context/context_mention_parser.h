#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Context {

struct Mention {
    std::string text;
    std::string type;
    int position;
    int length;
};

struct MentionParseResult {
    std::vector<Mention> mentions;
    std::string cleanedText;
};

class ContextMentionParser {
public:
    MentionParseResult Parse(const std::string& text);
};

} // namespace Context
} // namespace RawrXD
