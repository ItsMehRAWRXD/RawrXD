#include "context_mention_parser.h"
#include <regex>

namespace RawrXD {
namespace Context {

MentionParseResult ContextMentionParser::Parse(const std::string& text) {
    MentionParseResult result;
    result.cleanedText = text;

    // Parse @mentions
    std::regex mentionRegex(R"(@(\w+))");
    auto words_begin = std::sregex_iterator(text.begin(), text.end(), mentionRegex);
    auto words_end = std::sregex_iterator();

    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::smatch match = *i;
        Mention m;
        m.text = match.str();
        m.type = "symbol";
        m.position = match.position();
        m.length = match.length();
        result.mentions.push_back(m);
    }

    return result;
}

} // namespace Context
} // namespace RawrXD
