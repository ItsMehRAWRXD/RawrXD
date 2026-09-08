#pragma once
#include <string>
#include <vector>
namespace rawr::product {

struct ConversationHistory {
    std::vector<std::string> messages;
    void append(const std::string& role, const std::string& text) {
        messages.push_back(role + ": " + text);
    }
    void clear() { messages.clear(); }
    size_t size() const { return messages.size(); }
};

} // namespace rawr::product
