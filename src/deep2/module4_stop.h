// =============================================================================
// Module 4: Stop String Matcher
// Trie-based multi-pattern matcher for stop sequences.
// Tracks partial matches across token boundaries.
// No external dependencies.
// =============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>

class StopStringMatcher {
public:
    StopStringMatcher() : root_(new Node) {}

    void addStopString(const std::string& stop) {
        if (stop.empty()) return;
        Node* cur = root_.get();
        for (char ch : stop) {
            auto it = cur->children.find(ch);
            if (it == cur->children.end()) {
                Node* child = new Node;
                cur->children[ch] = child;
                cur = child;
            } else {
                cur = it->second;
            }
        }
        cur->isTerminal = true;
        cur->stopString = stop;
    }

    // Feed a single character. Returns true if a stop string was matched.
    // If matched, 'matchedStop' is filled with the matched stop string.
    bool feed(char ch, std::string& matchedStop) {
        // Try to extend current active nodes
        std::vector<Node*> nextActive;
        bool matched = false;

        // Always start fresh from root as well
        auto rootIt = root_>children.find(ch);
        if (rootIt != root_>children.end()) {
            nextActive.push_back(rootIt->second);
            if (rootIt->second->isTerminal) {
                matchedStop = rootIt->second->stopString;
                matched = true;
            }
        }

        for (Node* node : active_) {
            auto it = node->children.find(ch);
            if (it != node->children.end()) {
                nextActive.push_back(it->second);
                if (it->second->isTerminal && !matched) {
                    matchedStop = it->second->stopString;
                    matched = true;
                }
            }
        }

        active_ = std::move(nextActive);
        return matched;
    }

    // Feed a string. Returns true if any stop string matched.
    // 'consumed' is set to the number of characters consumed before
    // the match (or full length if no match).
    bool feedString(const std::string& text, size_t& consumed, std::string& matchedStop) {
        for (size_t i = 0; i < text.size(); ++i) {
            if (feed(text[i], matchedStop)) {
                consumed = i + 1;
                return true;
            }
        }
        consumed = text.size();
        return false;
    }

    void reset() {
        active_.clear();
    }

    bool hasStopStrings() const {
        return !root_>children.empty();
    }

private:
    struct Node {
        std::map<char, Node*> children;
        bool isTerminal = false;
        std::string stopString;

        ~Node() {
            for (auto& kv : children) {
                delete kv.second;
            }
        }
    };

    std::unique_ptr<Node> root_;
    std::vector<Node*> active_;
};
