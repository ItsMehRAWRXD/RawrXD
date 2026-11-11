#pragma once
#include "RawrRunSession.hpp"
#include <string>
#include <vector>
namespace Deep2 {
struct Deep2ChatTurn { std::string role; std::string content; };
struct Deep2ChatSession {
    Deep2Engine engine;
    rawr_run::RunWitness witness{};
    std::vector<Deep2ChatTurn> turns;
    bool open(const std::string& alias) {
        return rawr_run::OpenSession(engine, alias.c_str(), witness);
    }
    void add(const std::string& role, const std::string& content) {
        turns.push_back({role, content});
    }
    std::string formatLastUser() {
        std::string user = turns.empty() ? "Hello" : turns.back().content;
        return rawr_run::FormatChatPrompt(engine, user, &witness);
    }
    void close() { engine.unloadModel(); }
};
} // namespace Deep2
