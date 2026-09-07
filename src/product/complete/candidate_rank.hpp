#pragma once
#include <cctype>
#include <string>
#include <vector>
namespace rawr::product {

struct Candidate {
    std::string text;
    uint64_t id = 0;
    int syntax = 0;
    int repoHit = 0;
    int compileLikely = 0;
    int score = 0;
};

inline int LooksBalanced(const std::string& t) {
    int p = 0, b = 0, c = 0;
    for (char ch : t) {
        if (ch == '(') p++;
        else if (ch == ')') p--;
        else if (ch == '{') b++;
        else if (ch == '}') b--;
        else if (ch == '[') c++;
        else if (ch == ']') c--;
        if (p < 0 || b < 0 || c < 0) return 0;
    }
    return (p == 0 && b == 0 && c == 0) ? 1 : 0;
}

inline Candidate RankOne(const std::string& text, int repoHit) {
    Candidate k;
    k.text = text;
    k.syntax = LooksBalanced(text);
    k.repoHit = repoHit ? 1 : 0;
    k.compileLikely = k.syntax;
    k.score = k.syntax * 40 + k.repoHit * 30 + k.compileLikely * 20;
    if (!text.empty() && std::isalpha((unsigned char)text[0])) k.score += 5;
    return k;
}

inline Candidate BestCandidate(const std::vector<std::string>& texts, int repoHit) {
    Candidate best{};
    for (const auto& t : texts) {
        Candidate k = RankOne(t, repoHit);
        if (k.score >= best.score) best = k;
    }
    return best;
}

} // namespace rawr::product
