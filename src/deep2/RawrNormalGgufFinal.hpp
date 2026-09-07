// RawrNormalGgufFinal.hpp — mechanical witnesses for NORMAL_GGUF_FINAL
#pragma once
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace Deep2 {
namespace normal_gguf {

struct QualityWitness {
    int utf8Valid = 0;
    int visibleChars = 0;
    int alphaCount = 0;
    int spaceCount = 0;
    int sentenceEnd = 0;
    int maxTokenRun = 0;
    double topRepeatRate = 0.0;
    int mojibake = 0;
    int debugInOutput = 0;
    int coherent = 0;
};

inline bool Utf8Valid(const std::string& s) {
    const unsigned char* p = (const unsigned char*)s.data();
    size_t n = s.size(), i = 0;
    while (i < n) {
        if (p[i] <= 0x7F) { ++i; continue; }
        if ((p[i] & 0xE0) == 0xC0 && i + 1 < n && (p[i + 1] & 0xC0) == 0x80) {
            i += 2; continue;
        }
        if ((p[i] & 0xF0) == 0xE0 && i + 2 < n && (p[i + 1] & 0xC0) == 0x80 &&
            (p[i + 2] & 0xC0) == 0x80) {
            i += 3; continue;
        }
        if ((p[i] & 0xF8) == 0xF0 && i + 3 < n && (p[i + 1] & 0xC0) == 0x80 &&
            (p[i + 2] & 0xC0) == 0x80 && (p[i + 3] & 0xC0) == 0x80) {
            i += 4; continue;
        }
        return false;
    }
    return true;
}

inline bool HasDebugLeak(const std::string& s) {
    return s.find("[Deep2") != std::string::npos ||
           s.find("HOTPATH_") != std::string::npos ||
           s.find("Top-10 logits") != std::string::npos ||
           s.find("G:\\") != std::string::npos ||
           s.find("AGENT] TOKEN") != std::string::npos;
}

inline QualityWitness ScoreQuality(const std::string& text,
                                   const std::vector<int>& ids) {
    QualityWitness w{};
    w.utf8Valid = Utf8Valid(text) ? 1 : 0;
    w.debugInOutput = HasDebugLeak(text) ? 1 : 0;
    for (unsigned char c : text) {
        if (c >= 32 && c != 127) ++w.visibleChars;
        if (std::isalpha(c)) ++w.alphaCount;
        if (c == ' ' || c == '\n' || c == '\t') ++w.spaceCount;
        if (c == '.' || c == '!' || c == '?') ++w.sentenceEnd;
        if (c == 0xC3 || c == 0xEF) ++w.mojibake; // common mojibake markers
    }
    int run = 1, maxRun = 1;
    for (size_t i = 1; i < ids.size(); ++i) {
        if (ids[i] == ids[i - 1]) {
            ++run;
            if (run > maxRun) maxRun = run;
        } else
            run = 1;
    }
    w.maxTokenRun = ids.empty() ? 0 : maxRun;
    if (!ids.empty()) {
        int best = 0;
        for (int id : ids) {
            int c = 0;
            for (int x : ids)
                if (x == id) ++c;
            if (c > best) best = c;
        }
        w.topRepeatRate = (double)best / (double)ids.size();
    }
    const double alphaRatio =
        w.visibleChars > 0 ? (double)w.alphaCount / (double)w.visibleChars : 0.0;
    w.coherent =
        w.utf8Valid && !w.debugInOutput && w.visibleChars >= 120 &&
        alphaRatio >= 0.55 && w.spaceCount >= 12 && w.sentenceEnd >= 1 &&
        w.maxTokenRun <= 3 && w.topRepeatRate <= 0.20 && w.mojibake == 0;
    return w;
}

inline void EmitQuality(FILE* f, const QualityWitness& w) {
    if (!f) f = stdout;
    fprintf(f, "DETOKENIZED_UTF8_VALID=%d\n", w.utf8Valid);
    fprintf(f, "OUTPUT_VISIBLE_CHARS=%d\n", w.visibleChars);
    fprintf(f, "ALPHA_RATIO=%.3f\n",
            w.visibleChars ? (double)w.alphaCount / w.visibleChars : 0.0);
    fprintf(f, "SPACE_COUNT=%d\n", w.spaceCount);
    fprintf(f, "SENTENCE_END_COUNT=%d\n", w.sentenceEnd);
    fprintf(f, "REPEATED_TOKEN_MAX_RUN=%d\n", w.maxTokenRun);
    fprintf(f, "TOP_TOKEN_REPEAT_RATE=%.3f\n", w.topRepeatRate);
    fprintf(f, "MOJIBAKE_SEQUENCE_COUNT=%d\n", w.mojibake);
    fprintf(f, "DEBUG_TEXT_IN_OUTPUT=%d\n", w.debugInOutput);
    fprintf(f, "COHERENT_PARAGRAPH=%d\n", w.coherent ? 1 : 0);
}

} // namespace normal_gguf
} // namespace Deep2
