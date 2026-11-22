#pragma once
// Native teacher-forced logit capture I/O. No inference or GPU dependencies.
#include <charconv>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace reap_capture {
inline std::vector<uint32_t> ParseTokens(const std::string& text) {
    std::vector<uint32_t> tokens;
    size_t i = 0;
    auto sep = [](char c) { return c == ' ' || c == ',' || c == '\t' || c == '\r' || c == '\n'; };
    while (i < text.size()) {
        while (i < text.size() && sep(text[i])) ++i;
        if (i == text.size()) break;
        size_t end = i;
        while (end < text.size() && !sep(text[end])) ++end;
        uint32_t token = 0;
        const auto parsed = std::from_chars(text.data() + i, text.data() + end, token);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + end)
            throw std::runtime_error("invalid token ID");
        tokens.push_back(token);
        i = end;
    }
    if (tokens.empty()) throw std::runtime_error("empty token sequence");
    return tokens;
}

class Capture {
public:
    Capture(std::filesystem::path dir, const std::vector<uint32_t>& tokens, size_t vocab)
        : dir_(std::move(dir)), tokens_(tokens), vocab_(vocab) {
        static_assert(sizeof(float) == 4 && std::numeric_limits<float>::is_iec559, "IEEE F32 required");
        if (tokens_.size() < 2 || vocab_ < 2 || vocab_ > 10000000)
            throw std::runtime_error("capture requires at least two tokens and a valid vocabulary");
        for (uint32_t token : tokens_) if (token >= vocab_) throw std::runtime_error("token outside vocabulary");
        if (!std::filesystem::create_directories(dir_)) throw std::runtime_error("capture directory already exists");
    }
    void Append(const std::vector<float>& logits) {
        if (finished_ || pos_ >= tokens_.size() - 1 || logits.size() != vocab_)
            throw std::runtime_error("invalid capture position or vocabulary");
        for (float value : logits) if (!std::isfinite(value)) throw std::runtime_error("nonfinite logit");
        const std::string name = "cpu_logits_pos" + std::to_string(pos_) + ".bin";
        std::ofstream out(dir_ / name, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(logits.data()), static_cast<std::streamsize>(logits.size() * sizeof(float)));
        out.close();
        if (!out) throw std::runtime_error("logit write failed");
        rows_ += "s\t" + std::to_string(pos_) + "\t" + std::to_string(tokens_[pos_]) + "\t" + std::to_string(tokens_[pos_+1]) + "\t" + name + "\n";
        ++pos_;
    }
    void Finish() {
        if (finished_ || pos_ != tokens_.size() - 1) throw std::runtime_error("incomplete capture");
        const auto temp = dir_ / "manifest.tsv.partial";
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        out << rows_;
        out.close();
        if (!out) throw std::runtime_error("manifest write failed");
        std::filesystem::rename(temp, dir_ / "manifest.tsv");
        finished_ = true;
    }
    size_t Count() const noexcept { return pos_; }
private:
    std::filesystem::path dir_;
    std::vector<uint32_t> tokens_;
    size_t vocab_, pos_ = 0;
    std::string rows_;
    bool finished_ = false;
};
} // namespace reap_capture
