// inference_parity_trace.h — Structured JSON trace for CLI/UI parity testing
//
// Both `rawrxd run` (CLI) and `runLocalInferencePipeline` (Win32IDE) can emit
// the same envelope describing a single inference call so the streams can be
// diffed structurally, not just by total stdout bytes.
//
// Envelope shape (one JSON object per file):
//   {
//     "source":  "cli" | "ui-pipeline",
//     "model":   "...",
//     "prompt":  "...",
//     "started_ms":   <epoch ms>,
//     "first_token_ms": <delta from started_ms to first non-empty token>,
//     "completed_ms":   <delta from started_ms to done=true>,
//     "tokens":  ["t0", "t1", ...],
//     "token_count": N,
//     "error":   "..." | ""
//   }
//
// Strings are escaped per RFC 8259 (no external JSON dep needed).
#pragma once

#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD::ParityTrace {

struct Recorder {
    std::string source;
    std::string model;
    std::string prompt;
    std::vector<std::string> tokens;
    long long startedMs = 0;
    long long firstTokenMs = -1;
    long long completedMs = -1;
    std::string error;
    std::mutex mu;

    static long long nowMs() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }

    void start(std::string src, std::string mdl, std::string p) {
        std::lock_guard<std::mutex> lk(mu);
        source = std::move(src);
        model = std::move(mdl);
        prompt = std::move(p);
        startedMs = nowMs();
        firstTokenMs = -1;
        completedMs = -1;
        tokens.clear();
        error.clear();
    }

    void onToken(const std::string& tok, bool /*done*/) {
        std::lock_guard<std::mutex> lk(mu);
        if (!tok.empty()) {
            if (firstTokenMs < 0) firstTokenMs = nowMs() - startedMs;
            tokens.push_back(tok);
        }
    }

    void onComplete() {
        std::lock_guard<std::mutex> lk(mu);
        if (completedMs < 0) completedMs = nowMs() - startedMs;
    }

    void onError(const std::string& msg) {
        std::lock_guard<std::mutex> lk(mu);
        error = msg;
        if (completedMs < 0) completedMs = nowMs() - startedMs;
    }
};

inline void appendEscaped(std::string& out, const std::string& s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

// Returns true if the trace was written successfully.
inline bool writeJson(const Recorder& r, const std::string& path) {
    std::string buf;
    buf.reserve(4096 + r.tokens.size() * 8);
    buf += "{\n  \"source\": ";    appendEscaped(buf, r.source);
    buf += ",\n  \"model\": ";     appendEscaped(buf, r.model);
    buf += ",\n  \"prompt\": ";    appendEscaped(buf, r.prompt);
    buf += ",\n  \"started_ms\": " + std::to_string(r.startedMs);
    buf += ",\n  \"first_token_ms\": " + std::to_string(r.firstTokenMs);
    buf += ",\n  \"completed_ms\": " + std::to_string(r.completedMs);
    buf += ",\n  \"token_count\": " + std::to_string(r.tokens.size());
    buf += ",\n  \"error\": ";     appendEscaped(buf, r.error);
    buf += ",\n  \"tokens\": [";
    for (size_t i = 0; i < r.tokens.size(); ++i) {
        if (i) buf += ", ";
        appendEscaped(buf, r.tokens[i]);
    }
    buf += "]\n}\n";

    FILE* f = nullptr;
#if defined(_WIN32)
    fopen_s(&f, path.c_str(), "wb");
#else
    f = std::fopen(path.c_str(), "wb");
#endif
    if (!f) return false;
    std::fwrite(buf.data(), 1, buf.size(), f);
    std::fclose(f);
    return true;
}

} // namespace RawrXD::ParityTrace
