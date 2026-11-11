#include "GgufParityTokenizer.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace rawrxd::parity {
namespace {

enum GgufType : uint32_t {
    GGUF_UINT8 = 0, GGUF_INT8 = 1, GGUF_UINT16 = 2, GGUF_INT16 = 3,
    GGUF_UINT32 = 4, GGUF_INT32 = 5, GGUF_FLOAT32 = 6, GGUF_BOOL = 7,
    GGUF_STRING = 8, GGUF_ARRAY = 9, GGUF_UINT64 = 10, GGUF_INT64 = 11,
    GGUF_FLOAT64 = 12
};

template <class T>
bool readPod(std::ifstream& f, T& v) {
    return static_cast<bool>(f.read(reinterpret_cast<char*>(&v), sizeof(T)));
}

bool readString(std::ifstream& f, std::string& s) {
    uint64_t n = 0;
    if (!readPod(f, n)) return false;
    if (n > (1ull << 31)) return false;
    s.resize(static_cast<size_t>(n));
    return n == 0 || static_cast<bool>(f.read(s.data(), static_cast<std::streamsize>(n)));
}

bool skipBytes(std::ifstream& f, uint64_t n) {
    f.seekg(static_cast<std::streamoff>(n), std::ios::cur);
    return static_cast<bool>(f);
}

bool skipValue(std::ifstream& f, uint32_t type);

bool skipScalar(std::ifstream& f, uint32_t type) {
    switch (type) {
        case GGUF_UINT8: case GGUF_INT8: case GGUF_BOOL: return skipBytes(f, 1);
        case GGUF_UINT16: case GGUF_INT16: return skipBytes(f, 2);
        case GGUF_UINT32: case GGUF_INT32: case GGUF_FLOAT32: return skipBytes(f, 4);
        case GGUF_UINT64: case GGUF_INT64: case GGUF_FLOAT64: return skipBytes(f, 8);
        case GGUF_STRING: {
            std::string tmp;
            return readString(f, tmp);
        }
        default: return false;
    }
}

bool skipValue(std::ifstream& f, uint32_t type) {
    if (type != GGUF_ARRAY) return skipScalar(f, type);
    uint32_t elem = 0;
    uint64_t count = 0;
    if (!readPod(f, elem) || !readPod(f, count)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        if (!skipScalar(f, elem)) return false;
    }
    return true;
}

bool readI32Like(std::ifstream& f, uint32_t type, int32_t& out) {
    if (type == GGUF_INT32) return readPod(f, out);
    if (type == GGUF_UINT32) {
        uint32_t v = 0;
        if (!readPod(f, v)) return false;
        out = static_cast<int32_t>(v);
        return true;
    }
    if (type == GGUF_INT64) {
        int64_t v = 0;
        if (!readPod(f, v)) return false;
        out = static_cast<int32_t>(v);
        return true;
    }
    if (type == GGUF_UINT64) {
        uint64_t v = 0;
        if (!readPod(f, v)) return false;
        out = static_cast<int32_t>(v);
        return true;
    }
    return false;
}

bool readBoolLike(std::ifstream& f, uint32_t type, bool& out) {
    if (type == GGUF_BOOL || type == GGUF_UINT8) {
        uint8_t v = 0;
        if (!readPod(f, v)) return false;
        out = v != 0;
        return true;
    }
    return false;
}

std::string metaspace(const std::string& s) {
    // LLaMA/SentencePiece-compatible minimum normalization:
    // replace runs of ASCII whitespace with U+2581 and prefix a word at BOI.
    // Newline/tab are represented as whitespace boundaries, not raw ASCII token 35-style splits.
    static const char kMeta[] = "\xE2\x96\x81";
    std::string out;
    out.reserve(s.size() + 8);
    bool atBoundary = true;
    for (unsigned char c : s) {
        const bool ws = c == ' ' || c == '\t' || c == '\r' || c == '\n';
        if (ws) {
            atBoundary = true;
            continue;
        }
        if (atBoundary) {
            out += kMeta;
            atBoundary = false;
        }
        out.push_back(static_cast<char>(c));
    }
    return out;
}

} // namespace

bool GgufParityTokenizer::load(const std::string& ggufPath, std::string* error) {
    pieces_.clear();
    exact_.clear();
    special_ids_.clear();

    std::ifstream f(ggufPath, std::ios::binary);
    if (!f) {
        if (error) *error = "cannot open GGUF";
        return false;
    }

    char magic[4]{};
    uint32_t version = 0;
    uint64_t tensorCount = 0, kvCount = 0;
    if (!f.read(magic, 4) || std::memcmp(magic, "GGUF", 4) != 0 ||
        !readPod(f, version) || !readPod(f, tensorCount) || !readPod(f, kvCount)) {
        if (error) *error = "invalid GGUF header";
        return false;
    }

    std::vector<std::string> tokens;
    std::vector<float> scores;
    std::vector<int32_t> types;

    for (uint64_t k = 0; k < kvCount; ++k) {
        std::string key;
        uint32_t type = 0;
        if (!readString(f, key) || !readPod(f, type)) {
            if (error) *error = "truncated GGUF metadata";
            return false;
        }

        if (key == "tokenizer.ggml.tokens" && type == GGUF_ARRAY) {
            uint32_t elem = 0; uint64_t n = 0;
            if (!readPod(f, elem) || !readPod(f, n) || elem != GGUF_STRING) return false;
            tokens.resize(static_cast<size_t>(n));
            for (auto& t : tokens) if (!readString(f, t)) return false;
        } else if (key == "tokenizer.ggml.scores" && type == GGUF_ARRAY) {
            uint32_t elem = 0; uint64_t n = 0;
            if (!readPod(f, elem) || !readPod(f, n) || elem != GGUF_FLOAT32) return false;
            scores.resize(static_cast<size_t>(n));
            for (auto& v : scores) if (!readPod(f, v)) return false;
        } else if (key == "tokenizer.ggml.token_type" && type == GGUF_ARRAY) {
            uint32_t elem = 0; uint64_t n = 0;
            if (!readPod(f, elem) || !readPod(f, n) || elem != GGUF_INT32) return false;
            types.resize(static_cast<size_t>(n));
            for (auto& v : types) if (!readPod(f, v)) return false;
        } else if (key == "tokenizer.ggml.bos_token_id") {
            if (!readI32Like(f, type, bos_id_)) { if (!skipValue(f, type)) return false; }
        } else if (key == "tokenizer.ggml.eos_token_id") {
            if (!readI32Like(f, type, eos_id_)) { if (!skipValue(f, type)) return false; }
        } else if (key == "tokenizer.ggml.unknown_token_id") {
            if (!readI32Like(f, type, unk_id_)) { if (!skipValue(f, type)) return false; }
        } else if (key == "tokenizer.ggml.add_bos_token") {
            if (!readBoolLike(f, type, model_add_bos_)) { if (!skipValue(f, type)) return false; }
        } else {
            if (!skipValue(f, type)) {
                if (error) *error = "unsupported/truncated GGUF metadata value";
                return false;
            }
        }
    }

    if (tokens.empty()) {
        if (error) *error = "tokenizer.ggml.tokens absent";
        return false;
    }

    pieces_.resize(tokens.size());
    for (size_t i = 0; i < tokens.size(); ++i) {
        pieces_[i].text = tokens[i];
        pieces_[i].score = i < scores.size() ? scores[i] : 0.0f;
        pieces_[i].type = i < types.size() ? types[i] : 1;
        exact_[pieces_[i].text] = static_cast<int32_t>(i);

        // GGML token types: 3=control, 4=user-defined in common GGUFs.
        // Also recognize explicit angle-bracket special forms.
        const bool shapeSpecial =
            pieces_[i].text.size() >= 4 &&
            pieces_[i].text.front() == '<' &&
            pieces_[i].text.back() == '>';
        if (pieces_[i].type == 3 || pieces_[i].type == 4 || shapeSpecial)
            special_ids_.push_back(static_cast<int32_t>(i));
    }

    std::sort(special_ids_.begin(), special_ids_.end(),
        [&](int32_t a, int32_t b) {
            return pieces_[a].text.size() > pieces_[b].text.size();
        });

    return true;
}

bool GgufParityTokenizer::matchSpecial(
    const std::string& text, size_t pos, int32_t& id, size_t& bytes) const {
    for (int32_t sid : special_ids_) {
        const auto& p = pieces_[static_cast<size_t>(sid)].text;
        if (!p.empty() && pos + p.size() <= text.size() &&
            text.compare(pos, p.size(), p) == 0) {
            id = sid;
            bytes = p.size();
            return true;
        }
    }
    return false;
}

std::vector<int32_t> GgufParityTokenizer::encodeNormalSpan(const std::string& utf8) const {
    const std::string s = metaspace(utf8);
    if (s.empty()) return {};

    // Deterministic score-aware dynamic segmentation.
    // Primary objective: best aggregate model score.
    // Tie-breakers: fewer pieces, then longer current piece, then lower token id.
    const size_t n = s.size();
    const double NEG = -std::numeric_limits<double>::infinity();
    std::vector<double> best(n + 1, NEG);
    std::vector<int> pieceCount(n + 1, std::numeric_limits<int>::max());
    std::vector<int32_t> prevId(n + 1, -1);
    std::vector<size_t> prevPos(n + 1, 0);
    best[0] = 0.0;
    pieceCount[0] = 0;

    for (size_t i = 0; i < n; ++i) {
        if (!std::isfinite(best[i])) continue;

        bool any = false;
        for (size_t id = 0; id < pieces_.size(); ++id) {
            const Piece& p = pieces_[id];
            if (p.text.empty() || p.type == 3) continue;
            if (i + p.text.size() > n) continue;
            if (s.compare(i, p.text.size(), p.text) != 0) continue;
            any = true;

            const size_t j = i + p.text.size();
            const double candidate = best[i] + static_cast<double>(p.score);
            const int pc = pieceCount[i] + 1;
            const bool better =
                candidate > best[j] + 1e-12 ||
                (std::fabs(candidate - best[j]) <= 1e-12 &&
                 (pc < pieceCount[j] ||
                  (pc == pieceCount[j] &&
                   (prevId[j] < 0 ||
                    p.text.size() > pieces_[static_cast<size_t>(prevId[j])].text.size() ||
                    (p.text.size() == pieces_[static_cast<size_t>(prevId[j])].text.size() &&
                     static_cast<int32_t>(id) < prevId[j])))));
            if (better) {
                best[j] = candidate;
                pieceCount[j] = pc;
                prevId[j] = static_cast<int32_t>(id);
                prevPos[j] = i;
            }
        }

        // Byte/unknown fallback so the algorithm always advances.
        if (!any) {
            const size_t j = i + 1;
            if (best[i] > best[j]) {
                best[j] = best[i] - 1000.0;
                pieceCount[j] = pieceCount[i] + 1;
                prevId[j] = unk_id_;
                prevPos[j] = i;
            }
        }
    }

    if (prevId[n] < 0) return {unk_id_};

    std::vector<int32_t> out;
    for (size_t p = n; p > 0;) {
        const int32_t id = prevId[p];
        if (id < 0) { out.push_back(unk_id_); break; }
        out.push_back(id);
        p = prevPos[p];
    }
    std::reverse(out.begin(), out.end());
    return out;
}

std::vector<int32_t> GgufParityTokenizer::encode(
    const std::string& text, bool addBos) const {
    std::vector<int32_t> out;
    if (addBos && model_add_bos_ && bos_id_ >= 0) out.push_back(bos_id_);

    size_t pos = 0;
    size_t normalStart = 0;
    auto flushNormal = [&](size_t end) {
        if (end > normalStart) {
            auto ids = encodeNormalSpan(text.substr(normalStart, end - normalStart));
            out.insert(out.end(), ids.begin(), ids.end());
        }
    };

    while (pos < text.size()) {
        int32_t sid = -1;
        size_t bytes = 0;
        if (matchSpecial(text, pos, sid, bytes)) {
            flushNormal(pos);
            out.push_back(sid);
            pos += bytes;
            normalStart = pos;
        } else {
            ++pos;
        }
    }
    flushNormal(text.size());
    return out;
}

std::string GgufParityTokenizer::decode(const std::vector<int32_t>& ids) const {
    std::string out;
    for (int32_t id : ids) {
        if (id < 0 || static_cast<size_t>(id) >= pieces_.size()) continue;
        if (id == bos_id_ || id == eos_id_) continue;
        out += pieces_[static_cast<size_t>(id)].text;
    }

    static const std::string meta = "\xE2\x96\x81";
    size_t pos = 0;
    while ((pos = out.find(meta, pos)) != std::string::npos) {
        out.replace(pos, meta.size(), " ");
        ++pos;
    }
    if (!out.empty() && out.front() == ' ') out.erase(out.begin());
    return out;
}

} // namespace rawrxd::parity
