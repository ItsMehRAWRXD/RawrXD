#include "rawrxd_tokenizer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <mutex>
#include <unordered_map>
#include <set>

namespace {

// GGUF metadata value type tags (spec v2/v3).
enum GgufType : uint32_t {
    GGUF_UINT8 = 0, GGUF_INT8 = 1, GGUF_UINT16 = 2, GGUF_INT16 = 3,
    GGUF_UINT32 = 4, GGUF_INT32 = 5, GGUF_FLOAT32 = 6, GGUF_BOOL = 7,
    GGUF_STRING = 8, GGUF_ARRAY = 9, GGUF_UINT64 = 10, GGUF_INT64 = 11,
    GGUF_FLOAT64 = 12
};

// Streaming GGUF metadata reader.
//
// RAWRXD_P0_GGUF_TOKENIZER_001: this reads through an ifstream with an explicit
// byte budget rather than slurping the file. A 36 GB GGUF cannot be read into
// memory just to obtain a vocabulary, so every read is bounded and every offset
// is checked. Any malformed input fails closed.
class GgufMetaReader {
public:
    explicit GgufMetaReader(const std::string& path) : in_(path, std::ios::binary) {}

    bool ok() const { return ok_; }
    const std::string& error() const { return err_; }
    uint64_t metaCount() const { return metaCount_; }
    const std::string& key() const { return key_; }

    bool Open() {
        if (!in_) return fail("cannot open file");
        char magic[4] = {};
        if (!readRaw(magic, 4)) return fail("truncated header");
        if (std::memcmp(magic, "GGUF", 4) != 0) return fail("bad GGUF magic");
        if (!u32(version_)) return fail("truncated version");
        if (!u64(tensorCount_)) return fail("truncated tensor count");
        if (!u64(metaCount_)) return fail("truncated meta count");
        // A sanity bound: a real vocabulary is far below this, and an absurd
        // count means a corrupt or hostile header.
        if (metaCount_ > kMaxMetaEntries) return fail("implausible metadata count");
        return true;
    }

    // Reads the next key/value pair. `type` receives the value tag and
    // `arrElemType` the element tag for arrays.
    bool Next(uint32_t& type, uint32_t& arrElemType) {
        key_.clear();
        if (!str(key_)) return fail("truncated key");
        if (!u32(type)) return fail("truncated value type");
        arrElemType = type;
        if (type == GGUF_ARRAY) {
            if (!u32(type)) return fail("truncated array type");
            if (!u64(count_)) return fail("truncated array count");
            arrElemType = type;
            // An array of primitives has a computable element size; cap the
            // count so a corrupt length cannot drive a huge allocation.
            size_t elemSize = PrimitiveSize(type);
            if (elemSize != 0) {
                if (count_ > kMaxArrayBytes / elemSize) {
                    count_ = 0;
                    return fail("implausible array length");
                }
            } else if (type == GGUF_STRING) {
                if (count_ > kMaxStringArray) {
                    count_ = 0;
                    return fail("implausible string array length");
                }
            } else {
                return fail("unsupported array element type");
            }
        }
        return true;
    }

    bool ReadU32Value(uint32_t& out) {
        int64_t v = 0;
        if (!scalar(v)) return false;
        if (v < 0 || v > 0xFFFFFFFFll) return fail("u32 out of range");
        out = static_cast<uint32_t>(v);
        return true;
    }

    bool ReadStringValue(std::string& out) { return str(out); }

    bool ReadStringArray(std::vector<std::string>& out) {
        out.clear();
        out.reserve(static_cast<size_t>(std::min<uint64_t>(count_, 1u << 20)));
        for (uint64_t i = 0; i < count_; ++i) {
            std::string s;
            if (!str(s)) return false;
            out.push_back(std::move(s));
        }
        return true;
    }

    bool ReadFloatArray(std::vector<float>& out) {
        out.clear();
        out.resize(static_cast<size_t>(count_));
        for (uint64_t i = 0; i < count_; ++i) {
            float f = 0.0f;
            if (!in_.read(reinterpret_cast<char*>(&f), sizeof(f))) {
                return fail("truncated float array");
            }
            out[static_cast<size_t>(i)] = f;
        }
        return true;
    }

    bool ReadInt32Array(std::vector<int32_t>& out) {
        out.clear();
        out.resize(static_cast<size_t>(count_));
        for (uint64_t i = 0; i < count_; ++i) {
            int32_t v = 0;
            if (!in_.read(reinterpret_cast<char*>(&v), sizeof(v))) {
                return fail("truncated int32 array");
            }
            out[static_cast<size_t>(i)] = v;
        }
        return true;
    }

    // Consumes a value of the given tag without materialising it.
    bool SkipValue(uint32_t type) {
        if (type == GGUF_ARRAY) {
            uint32_t elem = 0;
            uint64_t n = 0;
            if (!u32(elem) || !u64(n)) return false;
            if (elem == GGUF_STRING) {
                for (uint64_t i = 0; i < n; ++i) {
                    std::string s;
                    if (!str(s)) return false;
                }
                return true;
            }
            const size_t sz = PrimitiveSize(elem);
            if (sz == 0) return fail("unsupported array element type");
            return skipBytes(static_cast<uint64_t>(sz) * n);
        }
        if (type == GGUF_STRING) {
            std::string s;
            return str(s);
        }
        const size_t sz = PrimitiveSize(type);
        if (sz == 0) return fail("unsupported value type");
        return skipBytes(sz);
    }

private:
    static constexpr uint64_t kMaxMetaEntries = 1u << 20;
    static constexpr uint64_t kMaxArrayBytes = 256ull << 20;   // 256 MB per array
    static constexpr uint64_t kMaxStringArray = 4ull << 20;     // 4M strings

    static size_t PrimitiveSize(uint32_t t) {
        switch (t) {
            case GGUF_UINT8: case GGUF_INT8: case GGUF_BOOL: return 1;
            case GGUF_UINT16: case GGUF_INT16: return 2;
            case GGUF_UINT32: case GGUF_INT32: case GGUF_FLOAT32: return 4;
            case GGUF_UINT64: case GGUF_INT64: case GGUF_FLOAT64: return 8;
            default: return 0;
        }
    }

    bool fail(const char* m) {
        if (ok_) err_ = m;
        ok_ = false;
        return false;
    }

    bool readRaw(void* p, size_t n) {
        if (!ok_) return false;
        in_.read(static_cast<char*>(p), static_cast<std::streamsize>(n));
        if (!in_) return fail("unexpected end of file");
        return true;
    }

    bool skipBytes(uint64_t n) {
        if (!ok_) return false;
        if (n > (1ull << 32)) return fail("skip too large");
        in_.seekg(static_cast<std::streamoff>(n), std::ios::cur);
        if (!in_) return fail("seek failed");
        return true;
    }

    bool u8(uint8_t& v)  { return readRaw(&v, 1); }
    bool u16(uint16_t& v){ return readRaw(&v, 2); }
    bool u32(uint32_t& v){ return readRaw(&v, 4); }
    bool u64(uint64_t& v){ return readRaw(&v, 8); }

    bool str(std::string& s) {
        uint64_t len = 0;
        if (!u64(len)) return false;
        if (len > (1ull << 30)) return fail("string length implausible");
        s.clear();
        s.resize(static_cast<size_t>(len));
        if (len == 0) return true;
        return readRaw(&s[0], static_cast<size_t>(len));
    }

    bool scalar(int64_t& out) {
        uint32_t t = 0;
        if (!u32(t)) return false;
        switch (t) {
            case GGUF_UINT8:  { uint8_t v;  if (!u8(v)) return false;  out = v; return true; }
            case GGUF_INT8:   { int8_t v;   if (!u8(reinterpret_cast<uint8_t&>(v))) return false; out = v; return true; }
            case GGUF_UINT16: { uint16_t v; if (!u16(v)) return false; out = v; return true; }
            case GGUF_INT16:  { int16_t v;  if (!u16(reinterpret_cast<uint16_t&>(v))) return false; out = v; return true; }
            case GGUF_UINT32: { uint32_t v; if (!u32(v)) return false; out = v; return true; }
            case GGUF_INT32:  { int32_t v;  if (!u32(reinterpret_cast<uint32_t&>(v))) return false; out = v; return true; }
            case GGUF_BOOL:   { uint8_t v;  if (!u8(v)) return false;  out = v ? 1 : 0; return true; }
            case GGUF_UINT64: { uint64_t v; if (!u64(v)) return false; out = static_cast<int64_t>(v); return true; }
            case GGUF_INT64:  { int64_t v;  if (!u64(reinterpret_cast<uint64_t&>(v))) return false; out = v; return true; }
            case GGUF_FLOAT32:{ float v; if (!readRaw(&v, 4)) return false; out = static_cast<int64_t>(v); return true; }
            case GGUF_FLOAT64:{ double v; if (!readRaw(&v, 8)) return false; out = static_cast<int64_t>(v); return true; }
            default: return fail("unsupported scalar type");
        }
    }

    std::ifstream in_;
    uint32_t version_ = 0;
    uint64_t tensorCount_ = 0;
    uint64_t metaCount_ = 0;
    uint64_t count_ = 0;
    std::string key_;
    std::string err_;
    bool ok_ = true;
};

const char* kKeyModel    = "tokenizer.ggml.model";
const char* kKeyTokens   = "tokenizer.ggml.tokens";
const char* kKeyScores   = "tokenizer.ggml.scores";
const char* kKeyTypes    = "tokenizer.ggml.token_type";
const char* kKeyMerges   = "tokenizer.ggml.merges";
const char* kKeyBos      = "tokenizer.ggml.bos_token_id";
const char* kKeyEos      = "tokenizer.ggml.eos_token_id";
const char* kKeyUnk      = "tokenizer.ggml.unknown_token_id";
const char* kKeyPad      = "tokenizer.ggml.padding_token_id";

// llama.cpp uses U+2581 LOWER ONE EIGHTH BLOCK as the SentencePiece word
// boundary marker.
constexpr char32_t kSpmSpace = 0x2581;

std::string SpmMarkerToSpace(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0xE2 && i + 2 < s.size() &&
            static_cast<unsigned char>(s[i + 1]) == 0x96 &&
            static_cast<unsigned char>(s[i + 2]) == 0x81) {
            out.push_back(' ');
            i += 3;
        } else {
            out.push_back(s[i]);
            ++i;
        }
    }
    return out;
}

} // namespace

namespace rawrxd {

class Tokenizer::Impl {
public:
    TokenizerConfig config_;
    std::unordered_map<std::string, uint32_t> vocab_;
    std::unordered_map<uint32_t, std::string> id_to_token_;
    std::vector<std::pair<std::string, std::string>> merges_;
    std::set<uint32_t> special_ids_;
    mutable std::mutex mutex_;
    bool loaded_ = false;

    // RAWRXD_P0_GGUF_TOKENIZER_001: populated from GGUF metadata.
    bool is_spm_ = false;
    std::vector<float> scores_;
    std::vector<int32_t> token_types_;
    std::string model_name_;
    size_t max_token_chars_ = 0;  // longest vocab entry, for SPM longest-match

    bool ClearLoaded() {
        std::lock_guard<std::mutex> lock(mutex_);
        vocab_.clear();
        id_to_token_.clear();
        merges_.clear();
        special_ids_.clear();
        scores_.clear();
        token_types_.clear();
        model_name_.clear();
        max_token_chars_ = 0;
        is_spm_ = false;
        loaded_ = false;
        return true;
    }

    bool LoadVocabData(const std::vector<uint8_t>& vocab_data,
                       const std::vector<uint8_t>& merges_data) {
        std::lock_guard<std::mutex> lock(mutex_);
        vocab_.clear();
        id_to_token_.clear();
        merges_.clear();
        std::istringstream vocab_stream(std::string(vocab_data.begin(), vocab_data.end()));
        std::string line;
        uint32_t next_id = 0;
        while (std::getline(vocab_stream, line)) {
            size_t pos = line.find(' ');
            if (pos != std::string::npos) {
                std::string token = line.substr(0, pos);
                float score = 0.0f;
                try { score = std::stof(line.substr(pos + 1)); } catch (...) {}
                uint32_t id = next_id++;
                vocab_[token] = id;
                id_to_token_[id] = token;
            }
        }
        std::istringstream merges_stream(std::string(merges_data.begin(), merges_data.end()));
        while (std::getline(merges_stream, line)) {
            if (line.empty() || line[0] == '#') continue;
            size_t pos = line.find(' ');
            if (pos != std::string::npos) {
                merges_.push_back({line.substr(0, pos), line.substr(pos + 1)});
            }
        }
        special_ids_.insert(config_.bos_id);
        special_ids_.insert(config_.eos_id);
        special_ids_.insert(config_.unk_id);
        special_ids_.insert(config_.pad_id);
        loaded_ = true;
        return !vocab_.empty();
    }

    std::vector<uint32_t> EncodeBPE(const std::string& text) const {
        std::vector<uint32_t> result;
        auto pieces = PreTokenizeInternal(text);
        for (const auto& piece : pieces) {
            auto ids = EncodePiece(piece);
            result.insert(result.end(), ids.begin(), ids.end());
        }
        return result;
    }

    std::vector<std::string> PreTokenizeInternal(const std::string& text) const {
        std::vector<std::string> pieces;
        if (text.empty()) return pieces;
        std::string current;
        for (size_t i = 0; i < text.size();) {
            unsigned char c = static_cast<unsigned char>(text[i]);
            if (c < 0x80) {
                if (std::isspace(c)) {
                    if (!current.empty()) { pieces.push_back(current); current.clear(); }
                    pieces.push_back(std::string(1, text[i]));
                    ++i;
                } else {
                    current += text[i++];
                }
            } else if ((c & 0xE0) == 0xC0) {
                current += text.substr(i, 2); i += 2;
            } else if ((c & 0xF0) == 0xE0) {
                current += text.substr(i, 3); i += 3;
            } else if ((c & 0xF8) == 0xF0) {
                current += text.substr(i, 4); i += 4;
            } else {
                current += text[i++];
            }
        }
        if (!current.empty()) pieces.push_back(current);
        return pieces;
    }

    // SentencePiece greedy longest-match. llama.cpp scores every candidate
    // prefix and takes the best (highest score, then longest), which is what
    // makes SPM ids match the model's training-time segmentation. The previous
    // implementation only tried the whole piece and then fell back to single
    // bytes, so llama vocabularies encoded to garbage.
    std::vector<uint32_t> EncodeSPMPiece(const std::string& piece) const {
        std::vector<uint32_t> result;
        if (piece.empty()) return result;
        if (max_token_chars_ == 0) return result;

        std::string work = piece;
        if (!work.empty() && work[0] == ' ') {
            // SentencePiece encodes a leading space as the word-boundary marker
            // rather than as a literal space.
            static const std::string kMarker = "\xE2\x96\x81";
            work.replace(0, 1, kMarker);
        }

        size_t i = 0;
        while (i < work.size()) {
            size_t best_len = 0;
            uint32_t best_id = UINT32_MAX;
            float best_score = 0.0f;
            const size_t limit =
                std::min(max_token_chars_, work.size() - i);
            for (size_t len = limit; len >= 1; --len) {
                auto it = vocab_.find(work.substr(i, len));
                if (it == vocab_.end()) continue;
                const uint32_t id = it->second;
                float score = 0.0f;
                if (id < scores_.size()) score = scores_[id];
                if (best_id == UINT32_MAX || score > best_score ||
                    (score == best_score && len > best_len)) {
                    best_id = id;
                    best_len = len;
                    best_score = score;
                }
            }
            if (best_id == UINT32_MAX) {
                // Unknown byte: emit the SPM byte-fallback token if present,
                // otherwise the unk id. Never silently drop the character.
                char buf[8];
                std::snprintf(buf, sizeof(buf), "<0x%02X>",
                              static_cast<unsigned>(static_cast<unsigned char>(work[i])));
                auto bit = vocab_.find(buf);
                result.push_back(bit != vocab_.end() ? bit->second : config_.unk_id);
                ++i;
            } else {
                result.push_back(best_id);
                i += best_len;
            }
        }
        return result;
    }

    std::vector<uint32_t> EncodePiece(const std::string& piece) const {
        if (is_spm_) return EncodeSPMPiece(piece);

        std::vector<uint32_t> result;
        auto it = vocab_.find(piece);
        if (it != vocab_.end()) {
            result.push_back(it->second);
            return result;
        }
        std::string word = piece;
        // merges_ is stored in file (rank) order, so this loop is rank-ordered
        // rather than hash-ordered.
        for (const auto& [first, second] : merges_) {
            size_t pos = 0;
            while ((pos = word.find(first + second, pos)) != std::string::npos) {
                auto merged = first + second;
                if (vocab_.count(merged)) {
                    word.replace(pos, first.size() + second.size(), merged);
                }
                ++pos;
            }
        }
        it = vocab_.find(word);
        if (it != vocab_.end()) {
            result.push_back(it->second);
        } else {
            for (char c : piece) {
                std::string s(1, c);
                auto cit = vocab_.find(s);
                if (cit != vocab_.end()) result.push_back(cit->second);
                else result.push_back(config_.unk_id);
            }
        }
        return result;
    }

    std::string DecodeInternal(const std::vector<uint32_t>& tokens) const {
        std::string result;
        for (auto id : tokens) {
            if (special_ids_.count(id) && id != config_.unk_id) continue;
            auto it = id_to_token_.find(id);
            if (it == id_to_token_.end()) {
                result += config_.unk_token;
                continue;
            }
            const std::string& piece = it->second;
            // SPM byte-fallback token: <0xXX> means "emit this raw byte".
            if (piece.size() == 6 && piece[0] == '<' && piece[1] == '0' &&
                piece[2] == 'x' && piece[5] == '>') {
                auto hex = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    return -1;
                };
                const int hi = hex(piece[3]);
                const int lo = hex(piece[4]);
                if (hi >= 0 && lo >= 0) {
                    result.push_back(static_cast<char>((hi << 4) | lo));
                    continue;
                }
            }
            if (is_spm_) {
                result += SpmMarkerToSpace(piece);
            } else {
                result += piece;
            }
        }
        if (config_.clean_up_tokenization_spaces) {
            std::string cleaned;
            bool prev_space = false;
            for (char c : result) {
                if (std::isspace(static_cast<unsigned char>(c))) {
                    if (!prev_space) { cleaned += ' '; prev_space = true; }
                } else {
                    cleaned += c;
                    prev_space = false;
                }
            }
            if (!cleaned.empty() && cleaned.back() == ' ') cleaned.pop_back();
            result = cleaned;
        }
        return result;
    }
};

Tokenizer::Tokenizer() : impl_(std::make_unique<Impl>()) {}
Tokenizer::~Tokenizer() = default;

bool Tokenizer::LoadFromGGUF(const std::string& path) {
    // RAWRXD_P0_GGUF_TOKENIZER_001: this was `return false;`. Every caller
    // therefore ran with an empty vocabulary, and CPUInferenceEngine swallowed
    // that failure and still reported a loaded model.
    impl_->ClearLoaded();

    GgufMetaReader reader(path);
    if (!reader.Open()) {
        impl_->ClearLoaded();
        return false;
    }

    std::vector<std::string> tokens;
    std::vector<std::string> merges;
    bool haveScores = false;
    bool haveTypes = false;
    bool haveBos = false, haveEos = false, haveUnk = false, havePad = false;
    TokenizerConfig cfg;

    const uint64_t count = reader.metaCount();
    for (uint64_t i = 0; i < count; ++i) {
        uint32_t type = 0;
        uint32_t elem = 0;
        if (!reader.Next(type, elem)) {
            impl_->ClearLoaded();
            return false;
        }
        const std::string& key = reader.key();

        if (key == kKeyTokens) {
            if (type != GGUF_ARRAY || elem != GGUF_STRING) {
                impl_->ClearLoaded();
                return false;
            }
            if (!reader.ReadStringArray(tokens)) {
                impl_->ClearLoaded();
                return false;
            }
        } else if (key == kKeyMerges) {
            if (type != GGUF_ARRAY || elem != GGUF_STRING) {
                impl_->ClearLoaded();
                return false;
            }
            if (!reader.ReadStringArray(merges)) {
                impl_->ClearLoaded();
                return false;
            }
        } else if (key == kKeyScores) {
            if (type != GGUF_ARRAY || elem != GGUF_FLOAT32) {
                impl_->ClearLoaded();
                return false;
            }
            if (!reader.ReadFloatArray(impl_->scores_)) {
                impl_->ClearLoaded();
                return false;
            }
            haveScores = true;
        } else if (key == kKeyTypes) {
            if (type != GGUF_ARRAY || elem != GGUF_INT32) {
                impl_->ClearLoaded();
                return false;
            }
            if (!reader.ReadInt32Array(impl_->token_types_)) {
                impl_->ClearLoaded();
                return false;
            }
            haveTypes = true;
        } else if (key == kKeyModel) {
            if (type != GGUF_STRING) {
                impl_->ClearLoaded();
                return false;
            }
            if (!reader.ReadStringValue(impl_->model_name_)) {
                impl_->ClearLoaded();
                return false;
            }
        } else if (key == kKeyBos || key == kKeyEos ||
                   key == kKeyUnk || key == kKeyPad) {
            if (type != GGUF_UINT32) {
                impl_->ClearLoaded();
                return false;
            }
            uint32_t id = 0;
            if (!reader.ReadU32Value(id)) {
                impl_->ClearLoaded();
                return false;
            }
            if (key == kKeyBos) { cfg.bos_id = id; haveBos = true; }
            else if (key == kKeyEos) { cfg.eos_id = id; haveEos = true; }
            else if (key == kKeyUnk) { cfg.unk_id = id; haveUnk = true; }
            else { cfg.pad_id = id; havePad = true; }
        } else {
            if (!reader.SkipValue(type)) {
                impl_->ClearLoaded();
                return false;
            }
        }
    }

    // A vocabulary is the one thing this function must produce. Without it the
    // engine cannot encode or decode anything.
    if (tokens.empty()) {
        impl_->ClearLoaded();
        return false;
    }
    if (haveScores && impl_->scores_.size() != tokens.size()) {
        impl_->ClearLoaded();
        return false;
    }
    if (haveTypes && impl_->token_types_.size() != tokens.size()) {
        impl_->ClearLoaded();
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(impl_->mutex_);
        impl_->vocab_.clear();
        impl_->id_to_token_.clear();
        impl_->max_token_chars_ = 0;
        for (size_t i = 0; i < tokens.size(); ++i) {
            const uint32_t id = static_cast<uint32_t>(i);
            impl_->id_to_token_[id] = tokens[i];
            // First occurrence wins, matching llama.cpp for duplicate pieces.
            impl_->vocab_.emplace(tokens[i], id);
            impl_->max_token_chars_ =
                std::max(impl_->max_token_chars_, tokens[i].size());
        }

        // Merges arrive in rank order; preserve it.
        impl_->merges_.clear();
        impl_->merges_.reserve(merges.size());
        for (const auto& line : merges) {
            const size_t sp = line.find(' ');
            if (sp == std::string::npos) continue;
            impl_->merges_.emplace_back(line.substr(0, sp), line.substr(sp + 1));
        }

        std::string lower;
        lower.reserve(impl_->model_name_.size());
        for (char c : impl_->model_name_) {
            lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        // No model tag: infer from evidence. llama SPM vocabularies always
        // carry a score array; gpt2 BPE does not.
        impl_->is_spm_ = (lower == "llama") ||
                         (lower.find("spm") != std::string::npos) ||
                         (lower.empty() && haveScores);
        impl_->config_ = cfg;
        impl_->config_.type = impl_->is_spm_ ? TokenizerType::SPM : TokenizerType::BPE;

        impl_->special_ids_.clear();
        if (haveBos) impl_->special_ids_.insert(cfg.bos_id);
        if (haveEos) impl_->special_ids_.insert(cfg.eos_id);
        if (haveUnk) impl_->special_ids_.insert(cfg.unk_id);
        if (havePad && cfg.pad_id != 0) impl_->special_ids_.insert(cfg.pad_id);
        if (!haveUnk) impl_->special_ids_.insert(cfg.unk_id);
        if (impl_->vocab_.count(cfg.unk_token) == 0) {
            // Keep unk resolvable even when the file omits the id.
            cfg.unk_id = 0;
        }
        impl_->loaded_ = true;
    }
    return true;
}

bool Tokenizer::LoadFromFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    std::vector<uint8_t> vocab((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
    std::vector<uint8_t> merges;
    return impl_->LoadVocabData(vocab, merges);
}

bool Tokenizer::LoadFromMemory(const std::vector<uint8_t>& vocab_data,
                                const std::vector<uint8_t>& merges_data) {
    return impl_->LoadVocabData(vocab_data, merges_data);
}

bool Tokenizer::LoadVocab(const std::map<std::string, uint32_t>& vocab,
                          const std::vector<std::pair<std::string, std::string>>& merges) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->vocab_.clear();
    impl_->id_to_token_.clear();
    for (const auto& [token, id] : vocab) {
        impl_->vocab_[token] = id;
        impl_->id_to_token_[id] = token;
    }
    impl_->merges_ = merges;
    impl_->loaded_ = true;
    return true;
}

bool Tokenizer::IsLoaded() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->loaded_;
}

std::vector<uint32_t> Tokenizer::Encode(const std::string& text) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<uint32_t> result;
    if (impl_->config_.add_bos) result.push_back(impl_->config_.bos_id);
    auto encoded = impl_->EncodeBPE(text);
    result.insert(result.end(), encoded.begin(), encoded.end());
    if (impl_->config_.add_eos) result.push_back(impl_->config_.eos_id);
    return result;
}

std::string Tokenizer::Decode(const std::vector<uint32_t>& tokens) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->DecodeInternal(tokens);
}

std::string Tokenizer::DecodePiece(uint32_t token) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->id_to_token_.find(token);
    if (it != impl_->id_to_token_.end()) return it->second;
    return impl_->config_.unk_token;
}

size_t Tokenizer::VocabSize() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->vocab_.size();
}

std::vector<std::string> Tokenizer::VocabStrings() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> result;
    for (const auto& [token, _] : impl_->vocab_) result.push_back(token);
    return result;
}

std::optional<std::string> Tokenizer::IdToToken(uint32_t id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->id_to_token_.find(id);
    if (it != impl_->id_to_token_.end()) return it->second;
    return std::nullopt;
}

std::optional<uint32_t> Tokenizer::TokenToId(const std::string& token) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->vocab_.find(token);
    if (it != impl_->vocab_.end()) return it->second;
    return std::nullopt;
}

std::vector<uint32_t> Tokenizer::EncodeWithPreTokenization(const std::string& text) const {
    return Encode(text);
}

void Tokenizer::SetConfig(const TokenizerConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->config_ = config;
}

const TokenizerConfig& Tokenizer::GetConfig() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

bool Tokenizer::Save(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ofstream ofs(path);
    if (!ofs) return false;
    for (const auto& [token, id] : impl_->vocab_) {
        ofs << token << ' ' << id << '\n';
    }
    return ofs.good();
}

std::vector<std::string> Tokenizer::PreTokenize(const std::string& text,
                                                  const std::string& /*pattern*/) {
    std::vector<std::string> result;
    if (text.empty()) return result;
    std::string current;
    for (size_t i = 0; i < text.size();) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < 0x80) {
            if (std::isspace(c)) {
                if (!current.empty()) { result.push_back(current); current.clear(); }
                result.push_back(std::string(1, text[i]));
                ++i;
            } else {
                current += text[i++];
            }
        } else if ((c & 0xE0) == 0xC0) {
            current += text.substr(i, 2); i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            current += text.substr(i, 3); i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            current += text.substr(i, 4); i += 4;
        } else {
            current += text[i++];
        }
    }
    if (!current.empty()) result.push_back(current);
    return result;
}

} // namespace rawrxd
