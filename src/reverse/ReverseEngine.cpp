#include "ReverseEngine.hpp"
#include <algorithm>
#include <numeric>
#include <cstring>

#if defined(_MSC_VER)
    #include <intrin.h>
#else
    #include <x86intrin.h>
#endif
#include <immintrin.h>

namespace rxd::reverse {

ReverseEngine::ReverseEngine(const ReverseModel& model) : model_(model) {}

bool ReverseEngine::VerifyMaskedMatch(const Pattern& pat, const uint8_t* data, size_t offset, size_t size) {
    const size_t pat_len = pat.bytes.size();
    if (offset + pat_len > size) return false;

    const bool has_mask = !pat.mask.empty();
    for (size_t i = 0; i < pat_len; ++i) {
        const uint8_t m = has_mask ? pat.mask[i] : 0xFF;
        if ((data[offset + i] & m) != (pat.bytes[i] & m)) return false;
    }
    return true;
}

double ReverseEngine::ScoreMatch(const Pattern& pat, const uint8_t* data, size_t offset, size_t size) {
    if (!VerifyMaskedMatch(pat, data, offset, size)) return 0.0;

    double base = pat.weight;
    for (const auto& s : model_.samples) {
        if (s.output == data[offset] && s.confidence > base) {
            base = s.confidence;
        }
    }
    return base;
}

static std::string HexContext(const uint8_t* data, size_t size, size_t offset, size_t ctx) {
    std::string out;
    size_t start = (offset > ctx) ? offset - ctx : 0;
    size_t end = std::min(offset + ctx + 1, size);
    char buf[4];
    for (size_t i = start; i < end; ++i) {
        std::snprintf(buf, sizeof(buf), "%02X", data[i]);
        if (i == offset) out += '[';
        out += buf;
        if (i == offset) out += ']';
        out += ' ';
    }
    if (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

static void RecordMatch(std::vector<Match>& matches, const Pattern& pat, size_t offset, double conf, const uint8_t* data, size_t size) {
    Match m;
    m.patternId = pat.id;
    m.patternName = pat.mnemonic;
    m.offset = offset;
    m.length = pat.bytes.size();
    m.confidence = conf;
    m.predictedByte = data[offset];
    m.extractedBytes.assign(data + offset, data + offset + pat.bytes.size());
    m.contextHex = HexContext(data, size, offset, 8);
    m.isValid = true;
    matches.push_back(std::move(m));
}

// ============================================================================
// Scalar Engine
// ============================================================================
std::vector<Match> ReverseEngine::ScanScalar(const uint8_t* data, size_t size) {
    std::vector<Match> matches;
    for (const auto& pat : model_.patterns) {
        if (pat.bytes.empty() || pat.bytes.size() > size) continue;
        const uint8_t first = pat.bytes[0];
        const size_t limit = size - pat.bytes.size();
        for (size_t i = 0; i <= limit; ++i) {
            if (data[i] != first) continue;
            double conf = ScoreMatch(pat, data, i, size);
            if (conf >= model_.minConfidence) {
                RecordMatch(matches, pat, i, conf, data, size);
            }
        }
    }
    return matches;
}

// ============================================================================
// AVX2 Engine (32 bytes / iteration)
// ============================================================================
#if defined(__AVX2__)
std::vector<Match> ReverseEngine::ScanAVX2(const uint8_t* data, size_t size) {
    std::vector<Match> matches;
    for (const auto& pat : model_.patterns) {
        if (pat.bytes.empty() || pat.bytes.size() > size) continue;

        const uint8_t first = pat.bytes[0];
        const size_t pat_len = pat.bytes.size();
        const size_t max_offset = size - pat_len;
        const __m256i v_first = _mm256_set1_epi8(static_cast<char>(first));

        size_t offset = 0;
        for (; offset + 32 <= max_offset; offset += 32) {
            __m256i v_buf = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + offset));
            __m256i v_cmp = _mm256_cmpeq_epi8(v_buf, v_first);
            uint32_t mask = static_cast<uint32_t>(_mm256_movemask_epi8(v_cmp));

            while (mask != 0) {
#if defined(_MSC_VER)
                unsigned long bit_index;
                _BitScanForward(&bit_index, mask);
#else
                unsigned long bit_index = __builtin_ctz(mask);
#endif
                size_t candidate = offset + bit_index;
                double conf = ScoreMatch(pat, data, candidate, size);
                if (conf >= model_.minConfidence) {
                    RecordMatch(matches, pat, candidate, conf, data, size);
                }
                mask &= (mask - 1);
            }
        }

        // Scalar tail
        for (; offset <= max_offset; ++offset) {
            if (data[offset] != first) continue;
            double conf = ScoreMatch(pat, data, offset, size);
            if (conf >= model_.minConfidence) {
                RecordMatch(matches, pat, offset, conf, data, size);
            }
        }
    }
    return matches;
}
#endif

// ============================================================================
// AVX-512 Engine (64 bytes / iteration)
// ============================================================================
#if defined(__AVX512F__) && defined(__AVX512BW__)
std::vector<Match> ReverseEngine::ScanAVX512(const uint8_t* data, size_t size) {
    std::vector<Match> matches;
    for (const auto& pat : model_.patterns) {
        if (pat.bytes.empty() || pat.bytes.size() > size) continue;

        const uint8_t first = pat.bytes[0];
        const size_t pat_len = pat.bytes.size();
        const size_t max_offset = size - pat_len;
        const __m512i v_first = _mm512_set1_epi8(static_cast<char>(first));

        size_t offset = 0;
        for (; offset + 64 <= max_offset; offset += 64) {
            __m512i v_buf = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(data + offset));
            __mmask64 mask = _mm512_cmpeq_epi8_mask(v_buf, v_first);

            while (mask != 0) {
#if defined(_MSC_VER)
                unsigned long bit_index;
                _BitScanForward64(&bit_index, mask);
#else
                unsigned long bit_index = __builtin_ctzll(mask);
#endif
                size_t candidate = offset + bit_index;
                double conf = ScoreMatch(pat, data, candidate, size);
                if (conf >= model_.minConfidence) {
                    RecordMatch(matches, pat, candidate, conf, data, size);
                }
                mask &= (mask - 1);
            }
        }

        // Scalar tail
        for (; offset <= max_offset; ++offset) {
            if (data[offset] != first) continue;
            double conf = ScoreMatch(pat, data, offset, size);
            if (conf >= model_.minConfidence) {
                RecordMatch(matches, pat, offset, conf, data, size);
            }
        }
    }
    return matches;
}
#endif

// ============================================================================
// Public Scan Dispatch
// ============================================================================
std::vector<Match> ReverseEngine::Scan(const uint8_t* data, size_t size) {
    std::vector<Match> matches;

#if defined(__AVX512F__) && defined(__AVX512BW__)
    matches = ScanAVX512(data, size);
#elif defined(__AVX2__)
    matches = ScanAVX2(data, size);
#else
    matches = ScanScalar(data, size);
#endif

    // Post-process: dedupe by offset (keep highest confidence)
    if (model_.dedupeConsecutive) {
        std::sort(matches.begin(), matches.end(), [](const Match& a, const Match& b) {
            return a.offset < b.offset;
        });
        std::vector<Match> deduped;
        for (const auto& m : matches) {
            if (!deduped.empty() && deduped.back().offset == m.offset) {
                if (m.confidence > deduped.back().confidence) deduped.back() = m;
            } else {
                deduped.push_back(m);
            }
        }
        matches = std::move(deduped);
    }

    std::sort(matches.begin(), matches.end(), [](const Match& a, const Match& b) {
        return a.confidence > b.confidence;
    });
    return matches;
}

Reconstruction ReverseEngine::Reconstruct(const uint8_t* data, size_t size) {
    Reconstruction rc;
    rc.bytes.assign(data, data + size);
    rc.matches = Scan(data, size);
    if (!rc.matches.empty()) {
        double sum = std::accumulate(rc.matches.begin(), rc.matches.end(), 0.0,
                                     [](double acc, const Match& m) { return acc + m.confidence; });
        rc.overallConfidence = sum / rc.matches.size();
    } else {
        rc.overallConfidence = 0.0;
    }
    return rc;
}

} // namespace rxd::reverse
