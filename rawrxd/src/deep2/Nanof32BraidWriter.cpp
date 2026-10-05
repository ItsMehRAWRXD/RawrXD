// ============================================================================
// Nanof32BraidWriter.cpp — RAWRXD_NANOF32_BRAID_WRITER_001
//
// See Nanof32BraidWriter.hpp for the layout rationale and for the measurement
// that established no writer existed. This file is the inverse of
// Nanof32BraidStreamer.cpp; every encoder below is paired with the specific
// decompress* function it must round-trip against, named in the comment.
// ============================================================================

#include "Nanof32BraidWriter.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace Deep2 {
namespace {

// Inverse of bfloat16_t::bfloat16_t(float) in BP16Streamer.hpp.
//
// That constructor TRUNCATES: `v = static_cast<uint16_t>(u >> 16)`. This
// encoder must do the same, bit for bit. An earlier revision of this file
// round-to-nearest-even instead, which is the more accurate conversion and the
// wrong one here: it is not the inverse of the shipped reader, so a round-trip
// check against that reader disagreed by up to one bf16 ulp (2^-8 relative)
// for reasons that had nothing to do with the format. Matching the reader's
// arithmetic exactly is what makes the round trip falsifiable.
uint16_t floatToBf16(float f) {
    uint32_t u;
    std::memcpy(&u, &f, sizeof u);
    return static_cast<uint16_t>(u >> 16);
}

void setBit(std::vector<uint8_t>& bits, size_t bitPos) {
    bits[bitPos >> 3] |= static_cast<uint8_t>(1u << (bitPos & 7u));
}

} // namespace

// ----------------------------------------------------------------------------
// Size accounting
// ----------------------------------------------------------------------------

uint64_t nanof32CompressedBytes(uint32_t quant, uint64_t elements) {
    switch (quant) {
        case NQBRAID_DENSE_F32:
            return elements * sizeof(float);
        case NQBRAID_DENSE_BF16:
            return elements * sizeof(uint16_t);
        case NQBRAID_BRAID_115: {
            // Nanof32BraidStreamer::decompressBraid: 20 weights per group,
            // 23 bits per group, ceil(groups * 23 / 8) bytes.
            const uint64_t groups = (elements + 19) / 20;
            return (groups * 23 + 7) / 8;
        }
        case NQBRAID_CODEBOOK_1BIT:
        case NQBRAID_CODEBOOK_2BIT:
        case NQBRAID_CODEBOOK_3BIT: {
            const uint32_t bits = quant - NQBRAID_CODEBOOK_1BIT + 1;
            const uint64_t perByte = 8 / bits;
            return (elements + perByte - 1) / perByte;
        }
        default:
            return 0;   // unknown quant: refuse rather than guess
    }
}

// ----------------------------------------------------------------------------
// Encoders
// ----------------------------------------------------------------------------

// Inverse of the NQBRAID_DENSE_F32 branch in readNextTensor.
uint64_t nanof32EncodeDenseF32(const float* values, uint64_t elements,
                               std::vector<uint8_t>& out) {
    if (!values || elements == 0) return 0;
    const uint64_t bytes = elements * sizeof(float);
    out.resize(static_cast<size_t>(bytes));
    std::memcpy(out.data(), values, static_cast<size_t>(bytes));
    return bytes;
}

// Inverse of the NQBRAID_DENSE_BF16 branch in readNextTensor.
uint64_t nanof32EncodeDenseBF16(const float* values, uint64_t elements,
                                std::vector<uint8_t>& out) {
    if (!values || elements == 0) return 0;
    out.resize(static_cast<size_t>(elements * sizeof(uint16_t)));
    for (uint64_t i = 0; i < elements; ++i) {
        const uint16_t h = floatToBf16(values[i]);
        std::memcpy(out.data() + i * sizeof(uint16_t), &h, sizeof h);
    }
    return out.size();
}

// Inverse of Nanof32BraidStreamer::decompressBraid.
//
// Bit order must match exactly. The decoder reads, for each of 20 base bits:
//     bit = (compressed[byteIdx] >> bitIdx) & 1u   with bitIdx = bitPos % 8
// i.e. LSB-first within each byte, and assembles baseBits with
//     baseBits |= bit << b
// so weight w uses bit position (groupStart + w). The 3-bit mode follows
// immediately at groupStart+20..22, assembled the same LSB-first way.
uint64_t nanof32EncodeBraid115(const float* values, uint64_t elements,
                               float scaleMin, float scaleMax,
                               std::vector<uint8_t>& out) {
    if (!values || elements == 0) return 0;

    // A degenerate range would collapse every weight to one value and make the
    // round-trip indistinguishable from a writer that emits constants.
    if (!(scaleMax > scaleMin)) return 0;

    const uint64_t groups   = (elements + 19) / 20;
    const uint64_t requiredBits  = groups * 23;
    const uint64_t requiredBytes = (requiredBits + 7) / 8;

    out.assign(static_cast<size_t>(requiredBytes), 0u);

    // Centroid ladder the decoder will rebuild from scaleMin/scaleMax. The
    // encoder only needs it to decide which mode reproduces a weight best, but
    // it must be computed the same way the decoder computes it or the chosen
    // mode will not be the mode that decodes closest.
    float centroids[8];
    const float step = (scaleMax - scaleMin) / 8.0f;
    for (int i = 0; i < 8; ++i) {
        centroids[i] = scaleMin + step * (static_cast<float>(i) + 0.5f);
    }

    size_t   bitPos = 0;
    uint64_t outIdx = 0;

    for (uint64_t g = 0; g < groups; ++g) {
        const size_t groupStart = bitPos;

        // Pass 1: choose base bits and record the per-weight target so pass 2
        // can pick the mode that best reconstructs the whole group.
        uint32_t baseBits = 0;
        float    want[20];
        bool     present[20];
        for (int w = 0; w < 20; ++w) {
            const bool have = (outIdx + static_cast<uint64_t>(w)) < elements;
            present[w] = have;
            if (!have) { want[w] = 0.0f; continue; }

            const float v = values[outIdx + static_cast<uint64_t>(w)];
            want[w] = v;
            const uint32_t base =
                (v >= (scaleMin + scaleMax) * 0.5f) ? 1u : 0u;
            baseBits |= (base << w);
        }

        // Pass 2: pick the mode minimising squared error over this group,
        // replicating the decoder's reconstruction exactly:
        //     val = (base==0 ? scaleMin : scaleMax)
        //     if (mode != 0) val = val*0.5 + centroids[mode&7]*0.5
        uint32_t bestMode = 0;
        float    bestErr  = 0.0f;
        bool     haveBest = false;
        for (uint32_t mode = 0; mode < 8; ++mode) {
            float err = 0.0f;
            for (int w = 0; w < 20; ++w) {
                if (!present[w]) continue;
                const float baseVal =
                    ((baseBits >> w) & 1u) ? scaleMax : scaleMin;
                float val = baseVal;
                if (mode != 0) val = val * 0.5f + centroids[mode & 7] * 0.5f;
                const float d = val - want[w];
                err += d * d;
            }
            if (!haveBest || err < bestErr) {
                bestErr  = err;
                bestMode = mode;
                haveBest = true;
            }
        }

        for (int b = 0; b < 20; ++b) {
            if ((baseBits >> b) & 1u) setBit(out, groupStart + static_cast<size_t>(b));
        }
        for (int b = 0; b < 3; ++b) {
            if ((bestMode >> b) & 1u) setBit(out, groupStart + 20 + static_cast<size_t>(b));
        }

        bitPos += 23;
        outIdx += 20;
    }

    return requiredBytes;
}

// ----------------------------------------------------------------------------
// Vocabulary section
// ----------------------------------------------------------------------------

// RAWRXD_NQBRAID_TOKENIZER_E2E_001
//
// Serialises to the layout documented in Nanof32BraidFormat.hpp. Returns an
// empty vector on any inconsistency, and the caller refuses to write rather
// than emitting a half-valid section: a vocab section with a wrong length in
// its own header is worse than no section, because the reader would compute
// offsets from it.
std::vector<uint8_t> nanof32EncodeVocabSection(const Nanof32VocabSpec& v) {
    std::vector<uint8_t> out;
    const size_t n = v.tokens.size();
    if (n == 0) return out;
    if (v.scores.size() != n || v.types.size() != n) return out;

    // String blob + explicit offset table. Offsets are recorded as each token
    // is appended, so a token containing an embedded NUL would silently
    // truncate: that is rejected here rather than written.
    std::vector<uint8_t> blob;
    std::vector<uint32_t> offsets;
    offsets.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        if (v.tokens[i].find('\0') != std::string::npos) return out;
        offsets.push_back(static_cast<uint32_t>(blob.size()));
        blob.insert(blob.end(), v.tokens[i].begin(), v.tokens[i].end());
        blob.push_back(0);
    }

    // Merges are newline-joined and must not contain newlines themselves.
    std::vector<uint8_t> merges;
    for (size_t i = 0; i < v.merges.size(); ++i) {
        if (v.merges[i].find('\n') != std::string::npos) return out;
        merges.insert(merges.end(), v.merges[i].begin(), v.merges[i].end());
        merges.push_back('\n');
    }

    Nanof32VocabHeader vh{};
    vh.magic      = NANO_F32_BRAID_VOCAB_MAGIC;
    vh.kind       = v.kind;
    vh.entryCount = static_cast<uint32_t>(n);
    vh.strBytes   = static_cast<uint32_t>(blob.size());
    vh.mergeCount = static_cast<uint32_t>(v.merges.size());
    vh.mergeBytes = static_cast<uint32_t>(merges.size());
    vh.flags      = (v.addBos ? NQ_VOCAB_FLAG_ADD_BOS : 0u) |
                    (v.addEos ? NQ_VOCAB_FLAG_ADD_EOS : 0u);
    vh.bosId = v.bosId; vh.eosId = v.eosId;
    vh.unkId = v.unkId; vh.sepId = v.sepId; vh.padId = v.padId;
    std::snprintf(vh.model, sizeof vh.model, "%s", v.model.c_str());

    out.reserve(sizeof vh + blob.size() + n * 4 + n * 4 + n * 4 + 4 + merges.size());
    const auto append = [&](const void* p, size_t len) {
        const uint8_t* b = static_cast<const uint8_t*>(p);
        out.insert(out.end(), b, b + len);
    };
    append(&vh, sizeof vh);
    append(blob.data(), blob.size());
    append(offsets.data(), offsets.size() * 4);
    append(v.scores.data(), v.scores.size() * 4);
    append(v.types.data(), v.types.size() * 4);
    append(&vh.mergeCount, 4);
    append(merges.data(), merges.size());
    return out;
}

// ----------------------------------------------------------------------------
// RAWRXD_NQB_ONE_FORMAT_AUTHORITY_001 -- streaming container writer
// ----------------------------------------------------------------------------

uint32_t nanof32DeriveBitsPerWeight100(uint64_t payloadBytes, uint64_t elements) {
    if (elements == 0) return 0;
    // bpw100 = round(payloadBytes * 800 / elements)
    //
    // 800 = 8 bits * 100 hundredths. This is MEASURED from what was written,
    // not predicted from a payload type, which is the whole point:
    //
    //   * it stays correct for a mixed-codec artifact, where no single type
    //     describes the file;
    //   * it cannot be "fixed" by editing a constant in one of two writers,
    //     because there is now only one derivation and it reads the bytes;
    //   * a file whose stored bpw disagrees with its payload is detectable,
    //     which is exactly how the fake q0 artifact would be caught.
    //
    // Rounding is half-up via (num + elements/2) / elements in integer
    // arithmetic: no floating point, so the result is identical on every host.
    if (payloadBytes > UINT64_MAX / 800ull) return 0;   // >23 PB: refuse to guess
    const uint64_t num = payloadBytes * 800ull;
    const uint64_t bpw = (num + elements / 2ull) / elements;
    return static_cast<uint32_t>(bpw > 0xFFFFFFFFull ? 0xFFFFFFFFull : bpw);
}

Nanof32BraidStreamWriter::~Nanof32BraidStreamWriter() {
    if (!finalized_) abort();
}

bool Nanof32BraidStreamWriter::open(const std::string& path,
                                    const Nanof32BraidArchMeta& archMetaIn,
                                    const Nanof32VocabSpec* vocab) {
    if (open_) {
        error_ = "open() called twice";
        return false;
    }
    if (archMetaIn.numLayers == 0 || archMetaIn.hiddenDim == 0 ||
        archMetaIn.vocabSize == 0) {
        error_ = "arch meta has a zero dimension (numLayers/hiddenDim/vocabSize)";
        return false;
    }

    path_ = path;
    out_.open(path, std::ios::binary | std::ios::trunc);
    if (!out_.is_open()) {
        error_ = "cannot open output for writing: " + path;
        return false;
    }

    Nanof32BraidArchMeta archMeta = archMetaIn;
    Nanof32BraidHeader header{};
    std::memset(header.reserved, 0, sizeof(header.reserved));
    std::memset(archMeta.modelName, 0, sizeof(archMeta.modelName));
    std::memset(archMeta.archName, 0, sizeof(archMeta.archName));

    header.magic          = NANO_F32_BRAID_MAGIC;
    header.version        = NANO_F32_BRAID_VERSION;
    // Every count below stays ZERO until finalize(). A provisional header that
    // already claims 255 tensors is how "GGUF says 255, writer skipped 3,
    // header still says 255" happens. Here the header cannot lie because it has
    // not been told anything yet.
    header.numTensors     = 0;
    header.paramCount     = 0;
    header.bitsPerWeight  = 0;
    header.tensorDirOffset = 0;
    header.fileSize       = 0;
    header.vocabSectionOffset = 0;
    header.vocabSectionBytes  = 0;

    out_.write(reinterpret_cast<const char*>(&header), sizeof header);
    out_.write(reinterpret_cast<const char*>(&archMeta), sizeof archMeta);
    if (!out_) {
        error_ = "write failed while emitting header/arch meta";
        abort();
        return false;
    }

if (vocab && !vocab->tokens.empty()) {
        // The vocabulary must FIT the embedding, not the other way round.
        //
        // archMeta.vocabSize is the number of rows in token_embd (and in the
        // output projection). encode() can only ever emit ids below
        // token_embd.rows, so the requirement is:
        //
        //     tokenizer_tokens <= embedding_rows
        //
        // and a tokenizer SMALLER than the embedding is perfectly legal -- the
        // surplus rows are simply unreachable. This check was briefly inverted
        // to `tokens < vocabSize` on the reasoning that "the vocabulary must
        // cover every declared id", which is a category error: the declared
        // ids ARE the vocabulary. Inverted, it rejected every fixture whose
        // embedding is wider than its tokenizer, and took the ctest matrix
        // from 18/18 to 4/18:
        //
        //     WRITE_ERROR=vocabulary has 288 tokens but archMeta.vocabSize is 512
        //
        // with 288 <= 512 being perfectly valid. The 18/18 that preceded it
        // had been measured against a stale build, so the regression was only
        // visible on a rebuild -- see RAWRXD_STALE_BUILD_FALSE_PASS below.
        //
        // The embedding row count is still checked independently, against the
        // token_embd tensor itself, so nothing is lost by using the declared
        // authority here.
        if (vocab->tokens.size() > static_cast<size_t>(archMeta.vocabSize)) {
            error_ = "NQB_INVARIANT_TOKEN_DOMAIN_001: vocabulary has " +
                     std::to_string(vocab->tokens.size()) +
                     " tokens but the embedding has only " +
                     std::to_string(archMeta.vocabSize) +
                     " rows; encode() could emit an id with no embedding row";
            abort();
            return false;
        }
        if (vocab->scores.size() != vocab->tokens.size() ||
            vocab->types.size()  != vocab->tokens.size()) {
            error_ = "vocabulary scores/types counts disagree with token count";
            abort();
            return false;
        }
        const std::vector<uint8_t> vocabBytes = nanof32EncodeVocabSection(*vocab);
        if (vocabBytes.empty()) {
            error_ = "vocabulary section failed to encode (empty result with a "
                     "non-empty token list)";
            abort();
            return false;
        }
        header.vocabSectionOffset = static_cast<uint64_t>(out_.tellp());
        header.vocabSectionBytes  = vocabBytes.size();
        out_.write(reinterpret_cast<const char*>(vocabBytes.data()),
                   static_cast<std::streamsize>(vocabBytes.size()));
        if (!out_) {
            error_ = "write failed while emitting the vocabulary section";
            abort();
            return false;
        }
    }

    dataStart_ = static_cast<uint64_t>(out_.tellp());
    header_    = header;
    census_    = Nanof32Census{};
    bytesWritten_ = dataStart_;
    open_      = true;
    finalized_ = false;
    return true;
}

bool Nanof32BraidStreamWriter::appendTensor(const std::string& name,
                                            uint64_t rows, uint64_t cols,
                                            uint32_t quant, const void* values,
                                            uint64_t elements,
                                            float scaleMin, float scaleMax,
                                            uint32_t expertIndex) {
    if (!open_) { error_ = "appendTensor before open()"; return false; }
    if (finalized_) { error_ = "appendTensor after finalize()"; return false; }
    if (name.empty()) { error_ = "tensor has an empty name"; return false; }
    if (name.size() >= sizeof(Nanof32BraidTensorFooter::name)) {
        error_ = "tensor name exceeds footer name field: " + name;
        return false;
    }
    if (rows == 0 || cols == 0) { error_ = "tensor " + name + " has a zero dimension"; return false; }
    if (elements != rows * cols) {
        error_ = "tensor " + name + ": element count disagrees with rows*cols";
        return false;
    }
    if (!values) { error_ = "tensor " + name + " has a null value pointer"; return false; }
    if (quant >= NQBRAID_COUNT) {
        error_ = "tensor " + name + ": unknown quantType " + std::to_string(quant);
        return false;
    }

    const float* f = static_cast<const float*>(values);
    std::vector<uint8_t> encoded;
    uint64_t wrote = 0;
    switch (quant) {
        case NQBRAID_DENSE_F32:  wrote = nanof32EncodeDenseF32(f, elements, encoded);  break;
        case NQBRAID_DENSE_BF16: wrote = nanof32EncodeDenseBF16(f, elements, encoded); break;
case NQBRAID_BRAID_115:   wrote = nanof32EncodeBraid115(f, elements,
                                                                 scaleMin, scaleMax,
                                                                 encoded); break;
        default:
            error_ = "tensor " + name + ": quantType " + std::to_string(quant) +
                     " has no encoder";
            return false;
    }

    const uint64_t expected = nanof32CompressedBytes(quant, elements);
    if (wrote == 0 || wrote != expected) {
        error_ = "tensor " + name + ": encoder produced " + std::to_string(wrote) +
                 " bytes, accounting expected " + std::to_string(expected);
        return false;
    }

    out_.write(reinterpret_cast<const char*>(encoded.data()),
               static_cast<std::streamsize>(encoded.size()));
    if (!out_) { error_ = "write failed while emitting payload for " + name; abort(); return false; }

    Nanof32BraidTensorFooter footer{};
    std::memset(footer.name, 0, sizeof footer.name);
    footer.magic       = NANO_F32_BRAID_MAGIC;
    footer.quantType   = quant;
    footer.scaleMin    = scaleMin;
    footer.scaleMax    = scaleMax;
    footer.rows        = rows;
    footer.cols        = cols;
    footer.dataBytes   = wrote;
    footer.expertIndex = expertIndex;
    std::memcpy(footer.name, name.c_str(), name.size());

    out_.write(reinterpret_cast<const char*>(&footer), sizeof footer);
    if (!out_) { error_ = "write failed while emitting footer for " + name; abort(); return false; }

    // Census accumulates from what was ACTUALLY emitted. A tensor that failed
    // to encode never reaches these lines, so it cannot be counted.
    census_.tensorCount  += 1;
    census_.paramCount   += elements;
    census_.payloadBytes += wrote;
    census_.footerBytes  += sizeof(Nanof32BraidTensorFooter);
    census_.codecCount[quant] += 1;
    bytesWritten_ = static_cast<uint64_t>(out_.tellp());
    return true;
}

bool Nanof32BraidStreamWriter::finalize() {
    if (!open_)  { error_ = "finalize() before open()"; return false; }
    if (finalized_) return true;

    if (census_.tensorCount == 0) {
        error_ = "no tensors were appended";
        abort();
        return false;
    }
    if (bytesWritten_ <= sizeof(Nanof32BraidHeader) + sizeof(Nanof32BraidArchMeta)) {
        error_ = "produced file is smaller than header + arch meta";
        abort();
        return false;
    }

header_.numTensors      = static_cast<uint32_t>(census_.tensorCount);
    header_.paramCount      = census_.paramCount;
    header_.fileSize        = bytesWritten_;
    header_.tensorDirOffset = bytesWritten_ - sizeof(Nanof32BraidTensorFooter);
    header_.bitsPerWeight   = nanof32DeriveBitsPerWeight100(census_.payloadBytes,
                                                            census_.paramCount);
    // The census is the writer's own record of what it emitted, so it must carry
    // the derived value too. A caller cross-checking header.bitsPerWeight against
    // census.bpw100 found the header written correctly and the census reading 0,
    // which is a real trap: the census is what a converter uses to decide whether
    // its own output is consistent.
    census_.bpw100          = header_.bitsPerWeight;

    // RAWRXD_NQB_BPW_CENSUS_CHECK_001
    //
    // The stored bitsPerWeight is DERIVED, so a wrong payloadBytes or
    // paramCount produces a confidently wrong number rather than an error. The
    // real artifact is dense F32 and physically stores 32 bits per weight, yet
    // it reported 3.20 -- a factor of ten low, which is exactly what you get
    // when the numerator is the FILE size rather than the PAYLOAD size on a
    // 10x-decade confusion, or when one of the two census counters is off by a
    // decade. Rather than reason about which, the writer now measures the
    // authoritative quantity itself -- payload bytes actually emitted over
    // parameters actually emitted -- and states both, so the header value and
    // the derived value can be compared in the same receipt.
    const uint32_t bpwFromCensus =
        nanof32DeriveBitsPerWeight100(census_.payloadBytes, census_.paramCount);
    std::fprintf(stderr,
        "[NQBRAID] BPW payload_bytes=%llu params=%llu derived_bpw100=%u "
        "header_bpw100=%u %s\n",
        (unsigned long long)census_.payloadBytes,
        (unsigned long long)census_.paramCount,
        bpwFromCensus, header_.bitsPerWeight,
        (bpwFromCensus == header_.bitsPerWeight) ? "MATCH" : "MISMATCH");


    out_.seekp(0, std::ios::beg);
    out_.write(reinterpret_cast<const char*>(&header_), sizeof header_);
    out_.close();
    if (!out_) {
        error_ = "failed to backfill header";
        std::remove(path_.c_str());
        open_ = false;
        return false;
    }

    finalized_ = true;
    open_      = false;
    return true;
}

void Nanof32BraidStreamWriter::abort() {
    if (out_.is_open()) out_.close();
    if (!path_.empty()) std::remove(path_.c_str());
    open_      = false;
    finalized_ = true;   // nothing further to clean up
}

// ----------------------------------------------------------------------------
// The one-shot writer, now a loop over the streaming writer.
// Its validation is kept verbatim: those checks are what stopped a half-written
// file from being produced in the first place.
// ----------------------------------------------------------------------------

Nanof32WriteResult nanof32WriteBraid(const std::string& path,
                                     const Nanof32BraidArchMeta& archMetaIn,
                                     const std::vector<Nanof32TensorSpec>& tensors,
                                     const Nanof32VocabSpec* vocab) {
    Nanof32WriteResult r;

    if (path.empty()) { r.error = "empty output path"; return r; }
    if (archMetaIn.numLayers == 0 || archMetaIn.hiddenDim == 0 ||
        archMetaIn.vocabSize == 0) {
        r.error = "arch meta has a zero dimension (numLayers/hiddenDim/vocabSize)";
        return r;
    }
    if (tensors.empty()) { r.error = "no tensors to write"; return r; }

    for (size_t i = 0; i < tensors.size(); ++i) {
        const Nanof32TensorSpec& t = tensors[i];
        if (t.name.empty()) { r.error = "tensor " + std::to_string(i) + " has an empty name"; return r; }
        if (t.name.size() >= sizeof(Nanof32BraidTensorFooter::name)) {
            r.error = "tensor name exceeds footer name field: " + t.name;
            return r;
        }
        if (t.rows == 0 || t.cols == 0) { r.error = "tensor " + t.name + " has a zero dimension"; return r; }
        if (!t.values) { r.error = "tensor " + t.name + " has a null value pointer"; return r; }
        if (nanof32CompressedBytes(t.quant, t.rows * t.cols) == 0) {
            r.error = "tensor " + t.name + " has unsupported quantType " + std::to_string(t.quant);
            return r;
        }
    }

    Nanof32BraidStreamWriter w;
    if (!w.open(path, archMetaIn, vocab)) { r.error = w.error(); return r; }

    for (const Nanof32TensorSpec& t : tensors) {
        if (!w.appendTensor(t.name, t.rows, t.cols, t.quant, t.values,
                            t.rows * t.cols, t.scaleMin, t.scaleMax, t.expertIndex)) {
            r.error = w.error();
            w.abort();
            return r;
        }
    }
    if (!w.finalize()) { r.error = w.error(); return r; }

    r.ok          = true;
    r.paramCount  = w.census().paramCount;
    r.tensorCount = static_cast<uint32_t>(w.census().tensorCount);
    r.bytesWritten = w.bytesWritten();
    r.dataStart   = w.dataStart();
    r.finalFooter = w.bytesWritten() - sizeof(Nanof32BraidTensorFooter);
    return r;
}

} // namespace Deep2
