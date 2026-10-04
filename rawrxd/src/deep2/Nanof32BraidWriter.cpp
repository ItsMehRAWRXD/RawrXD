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
// File writer
// ----------------------------------------------------------------------------

Nanof32WriteResult nanof32WriteBraid(const std::string& path,
                                     const Nanof32BraidArchMeta& archMetaIn,
                                     const std::vector<Nanof32TensorSpec>& tensors,
                                     const Nanof32VocabSpec* vocab) {
    Nanof32WriteResult r;

    // ---- validate before touching the filesystem ---------------------------
    // A half-written .nqb is worse than none: the reader will happily consume
    // a structurally valid prefix and report a model with missing tensors.
    if (path.empty()) {
        r.error = "empty output path";
        return r;
    }
    if (archMetaIn.numLayers == 0 || archMetaIn.hiddenDim == 0 ||
        archMetaIn.vocabSize == 0) {
        r.error = "arch meta has a zero dimension (numLayers/hiddenDim/vocabSize)";
        return r;
    }
    if (tensors.empty()) {
        r.error = "no tensors to write";
        return r;
    }

    uint64_t paramCount = 0;
    for (size_t i = 0; i < tensors.size(); ++i) {
        const Nanof32TensorSpec& t = tensors[i];
        if (t.name.empty()) {
            r.error = "tensor " + std::to_string(i) + " has an empty name";
            return r;
        }
        if (t.name.size() >= sizeof(Nanof32BraidTensorFooter::name)) {
            r.error = "tensor name exceeds footer name field: " + t.name;
            return r;
        }
        if (t.rows == 0 || t.cols == 0) {
            r.error = "tensor " + t.name + " has a zero dimension";
            return r;
        }
        const uint64_t elements = t.rows * t.cols;
        if (!t.values) {
            r.error = "tensor " + t.name + " has a null value pointer";
            return r;
        }
        if (nanof32CompressedBytes(t.quant, elements) == 0) {
            r.error = "tensor " + t.name + " has unsupported quantType " +
                      std::to_string(t.quant);
            return r;
        }
        paramCount += elements;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        r.error = "cannot open output for writing: " + path;
        return r;
    }

    // ---- header + arch meta (sizes from sizeof, never literals) -----------
    Nanof32BraidHeader header{};
    Nanof32BraidArchMeta archMeta = archMetaIn;
    // ArchMeta is fully assigned field-by-field in the tool; there is no
    // reserved[] padding left to clear (the MLA words consumed it).
    std::memset(header.reserved, 0, sizeof(header.reserved));
    std::memset(archMeta.modelName, 0, sizeof(archMeta.modelName));
    std::memset(archMeta.archName, 0, sizeof(archMeta.archName));

    header.magic      = NANO_F32_BRAID_MAGIC;
    header.version    = NANO_F32_BRAID_VERSION;
    header.paramCount = paramCount;
    header.numTensors = static_cast<uint32_t>(tensors.size());
    header.bitsPerWeight = 115;   // set below from the dominant quant

    out.write(reinterpret_cast<const char*>(&header), sizeof header);
    out.write(reinterpret_cast<const char*>(&archMeta), sizeof archMeta);
    if (!out) {
        r.error = "write failed while emitting header/arch meta";
        out.close();
        std::remove(path.c_str());
        return r;
    }

    // ---- vocabulary section (between arch meta and the first tensor) ------
    //
    // The reader walks tensors backward from EOF, so a forward section here
    // shifts dataStart without disturbing tensor traversal at all. Only the
    // header and arch meta have fixed offsets.
    std::vector<uint8_t> vocabBytes;
    if (vocab) {
        // NQB_INVARIANT_TOKEN_DOMAIN_001, writer half.
        //   0 <= token_id < tokenizer_vocab_size
        //   tokenizer_vocab_size <= embedding_rows
        //   tokenizer_vocab_size <= output_rows
        //   bos_id/eos_id < tokenizer_vocab_size
        // Enforced here as well as in the loader so an invalid model is never
        // produced in the first place; a file that must be rejected on load is
        // a defect that reached disk.
        const size_t tv = vocab->tokens.size();
        const size_t rows = archMetaIn.vocabSize;
        if (tv > rows) {
            r.error = "NQB_INVARIANT_TOKEN_DOMAIN_001: tokenizer has " +
                      std::to_string(tv) + " entries but vocabSize is " +
                      std::to_string(rows) +
                      "; encode() could emit an id with no embedding row";
            return r;
        }
        if (vocab->addBos && (vocab->bosId < 0 ||
                              static_cast<size_t>(vocab->bosId) >= tv)) {
            r.error = "NQB_INVARIANT_TOKEN_DOMAIN_001: bos_id " +
                      std::to_string(vocab->bosId) +
                      " is outside the tokenizer domain [0," + std::to_string(tv) + ")";
            return r;
        }
        if (vocab->addEos && (vocab->eosId < 0 ||
                              static_cast<size_t>(vocab->eosId) >= tv)) {
            r.error = "NQB_INVARIANT_TOKEN_DOMAIN_001: eos_id " +
                      std::to_string(vocab->eosId) +
                      " is outside the tokenizer domain [0," + std::to_string(tv) + ")";
            return r;
        }
        // The embedding and the output projection are separate tensors here,
        // so both must independently cover the vocabulary.
        for (const auto& t : tensors) {
            const bool isEmbed = (t.name == "token_embd.weight");
            const bool isHead  = (t.name == "output.weight");
            if (!isEmbed && !isHead) continue;
            if (t.rows < rows) {
                r.error = "NQB_INVARIANT_TOKEN_DOMAIN_001: " + t.name +
                          " has " + std::to_string(t.rows) +
                          " rows but vocabSize is " + std::to_string(rows);
                return r;
            }
        }
        vocabBytes = nanof32EncodeVocabSection(*vocab);
        if (vocabBytes.empty() && !vocab->tokens.empty()) {
            r.error = "vocabulary section failed to encode (empty result with "
                      "a non-empty token list)";
            out.close();
            std::remove(path.c_str());
            return r;
        }
        if (!vocabBytes.empty()) {
            header.vocabSectionOffset = static_cast<uint64_t>(out.tellp());
            header.vocabSectionBytes  = vocabBytes.size();
            out.write(reinterpret_cast<const char*>(vocabBytes.data()),
                      static_cast<std::streamsize>(vocabBytes.size()));
            if (!out) {
                r.error = "write failed while emitting the vocabulary section";
                out.close();
                std::remove(path.c_str());
                return r;
            }
        }
    }

    r.dataStart = static_cast<uint64_t>(out.tellp());

    // ---- tensor payloads, each trailed by its own footer ------------------
    std::vector<uint8_t> encoded;
    uint32_t dominantBpw = 0;   // in hundredths, e.g. 115 for 1.15 bpw

    for (size_t i = 0; i < tensors.size(); ++i) {
        const Nanof32TensorSpec& t = tensors[i];
        const uint64_t elements = t.rows * t.cols;

        uint64_t wrote = 0;
        switch (t.quant) {
            case NQBRAID_DENSE_F32:
                wrote = nanof32EncodeDenseF32(t.values, elements, encoded);
                // RAWRXD_NQB_BITS_PER_WEIGHT_UNIT_001
                //
                // The field is documented and read as HUNDREDTHS of a bit:
                //     Nanof32BraidFormat.hpp: uint32_t bitsPerWeight;
                //                                     // fixed-point: 115 = 1.15 bits/weight
                //     Nanof32BraidStreamer.cpp:61  "%u.%02u", v / 100, v % 100
                //     this file, line 418:         // in hundredths, e.g. 115
                //
                // Three mutually inconsistent values were in circulation for a
                // dense-F32 file, all measured, none of them the payload's
                // actual width:
                //     160  here, identical to the DENSE_BF16 arm  -> 1.60 bpw
                //     320  tools/gguf_to_nqb_converter.cpp        -> 3.20 bpw
                //     3200 this value, width * 8 * 100            -> 32.00 bpw
                // A 1.58 GB file whose header announces 1.60 bits per weight is
                // wrong by a factor of 20, and no reader flagged it: the reader
                // only prints the number. Verification caught it as
                //     EXPECTED_BITS_PER_WEIGHT=32 DECODED_BITS_PER_WEIGHT=3.2
                // after an intermediate repair set 320 here and failed the same
                // way -- which is the reason the constant is derived from
                // sizeof() rather than typed again.
                dominantBpw = std::max(dominantBpw,
                                       static_cast<uint32_t>(sizeof(float) * 8 * 100));
                break;
            case NQBRAID_DENSE_BF16:
                wrote = nanof32EncodeDenseBF16(t.values, elements, encoded);
                dominantBpw = std::max(dominantBpw,
                                       static_cast<uint32_t>(sizeof(uint16_t) * 8 * 100));
                break;
            case NQBRAID_BRAID_115:
                wrote = nanof32EncodeBraid115(t.values, elements,
                                              t.scaleMin, t.scaleMax, encoded);
                dominantBpw = std::max(dominantBpw, 115u);
                break;
            default:
                r.error = "tensor " + t.name + ": quantType " +
                          std::to_string(t.quant) + " has no encoder";
                out.close();
                std::remove(path.c_str());
                return r;
        }

        const uint64_t expected = nanof32CompressedBytes(t.quant, elements);
        if (wrote == 0 || wrote != expected) {
            r.error = "tensor " + t.name + ": encoder produced " +
                      std::to_string(wrote) + " bytes, accounting expected " +
                      std::to_string(expected);
            out.close();
            std::remove(path.c_str());
            return r;
        }

        out.write(reinterpret_cast<const char*>(encoded.data()),
                  static_cast<std::streamsize>(encoded.size()));

        Nanof32BraidTensorFooter footer{};
        std::memset(footer.name, 0, sizeof footer.name);
        footer.magic      = NANO_F32_BRAID_MAGIC;
        footer.quantType  = t.quant;
        footer.scaleMin   = t.scaleMin;
        footer.scaleMax   = t.scaleMax;
        footer.rows       = t.rows;
        footer.cols       = t.cols;
        footer.dataBytes  = wrote;
        footer.expertIndex = t.expertIndex;   // 0xFFFFFFFF == dense, per the header
        std::memcpy(footer.name, t.name.c_str(), t.name.size());

        out.write(reinterpret_cast<const char*>(&footer), sizeof footer);
        if (!out) {
            r.error = "write failed while emitting tensor " + t.name;
            out.close();
            std::remove(path.c_str());
            return r;
        }
    }

    // ---- backfill the header fields that depend on the finished file -------
    r.bytesWritten = static_cast<uint64_t>(out.tellp());
    if (r.bytesWritten <= static_cast<uint64_t>(sizeof(Nanof32BraidHeader) +
                                                sizeof(Nanof32BraidArchMeta))) {
        r.error = "produced file is smaller than header + arch meta";
        out.close();
        std::remove(path.c_str());
        return r;
    }

    r.finalFooter = r.bytesWritten - sizeof(Nanof32BraidTensorFooter);
    header.fileSize        = r.bytesWritten;
    header.bitsPerWeight   = dominantBpw ? dominantBpw : 3200u;
    header.tensorDirOffset = r.finalFooter;   // where reverse traversal begins

    out.seekp(0, std::ios::beg);
    out.write(reinterpret_cast<const char*>(&header), sizeof header);
    out.close();

    if (!out) {
        r.error = "failed to backfill header";
        std::remove(path.c_str());
        return r;
    }

    r.ok          = true;
    r.paramCount  = paramCount;
    r.tensorCount = static_cast<uint32_t>(tensors.size());
    return r;
}

} // namespace Deep2