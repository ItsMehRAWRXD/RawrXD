// ============================================================================
// Nanof32BraidStreamer.cpp — Real reverse-streaming decompression
// ============================================================================

#include "Nanof32BraidStreamer.hpp"
#include "Nanof32BraidFormat.hpp"

#include <cstdio>
#include <cstring>
#include <algorithm>

namespace Deep2 {

// ----------------------------------------------------------------------------
// Braid115 bitstream: 23 bits encode exactly 20 weights (1.15 bpw).
//
// Wire format per 20-weight group:
//   bits[0..19]   = 1-bit base values (0 = scaleMin, 1 = scaleMax)
//   bits[20..22]  = 3-bit braid refinement mode
//
// Braid mode selects a per-weight micro-offset from 8 levels between
// scaleMin and scaleMax.  Mode 0 means "no offset" (pure 1-bit).
// Modes 1..7 apply progressively finer centroids.
// ----------------------------------------------------------------------------

Nanof32BraidStreamer::~Nanof32BraidStreamer() {
    close();
}

bool Nanof32BraidStreamer::open(const std::string& path) {
    file_.open(path, std::ios::binary | std::ios::ate);
    if (!file_.is_open()) {
        std::fprintf(stderr, "[NQBRAID] ERROR: cannot open %s\n", path.c_str());
        return false;
    }

    uint64_t fileSize = static_cast<uint64_t>(file_.tellg());
    if (fileSize < sizeof(Nanof32BraidHeader)) {
        std::fprintf(stderr, "[NQBRAID] ERROR: file too small for header\n");
        file_.close();
        return false;
    }

    // Read header at byte 0
    file_.seekg(0, std::ios::beg);
    header_ = std::make_unique<Nanof32BraidHeader>();
    file_.read(reinterpret_cast<char*>(header_.get()), sizeof(Nanof32BraidHeader));

    if (header_->magic != NANO_F32_BRAID_MAGIC) {
        std::fprintf(stderr, "[NQBRAID] ERROR: bad magic 0x%08X (expected 0x%08X)\n",
                     header_->magic, NANO_F32_BRAID_MAGIC);
        file_.close();
        return false;
    }

    // Set readHead to end of file (start reverse streaming)
    readHead_ = fileSize;
    bytesRead_ = sizeof(Nanof32BraidHeader);
    tensorsLoaded_ = 0;

    std::fprintf(stderr, "[NQBRAID] OPEN: params=%llu bitsPerWeight=%u.%02u tensors=%u\n",
                 (unsigned long long)header_->paramCount,
                 header_->bitsPerWeight / 100,
                 header_->bitsPerWeight % 100,
                 header_->numTensors);

    return true;
}

void Nanof32BraidStreamer::close() {
    if (file_.is_open()) file_.close();
    cache_.clear();
    header_.reset();
    readHead_ = 0;
    bytesRead_ = 0;
    tensorsLoaded_ = 0;
}

bool Nanof32BraidStreamer::readAt(uint64_t offset, void* buffer, size_t bytes) {
    if (!file_.is_open()) return false;
    file_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    file_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(bytes));
    size_t got = static_cast<size_t>(file_.gcount());
    bytesRead_ += got;
    return got == bytes;
}

// RAWRXD_NQBRAID_TOKENIZER_E2E_001
//
// Reads the vocabulary section named by header_->vocabSectionOffset.
//
// `present` distinguishes "this file declares no vocabulary" (valid, returns
// true) from "this file declares one and it is broken" (returns false with
// present=true). Those are different facts and the caller must not conflate
// them: a missing vocabulary is a property of the model, a corrupt one is a
// defect in the file.
bool Nanof32BraidStreamer::readVocabSection(std::vector<uint8_t>& out,
                                            bool& present) {
    out.clear();
    present = false;
    if (!file_.is_open() || !header_) return false;
    if (header_->vocabSectionBytes == 0) return true;   // valid: no vocabulary

    present = true;
    const uint64_t bytes = header_->vocabSectionBytes;
    if (bytes < sizeof(Nanof32VocabHeader)) {
        std::fprintf(stderr,
            "[NQBRAID] vocab section too small: %llu < %zu\n",
            (unsigned long long)bytes, sizeof(Nanof32VocabHeader));
        return false;
    }

    // Bounds are checked against the REAL file size, not against the declared
    // length. A header claiming a section that runs past EOF is refused here
    // rather than yielding a short read that would look like a valid section.
    file_.clear();
    file_.seekg(0, std::ios::end);
    const uint64_t fileSize = static_cast<uint64_t>(file_.tellg());
    const uint64_t off = header_->vocabSectionOffset;
    const uint64_t floorOff = sizeof(Nanof32BraidHeader) + sizeof(Nanof32BraidArchMeta);
    if (off < floorOff || off > fileSize || bytes > fileSize - off) {
        std::fprintf(stderr,
            "[NQBRAID] vocab section out of range: off=%llu bytes=%llu fileSize=%llu\n",
            (unsigned long long)off, (unsigned long long)bytes,
            (unsigned long long)fileSize);
        return false;
    }

    out.resize(static_cast<size_t>(bytes));
    if (!readAt(off, out.data(), static_cast<size_t>(bytes))) {
        std::fprintf(stderr, "[NQBRAID] vocab section short read\n");
        out.clear();
        return false;
    }

    Nanof32VocabHeader vh{};
    std::memcpy(&vh, out.data(), sizeof vh);
    if (vh.magic != NANO_F32_BRAID_VOCAB_MAGIC) {
        std::fprintf(stderr, "[NQBRAID] vocab magic mismatch 0x%08X\n", vh.magic);
        out.clear();
        return false;
    }
    return true;
}

bool Nanof32BraidStreamer::readNextTensor(Nanof32BraidTensorFooter& outFooter,
                                           std::vector<bfloat16_t>& outData,
                                           std::vector<float>* outF32) {
    if (!file_.is_open() || !header_) return false;

    // Guard: readHead must leave room for footer
    constexpr size_t FOOTER_SIZE = sizeof(Nanof32BraidTensorFooter);
    if (readHead_ <= sizeof(Nanof32BraidHeader) + FOOTER_SIZE) {
        return false;  // No more tensors
    }

    // Step 1: Move readHead back by footer size and read footer
    readHead_ -= FOOTER_SIZE;
    if (!readAt(readHead_, &outFooter, FOOTER_SIZE)) {
        std::fprintf(stderr, "[NQBRAID] ERROR: footer read failed at offset %llu\n",
                     (unsigned long long)readHead_);
        return false;
    }

    if (outFooter.magic != NANO_F32_BRAID_MAGIC) {
        std::fprintf(stderr, "[NQBRAID] ERROR: footer magic mismatch\n");
        return false;
    }

    // Step 2: Move readHead back by data size
    size_t elements = outFooter.rows * outFooter.cols;
    if (readHead_ <= outFooter.dataBytes) {
        std::fprintf(stderr, "[NQBRAID] ERROR: data bytes exceed remaining file\n");
        return false;
    }
    readHead_ -= outFooter.dataBytes;

    // Step 3: Read compressed data
    std::vector<uint8_t> compressed(outFooter.dataBytes);
    if (!readAt(readHead_, compressed.data(), outFooter.dataBytes)) {
        std::fprintf(stderr, "[NQBRAID] ERROR: data read failed\n");
        return false;
    }

    // Step 4: materialise.
    //
    // RAWRXD_NQB_DENSE_F32_PRESERVE_F32_001 -- a dense F32 payload used to be
    // narrowed to bfloat16 here, unconditionally, which discarded 16 of the 32
    // bits the file actually stored. When the caller asks for F32 it is copied
    // through untouched. Quantised formats are unaffected: they decompress to
    // bfloat16 by construction and keep filling outData.
    //
    // outData is sized up front because the codebook and braid cases below
    // write through outData.data() and have no other sizing of their own.
    outData.resize(elements);
    bool ok = false;

    switch (outFooter.quantType) {
        case NQBRAID_DENSE_BF16:
            // Direct copy: compressed is already BF16 bytes
            if (compressed.size() >= elements * sizeof(bfloat16_t)) {
                std::memcpy(outData.data(), compressed.data(), elements * sizeof(bfloat16_t));
                ok = true;
            }
            break;
        case NQBRAID_DENSE_F32:
            if (outF32) {
                outData.clear();
                if (compressed.size() >= elements * sizeof(float)) {
                    const float* fp32 = reinterpret_cast<const float*>(compressed.data());
                    outF32->assign(fp32, fp32 + elements);
                    ok = true;
                }
                break;
            }
            // Convert F32 → BF16 (legacy path, only when F32 was not requested)
            if (compressed.size() >= elements * sizeof(float)) {
                const float* fp32 = reinterpret_cast<const float*>(compressed.data());
                for (size_t i = 0; i < elements; ++i) {
                    outData[i] = bfloat16_t(fp32[i]);
                }
                ok = true;
            }
            break;
        case NQBRAID_CODEBOOK_1BIT:
            ok = decompressCodebook(compressed.data(), compressed.size(),
                                    1, outData.data(), elements,
                                    outFooter.scaleMin, outFooter.scaleMax);
            break;
        case NQBRAID_CODEBOOK_2BIT:
            ok = decompressCodebook(compressed.data(), compressed.size(),
                                    2, outData.data(), elements,
                                    outFooter.scaleMin, outFooter.scaleMax);
            break;
        case NQBRAID_CODEBOOK_3BIT:
            ok = decompressCodebook(compressed.data(), compressed.size(),
                                    3, outData.data(), elements,
                                    outFooter.scaleMin, outFooter.scaleMax);
            break;
        case NQBRAID_BRAID_115:
            ok = decompressBraid(compressed.data(), compressed.size(),
                                   outData.data(), elements,
                                   outFooter.scaleMin, outFooter.scaleMax);
            break;
        default:
            std::fprintf(stderr, "[NQBRAID] ERROR: unknown quantType=%u\n", outFooter.quantType);
            return false;
    }

    if (!ok) {
        std::fprintf(stderr, "[NQBRAID] ERROR: decompression failed for quantType=%u\n",
                     outFooter.quantType);
        return false;
    }

    ++tensorsLoaded_;
    return true;
}

bool Nanof32BraidStreamer::decompressBraid(const uint8_t* compressed, size_t compBytes,
                                           bfloat16_t* output, size_t elements,
                                           float scaleMin, float scaleMax) {
    // Exact 1.15 bpw: 23 bits per 20 weights.
    // Total groups = ceil(elements / 20).
    // Required bytes = ceil(groups * 23 / 8).
    const size_t weightsPerGroup = 20;
    const size_t bitsPerGroup    = 23;
    const size_t groups = (elements + weightsPerGroup - 1) / weightsPerGroup;
    const size_t requiredBits  = groups * bitsPerGroup;
    const size_t requiredBytes = (requiredBits + 7) / 8;

    if (compBytes < requiredBytes) {
        std::fprintf(stderr,
            "[NQBRAID] BRAID_115: need %zu bytes for %zu elements, got %zu\n",
            requiredBytes, elements, compBytes);
        return false;
    }

    // Pre-compute 8 braid centroids between scaleMin and scaleMax
    float centroids[8];
    float step = (scaleMax - scaleMin) / 8.0f;
    for (int i = 0; i < 8; ++i) {
        centroids[i] = scaleMin + step * (static_cast<float>(i) + 0.5f);
    }

    size_t bitPos = 0;   // current bit position in the compressed bitstream
    size_t outIdx = 0;   // current output element

    for (size_t g = 0; g < groups && outIdx < elements; ++g) {
        // Read 20 base bits
        uint32_t baseBits = 0;
        for (int b = 0; b < 20; ++b) {
            size_t byteIdx = bitPos / 8;
            size_t bitIdx  = bitPos % 8;
            uint32_t bit = (compressed[byteIdx] >> bitIdx) & 1u;
            baseBits |= (bit << b);
            ++bitPos;
        }

        // Read 3-bit braid refinement mode
        uint32_t braidMode = 0;
        for (int b = 0; b < 3; ++b) {
            size_t byteIdx = bitPos / 8;
            size_t bitIdx  = bitPos % 8;
            uint32_t bit = (compressed[byteIdx] >> bitIdx) & 1u;
            braidMode |= (bit << b);
            ++bitPos;
        }

        // Decode 20 weights for this group
        float offset = (braidMode == 0) ? 0.0f : centroids[braidMode & 7];

        for (int w = 0; w < 20 && outIdx < elements; ++w) {
            uint32_t base = (baseBits >> w) & 1u;
            float val = (base == 0) ? scaleMin : scaleMax;
            if (braidMode != 0) {
                // Apply braid offset as a micro-tweak toward the centroid
                val = val * 0.5f + offset * 0.5f;
            }
            output[outIdx++] = bfloat16_t(val);
        }
    }

    return outIdx == elements;
}

bool Nanof32BraidStreamer::decompressCodebook(const uint8_t* compressed, size_t compBytes,
                                              uint32_t bits, bfloat16_t* output, size_t elements,
                                              float scaleMin, float scaleMax) {
    if (bits < 1 || bits > 3) return false;

    const uint32_t numCentroids = 1u << bits;  // 2, 4, or 8
    // Centroids are linearly spaced between scaleMin and scaleMax
    std::vector<float> centroids(numCentroids);
    float step = (scaleMax - scaleMin) / static_cast<float>(numCentroids - 1);
    for (uint32_t i = 0; i < numCentroids; ++i) {
        centroids[i] = scaleMin + step * static_cast<float>(i);
    }

    // Decode: pack 'bits' per weight
    size_t weightsPerByte = 8 / bits;
    size_t requiredBytes = (elements + weightsPerByte - 1) / weightsPerByte;
    if (compBytes < requiredBytes) {
        std::fprintf(stderr, "[NQBRAID] CODEBOOK: compressed bytes insufficient\n");
        return false;
    }

    size_t idx = 0;
    for (size_t b = 0; b < compBytes && idx < elements; ++b) {
        uint8_t byte = compressed[b];
        for (uint32_t w = 0; w < weightsPerByte && idx < elements; ++w) {
            uint32_t cidx = (byte >> (w * bits)) & ((1u << bits) - 1);
            float val = centroids[cidx];
            output[idx++] = bfloat16_t(val);
        }
    }

    return idx == elements;
}

bool Nanof32BraidStreamer::readArchMeta(Nanof32BraidArchMeta& outMeta) {
    if (!file_.is_open()) return false;
    file_.seekg(sizeof(Nanof32BraidHeader), std::ios::beg);
    file_.read(reinterpret_cast<char*>(&outMeta), sizeof(Nanof32BraidArchMeta));
    return file_.gcount() == sizeof(Nanof32BraidArchMeta);
}

bool Nanof32BraidStreamer::readAllTensors(
    std::vector<std::pair<std::string, NQBraidBlock>>& outTensors) {
    outTensors.clear();
    if (!file_.is_open() || !header_) return false;

    // RAWRXD_NANOF32_BRAID_WRITER_001 -- re-arm the reverse cursor at true EOF.
    //
    // This previously read:
    //     uint64_t fileSize = static_cast<uint64_t>(file_.tellg());
    //     if (fileSize == 0) fileSize = header_->fileSize;
    //     readHead_ = fileSize;
    // tellg() is NOT the file size here. open() seeks to 0 and reads the
    // header, leaving the position at 128; readArchMeta() then leaves it at
    // 256. So readHead_ became 256, and the guard in readNextTensor
    //     if (readHead_ <= sizeof(Nanof32BraidHeader) + FOOTER_SIZE)  // 256
    // fired on the very first call and returned false. Measured against a
    // structurally valid 17156-byte file produced by the writer:
    //     [NQBRAID] readAllTensors failed at tensor 0
    // readAllTensors therefore failed for EVERY input, which meant
    // loadModelFromNanof32Braid always returned false and
    // tests/nanof32_e2e_test.cpp could not pass no matter what .nqb existed.
    // The defect was in the re-arm, not in any file.
    //
    // Seeking to end explicitly also removes the dependency on a writer
    // filling header_->fileSize correctly; that field stays as a cross-check.
    file_.clear();
    file_.seekg(0, std::ios::end);
    const uint64_t actualSize = static_cast<uint64_t>(file_.tellg());
    readHead_ = actualSize;

    if (header_->fileSize != 0 && header_->fileSize != actualSize) {
        std::fprintf(stderr,
            "[NQBRAID] WARN: header fileSize=%llu but file is %llu bytes\n",
            (unsigned long long)header_->fileSize,
            (unsigned long long)actualSize);
    }

    for (uint32_t i = 0; i < header_->numTensors; ++i) {
        Nanof32BraidTensorFooter footer{};
        std::vector<bfloat16_t> data;
        // RAWRXD_NQB_DENSE_F32_PRESERVE_F32_001 -- ask for F32 so a dense-F32
        // payload is not narrowed on its way to the engine. Quantised payloads
        // still land in `data`.
        std::vector<float> f32;
        if (!readNextTensor(footer, data, &f32)) {
            std::fprintf(stderr, "[NQBRAID] readAllTensors failed at tensor %u\n", i);
            return false;
        }
        NQBraidBlock blk;
        blk.fileOffset = readHead_;  // offset after this read
        blk.byteCount = f32.empty() ? (data.size() * sizeof(bfloat16_t))
                                    : (f32.size() * sizeof(float));
        blk.bf16Data = std::move(data);
        blk.f32Data  = std::move(f32);
        // RAWRXD_NANOF32_BRAID_WRITER_001 -- carry the footer name into the
        // block. This was left default-constructed, so every block reached the
        // engine with an empty name. Deep2Engine::bindTensor copies blk.name
        // into WeightTensor::name, which is why forward diagnostics reported
        //     LinearW: non-finite output tensor=null type=30
        // for a tensor that was in fact named. A diagnostic that cannot say
        // which tensor it is looking at cannot localise a fault.
        blk.name = std::string(footer.name);
        blk.expertIndex = footer.expertIndex;
        blk.ready = true;
        outTensors.emplace_back(blk.name, std::move(blk));
    }
    return true;
}

bool Nanof32BraidStreamer::releaseTensor(uint32_t tensorIndex) {
    std::lock_guard<std::mutex> lk(cacheMtx_);
    return cache_.erase(tensorIndex) > 0;
}

} // namespace Deep2
