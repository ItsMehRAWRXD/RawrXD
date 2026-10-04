#pragma once
// ============================================================================
// Nanof32BraidWriter.hpp — On-disk WRITER for nanof32braidQuantless models
//
// RAWRXD_NANOF32_BRAID_WRITER_001
//
// WHY THIS FILE EXISTS
// --------------------
// The tree had a reader (Nanof32BraidStreamer) and a format definition
// (Nanof32BraidFormat.hpp) but NO writer, and no .nqb file existed anywhere.
// Measured before this file was written:
//
//   rg -i 'writeNanof32|saveNanof32|Nanof32BraidWriter|serializeNanof32|
//         emitNanof32|nqb_write|Nanof32BraidEncoder|BuildNanof32' src tools tests
//   -> 0 matches
//   Get-ChildItem -Recurse -Filter *.nqb  -> 0 files
//   tests/nanof32_e2e_test.cpp            -> compiles and links cleanly
//
// A reader with no writer and no sample file is an untested format.
// tests/nanof32_e2e_test.cpp could be BUILT but never RUN, because the input
// it loads did not exist and no code in the tree could produce one.
//
// This is the inverse of Nanof32BraidStreamer.cpp. It was written against that
// reader's actual behaviour, not against the comments in
// Nanof32BraidFormat.hpp, because the two disagree in at least one place that
// matters (see tensorDirOffset below).
//
// ON-DISK LAYOUT (forward order)
// ------------------------------
//   [0]      Nanof32BraidHeader        sizeof == 128 (alignas(64))
//   [128]    Nanof32BraidArchMeta      sizeof == 128 (alignas(64))
//   [256]    tensor[0] data
//            tensor[0] footer           sizeof == 128 (alignas(32))
//            tensor[1] data
//            tensor[1] footer
//            ...
//            tensor[N-1] data
//            tensor[N-1] footer          <- ends exactly at EOF
//
// The footer trails its data because the reader walks BACKWARD from EOF:
// Nanof32BraidStreamer::readNextTensor() subtracts sizeof(footer) to read the
// footer, then subtracts dataBytes to read the payload. So the LAST tensor
// written is the FIRST tensor read.
//
// The header's struct sizes are NOT their naive field sums. alignas(64) rounds
// Nanof32BraidHeader from 72 to 128 and Nanof32BraidArchMeta from 116 to 128;
// alignas(32) rounds Nanof32BraidTensorFooter from 108 to 128. Nothing here
// hardcodes those numbers -- every offset is computed from sizeof() -- because
// a hardcoded 64 or 72 would produce a file the reader cannot parse.
//
// tensorDirOffset: the reader never reads this field. It is set to the offset
// of the final footer (= fileSize - sizeof(footer)), which is where reverse
// traversal actually begins, and is documented as advisory rather than
// load-bearing. Writing dataStart here instead would also "work" because
// nothing consumes it; that is precisely why it is called out rather than
// quietly picked.
// ============================================================================

#include "Nanof32BraidFormat.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

// One tensor to be serialised. `rows`/`cols` are the logical (decompressed)
// shape; the byte count on disk is derived from `quant` and rows*cols, never
// supplied by the caller. Supplying a dataBytes value independently is how a
// writer and a reader drift apart.
struct Nanof32TensorSpec {
    std::string name;          // e.g. "blk.0.attn_q.weight"
    uint64_t    rows   = 0;
    uint64_t    cols   = 0;
    uint32_t    quant  = NQBRAID_DENSE_BF16;   // one of NQBRAID_*
    // RAWRXD_NANOF32_BRAID_WRITER_001: 0xFFFFFFFF means dense, matching the
    // footer's convention. Any other value marks this tensor as belonging to
    // that MoE expert, which is the only thing that lets a reader group
    // per-expert weights back together.
    uint32_t    expertIndex = 0xFFFFFFFFu;
    float       scaleMin = 0.0f;               // used by codebook + braid
    float       scaleMax = 1.0f;               // used by codebook + braid
    const float* values = nullptr;              // rows*cols floats, row-major
};

// One vocabulary entry. Mirrors the GGUF tokenizer.ggml.* metadata the
// tokenizer reads, so a braid model needs no GGUF sidecar.
struct Nanof32VocabSpec {
    std::string        model = "llama";   // tokenizer.ggml.model
    uint32_t           kind  = 1;         // BPETokenizer::Kind: 1 GPT2BPE, 2 SP
    std::vector<std::string> tokens;
    std::vector<float>       scores;
    std::vector<int32_t>     types;
    std::vector<std::string> merges;      // "A B" pairs; GPT2BPE only
    int32_t bosId = -1, eosId = -1, unkId = -1, sepId = -1, padId = -1;
    bool addBos = false, addEos = false;
};

// Result of a write attempt. `ok` is derived, never asserted by the caller.
struct Nanof32WriteResult {
    bool     ok           = false;
    uint64_t bytesWritten = 0;
    uint64_t paramCount   = 0;
    uint32_t tensorCount  = 0;
    uint64_t dataStart    = 0;      // first tensor payload offset
    uint64_t finalFooter  = 0;      // offset reverse traversal begins at
    std::string error;              // empty iff ok
};

// Bytes a tensor occupies on disk under `quant`, given its element count.
// Exposed so a caller can predict file size without writing, and so the
// writer's own accounting can be checked against this one function.
uint64_t nanof32CompressedBytes(uint32_t quant, uint64_t elements);

// Encoders. Each returns the byte count written into `out`, or 0 on a
// validation failure (unknown quant, null input, insufficient capacity).
// They are the exact inverse of the matching decompress* in
// Nanof32BraidStreamer.cpp and are byte-order sensitive to it.
uint64_t nanof32EncodeDenseF32(const float* values, uint64_t elements,
                               std::vector<uint8_t>& out);
uint64_t nanof32EncodeDenseBF16(const float* values, uint64_t elements,
                                std::vector<uint8_t>& out);
// 23 bits per 20 weights: 20 base bits (0 -> scaleMin, 1 -> scaleMax) followed
// by a 3-bit braid mode, bits packed LSB-first within each byte.
uint64_t nanof32EncodeBraid115(const float* values, uint64_t elements,
                               float scaleMin, float scaleMax,
                               std::vector<uint8_t>& out);

// Writes a complete .nqb file. Returns a derived result; on failure the file
// is removed so a truncated artefact cannot be mistaken for a usable model.
Nanof32WriteResult nanof32WriteBraid(const std::string& path,
                                     const Nanof32BraidArchMeta& archMeta,
                                     const std::vector<Nanof32TensorSpec>& tensors,
                                     const Nanof32VocabSpec* vocab = nullptr);

// Serialises a vocabulary section to the exact bytes a reader expects.
// Exposed so a caller can predict section size, and so the writer's own
// offset arithmetic can be checked against an independent computation.
std::vector<uint8_t> nanof32EncodeVocabSection(const Nanof32VocabSpec& v);

} // namespace Deep2