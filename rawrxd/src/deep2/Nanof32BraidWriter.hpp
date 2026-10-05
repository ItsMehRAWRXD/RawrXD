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
#include <fstream>
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

// ----------------------------------------------------------------------------
// RAWRXD_NQB_ONE_FORMAT_AUTHORITY_001
//
// The container had TWO serializers. nanof32WriteBraid() wrote the layout, and
// tools/gguf_to_nqb_converter.cpp wrote it again by hand -- its own appendTensor,
// its own footer construction, its own header backfill. Two writers means the
// header fields are computed twice, and the tree already contains the receipts of
// that going wrong: one writer announced bitsPerWeight=160 for a dense-F32 file,
// the other announced 320, and the real artifact shipped with 0. All three are
// wrong for the same reason -- each site decided the field on its own.
//
// This class is the ONE place the container is serialized. The one-shot writer
// is a loop over it, and the streaming converter drives it directly, so the
// footer layout, the census accumulation and the header backfill exist once.
//
// It streams: appendTensor() consumes one tensor and forgets it, so writing a
// 12.85 GB model never holds more than one tensor's payload.
//
// TRANSACTIONAL. Nothing is a valid artifact until finalize() has run AND the
// caller has verified the result. abort() removes the partial file so a truncated
// write can never be mistaken for a model.
// ----------------------------------------------------------------------------

// Everything the header asserts, measured rather than predicted.
struct Nanof32Census {
    uint64_t tensorCount  = 0;
    uint64_t paramCount   = 0;
    uint64_t payloadBytes = 0;
    uint64_t footerBytes  = 0;
    uint64_t codecCount[Deep2::NQBRAID_COUNT] = {0, 0, 0, 0, 0, 0};
    uint32_t bpw100       = 0;   // hundredths of a bit per weight, derived
};

// bpw100 = round(payloadBytes * 800 / elements). Declared here because a caller
// verifying a file needs the SAME derivation the writer used, and two copies of
// that formula is the defect this whole class exists to remove.
uint32_t nanof32DeriveBitsPerWeight100(uint64_t payloadBytes, uint64_t elements);

class Nanof32BraidStreamWriter {
public:
    Nanof32BraidStreamWriter() = default;
    ~Nanof32BraidStreamWriter();

    Nanof32BraidStreamWriter(const Nanof32BraidStreamWriter&) = delete;
    Nanof32BraidStreamWriter& operator=(const Nanof32BraidStreamWriter&) = delete;

    // Writes the provisional header, the arch meta and (optionally) the
    // vocabulary section. The provisional header is a placeholder: tensorCount,
    // paramCount, fileSize and bitsPerWeight are all zero until finalize().
    bool open(const std::string& path,
              const Nanof32BraidArchMeta& archMeta,
              const Nanof32VocabSpec* vocab);

    // Encodes one tensor and appends payload + footer. `values` is read for
    // exactly `elements` floats and is not retained.
    bool appendTensor(const std::string& name, uint64_t rows, uint64_t cols,
                      uint32_t quant, const void* values, uint64_t elements,
                      float scaleMin, float scaleMax, uint32_t expertIndex);

    // Backfills the header from the accumulated census and closes the file.
    bool finalize();

    // Closes and deletes the partial file. Called by the destructor when
    // finalize() has not run.
    void abort();

    const Nanof32Census& census()      const { return census_; }
    const std::string&   error()       const { return error_; }
    uint64_t             dataStart()   const { return dataStart_; }
    uint64_t             bytesWritten()const { return bytesWritten_; }
    bool                 isOpen()      const { return open_; }

private:
    std::ofstream        out_;
    std::string          path_;
    std::string          error_;
    Nanof32BraidHeader   header_{};
    Nanof32Census        census_{};
    uint64_t             dataStart_    = 0;
    uint64_t             bytesWritten_ = 0;
    bool                 open_         = false;
    bool                 finalized_    = false;
};

} // namespace Deep2