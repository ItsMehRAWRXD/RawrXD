#pragma once
// ============================================================================
// Nanof32BraidFormat.hpp — On-disk layout for nanof32braidQuantless models
// ============================================================================
// Format: reverse-streamed, sub-1-bit compressed, bfloat16 output
// Effective: 1.15 bits/weight for 671B params → ~98 GB on disk
//
// Stream direction: BACKWARD (read footer first, then data)
// Eliminates forward-parse stalls and NaN propagation from misaligned headers.
// ============================================================================

#include <cstdint>
#include <cstddef>

namespace Deep2 {

// ----------------------------------------------------------------------------
// Magic and version
// ----------------------------------------------------------------------------
constexpr uint32_t NANO_F32_BRAID_MAGIC      = 0x4E513252; // 'NQ2R'
constexpr uint32_t NANO_F32_BRAID_VERSION    = 1;

// ----------------------------------------------------------------------------
// Global file header (at byte 0 of the file)
// ----------------------------------------------------------------------------
struct alignas(64) Nanof32BraidHeader {
    uint32_t magic;           // NQ2R
    uint32_t version;       // 1
    uint64_t paramCount;      // total parameters (e.g. 671000000000)
    uint32_t bitsPerWeight;   // fixed-point: 115 = 1.15 bits/weight
    uint32_t numTensors;      // tensor count
    uint64_t tensorDirOffset; // absolute offset to tensor directory footer
    uint64_t fileSize;        // total file size in bytes
    // RAWRXD_NANOF32_BRAID_WRITER_001 -- vocabulary section.
    //
    // Without these the loader could only ever fall back to a dummy tokenizer
    // and the end-to-end test could not decode a single token:
    //     WARN=tokenizer_load_failed_using_dummy
    //     OUTPUT=(tokenizer unavailable, N tokens)
    // A reader that wants tokens but cannot get them will invent ids, so
    // nothing downstream can be trusted. Both are 0 when the file carries no
    // vocabulary, which is a valid state and is reported as such rather than
    // treated as corruption.
    uint64_t vocabSectionOffset;   // 0 = no vocabulary in this file
    uint64_t vocabSectionBytes;    // 0 = no vocabulary in this file
    uint64_t reserved[2];
};

// ----------------------------------------------------------------------------
// Architecture metadata (stored at byte 64, immediately after header)
// Required for Deep2Engine to configure geometry without a GGUF loader.
// ----------------------------------------------------------------------------
struct alignas(64) Nanof32BraidArchMeta {
    char     modelName[32];      // e.g. "DeepSeek-R1-671B"
    char     archName[16];       // e.g. "deepseek2"
    uint32_t numLayers;          // total transformer layers
    uint32_t numExperts;           // total experts (0 for dense)
    uint32_t activeExperts;        // routed per token (0 for dense)
    uint32_t hiddenDim;            // hidden dimension
    uint32_t numHeads;             // attention heads
    uint32_t numKVHeads;           // GQA / MLA kv heads
    uint32_t headDim;              // dimension per head
    uint32_t intermediateDim;      // FFN intermediate dimension
    uint32_t vocabSize;            // vocabulary size
    uint32_t contextLength;        // max context length
    uint32_t ropeType;             // 0=none, 1=NeoX, 2=GPT-J, 3=MLA
    float    normEps;              // RMSNorm epsilon
    uint32_t moeGateDim;           // MoE gate dimension
    uint32_t hasSharedExperts;     // 1 if shared expert present
    // RAWRXD_NANOF32_BRAID_WRITER_001
    // One reserved slot is now ropeTheta. The braid path could not execute a
    // forward pass without it:
    //     [Deep2Engine] forward failed: RoPE: theta not bound from model metadata
    // because EngineConfig::ropeTheta is documented "unset until dynamic
    // geometry" and the GGUF path fills it from GGUF metadata, while this
    // format carried only ropeType. Rather than have every reader guess
    // 10000.0f, the value is carried. This consumes one word of padding that
    // existed for exactly this purpose, so sizeof(Nanof32BraidArchMeta) is
    // unchanged at 128 and no file written against the previous field layout
    // changes size. Values in the old reserved[0] slot are ignored on read.
    float    ropeTheta;            // RoPE base theta; 0 means "unset"
    // RAWRXD_NANOF32_BRAID_WRITER_001 -- MLA geometry.
    //
    // ropeType == 3 selects the MLA path, but the format carried no MLA
    // dimensions at all, so Deep2Engine's CPU MLA route could never satisfy
    // its own geometry guard and refused every MLA braid model:
    //     [CPU_MLA] reject: incomplete geometry H=64 heads=4
    //                kvRank=0 nope=0 rope=0 vlen=0
    // deep2_cpu_mla.cpp requires kvLoraRank, qkNopeHeadDim, qkRopeHeadDim
    // (and even), and vHeadDim, all from modelWeights.
    //
    // These five words consume the remaining reserved[] padding exactly:
    // the previous layout ended at byte 108 of a 128-byte struct, and
    // 108 + 5*4 == 128, so sizeof(Nanof32BraidArchMeta) is unchanged and no
    // file offset moves. static_assert below enforces that.
    uint32_t qLoraRank;          // attn_q_a output width
    uint32_t kvLoraRank;         // attn_kv_a latent width (kvRank)
    uint32_t qkNopeHeadDim;      // per-head non-positional key/query width
    uint32_t qkRopeHeadDim;      // per-head positional width; MUST be even
    uint32_t vHeadDim;           // per-head value width
};

static_assert(sizeof(Nanof32BraidArchMeta) == 128,
              "Nanof32BraidArchMeta must stay 128 bytes: the MLA fields were "
              "added into existing padding, not appended past the alignment "
              "boundary. If this fires, every .nqb offset is wrong.");

// ----------------------------------------------------------------------------
// Per-tensor footer (read FIRST when reverse-streaming)
// Appended at the end of each tensor's data block.
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// Vocabulary section
//
// RAWRXD_NQBRAID_TOKENIZER_E2E_001
//
// Stored between the arch meta and the first tensor. The reader walks tensors
// BACKWARD from EOF, so inserting a forward section here does not disturb
// tensor traversal at all -- only dataStart moves.
//
// Layout:
//   [Nanof32VocabHeader]
//   [string blob]                  entryCount NUL-terminated UTF-8 strings
//   [offset table]  uint32[entryCount]  byte offset of each string in the blob
//   [scores]        float[entryCount]
//   [types]         int32[entryCount]
//   [mergeCount]    uint32
//   [merges blob]                  newline-joined "A B" merge pairs
//
// The offset table is explicit rather than implied by walking NULs. Walking
// NULs couples the reader to the writer's exact encoding and turns one
// truncated string into a silently shifted vocabulary.
// ----------------------------------------------------------------------------

constexpr uint32_t NANO_F32_BRAID_VOCAB_MAGIC = 0x564B514EU;  // 'NQKV'

struct alignas(64) Nanof32VocabHeader {
    uint32_t magic;            // NANO_F32_BRAID_VOCAB_MAGIC
    uint32_t kind;             // mirrors Deep2::BPETokenizer::Kind
    uint32_t entryCount;
    uint32_t strBytes;         // size of the string blob
    uint32_t flags;            // bit0 add_bos, bit1 add_eos
    uint32_t mergeCount;
    uint32_t mergeBytes;
    int32_t  bosId;
    int32_t  eosId;
    int32_t  unkId;
    int32_t  sepId;
    int32_t  padId;
    char     model[16];        // tokenizer.ggml.model, e.g. "llama"
    uint64_t reserved[3];
};

static_assert(sizeof(Nanof32VocabHeader) == 128,
              "Nanof32VocabHeader must stay 128 bytes so the string blob that "
              "follows begins on a 64-byte boundary.");

constexpr uint32_t NQ_VOCAB_FLAG_ADD_BOS = 1u;
constexpr uint32_t NQ_VOCAB_FLAG_ADD_EOS = 2u;

struct alignas(32) Nanof32BraidTensorFooter {
    uint32_t magic;           // NQ2R (validates structural integrity)
    uint32_t quantType;       // decompression dispatch index
    float    scaleMin;        // global floor (prevents NaN dispatch)
    float    scaleMax;        // global ceiling
    uint64_t rows;            // output dimension
    uint64_t cols;            // input dimension
    uint64_t dataBytes;       // compressed byte count
    uint32_t expertIndex;     // 0xFFFFFFFF for dense, else expert id
    char     name[64];        // tensor name (null-terminated, e.g. "blk.0.attn_q.weight")
};

// Quant type dispatch indices
constexpr uint32_t NQBRAID_DENSE_F32      = 0;  // uncompressed float32
constexpr uint32_t NQBRAID_DENSE_BF16     = 1;  // uncompressed bfloat16
constexpr uint32_t NQBRAID_CODEBOOK_1BIT  = 2;  // 1-bit codebook (2 centroids)
constexpr uint32_t NQBRAID_CODEBOOK_2BIT  = 3;  // 2-bit codebook (4 centroids)
constexpr uint32_t NQBRAID_CODEBOOK_3BIT  = 4;  // 3-bit codebook (8 centroids)
constexpr uint32_t NQBRAID_BRAID_115      = 5;  // 1.15-bit braid (sub-1-bit)
constexpr uint32_t NQBRAID_COUNT          = 6;

// ----------------------------------------------------------------------------
// Block constants
// ----------------------------------------------------------------------------
constexpr size_t NQBRAID_BLOCK_SIZE = 4096;       // disk read granularity
constexpr size_t NQBRAID_CACHE_BLOCKS = 256;     // in-memory cache size

} // namespace Deep2
