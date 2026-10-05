#pragma once
// ============================================================================
// Nanof32BraidStreamer.hpp — Reverse-streaming loader for nanof32braidQuantless
// ============================================================================
// Reads tensor footers FIRST (backward from EOF), then raw data.
// Decompresses 1.15-bit braid → bfloat16 on demand.
// ============================================================================

#include "Nanof32BraidFormat.hpp"
#include "BP16Streamer.hpp"  // reuses bfloat16_t
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <fstream>

namespace Deep2 {

// ----------------------------------------------------------------------------
// Forward declarations
// ----------------------------------------------------------------------------
struct WeightTensor;

// ----------------------------------------------------------------------------
// Cached tensor block
// ----------------------------------------------------------------------------
struct NQBraidBlock {
    std::string name;             // tensor name from footer
    // RAWRXD_NANOF32_BRAID_WRITER_001 -- carried from the footer so per-expert
    // tensors can be grouped. 0xFFFFFFFF means dense, per the footer's own
    // convention. The loader previously had no way to tell which expert a
    // tensor belonged to, so every MoE expert slot stayed empty and
    // computeMoE refused with "expert tensors not fully bound".
    uint32_t    expertIndex = 0xFFFFFFFFu;
    uint64_t fileOffset = 0;
    size_t   byteCount = 0;
    std::vector<bfloat16_t> bf16Data;  // decompressed output
    // RAWRXD_NQB_DENSE_F32_PRESERVE_F32_001
    //
    // A block stored as NQBRAID_DENSE_F32 held 32 bits per weight on disk and
    // this class threw 16 of them away on the way in, unconditionally. The
    // measured cost over the 3.21B weights of llama3.2-3b-Q2_K was a maximum
    // absolute error of 0.0417309 per weight -- and because the loss happened
    // inside the READER, no comparison downstream could tell "the file is
    // wrong" from "the loader rounded it", so a F32 container could never be
    // verified against the F32 model it came from.
    //
    // Quantised formats keep using bf16Data, which is the representation they
    // actually decompress to. Dense F32 now populates this instead, so the
    // engine binds the exact values that were written.
    std::vector<float> f32Data;
    bool     ready = false;

    // Element count regardless of which representation was materialised.
    size_t elements() const { return f32Data.empty() ? bf16Data.size() : f32Data.size(); }
};

// ----------------------------------------------------------------------------
// Reverse streamer — reads backward, decompresses to BF16
// ----------------------------------------------------------------------------
class Nanof32BraidStreamer {
public:
    Nanof32BraidStreamer() = default;
    ~Nanof32BraidStreamer();

    // Open model file and validate header
    bool open(const std::string& path);
    void close();
    bool isOpen() const { return file_.is_open(); }

    // Read next tensor footer from EOF backward, then its data
    // Returns false when no more tensors (readHead <= header size)
    //
    // RAWRXD_NQB_DENSE_F32_PRESERVE_F32_001: outF32, when supplied, receives
    // NQBRAID_DENSE_F32 payloads WITHOUT narrowing and outData is left empty
    // for them. Omit it and dense F32 falls back to bfloat16 materialisation.
    bool readNextTensor(Nanof32BraidTensorFooter& outFooter,
                        std::vector<bfloat16_t>& outData,
                        std::vector<float>* outF32 = nullptr);

    // Seek so that the next readNextTensor() call returns the tensor at
    // `index`, where index 0 is the FIRST tensor written (lowest offset) and
    // index header()->numTensors-1 is the LAST.
    //
    // RAWRXD_NQBRAID_READER_API_INTEGRITY_001
    //
    // This was DECLARED and never DEFINED anywhere in the tree. A caller
    // compiled clean and then failed at LINK with LNK2019, which is the worst
    // failure mode for a public interface: the type system said the function
    // existed. Rather than delete the declaration -- random access without
    // materialising the model is exactly what the 12.85 GB artifact needs, and
    // the two full-model probes below exist only because it was missing -- it is
    // implemented here against the same reverse footer chain readNextTensor uses.
    //
    // Cost is index+1 footer reads of 128 bytes each: bounded, and independent of
    // payload size.
    bool seekTensor(uint32_t index);

    // RAWRXD_NQBRAID_TOKENIZER_E2E_001: read the vocabulary section.
    //
    // Returns false when the file carries none (offset 0) OR when the section
    // is structurally invalid. Those are different conditions and the caller
    // must be able to tell them apart, so `present` reports whether the file
    // CLAIMED a vocabulary. A file that claims one and has a broken one is a
    // defect; a file with none is simply a model without text.
    bool readVocabSection(std::vector<uint8_t>& out, bool& present);

    // True when the header declares a vocabulary section.
    bool hasVocab() const { return header_ && header_->vocabSectionBytes != 0; }

    // RAWRXD_NQBRAID_READER_API_INTEGRITY_001
    //
    // loadTensor() was ALSO declared and never defined, and its return type
    // `const bfloat16_t*` hardcodes the narrowed representation -- so it could
    // never have been a lossless accessor for a DENSE_F32 payload even once
    // written. It is REMOVED rather than implemented, because implementing it
    // would reintroduce exactly the silent precision narrowing that
    // RAWRXD_NQBRAID_DENSE_F32_PRESERVE_F32_001 removed from the production
    // path. Callers that need a whole tensor use:
    //
    //     seekTensor(i); readNextTensor(footer, bf16, &f32);
    //
    // which yields the lossless F32 image for DENSE_F32 and the codec-decoded
    // values for quantised payloads.
    //
    // A public interface should be executable authority. A declaration with no
    // definition is neither.

    // Release cached tensor
    bool releaseTensor(uint32_t tensorIndex);

    // Stats
    uint64_t bytesReadFromDisk() const { return bytesRead_; }
    uint64_t tensorsLoaded()   const { return tensorsLoaded_; }

    // Header access
    const Nanof32BraidHeader* header() const { return header_.get(); }

    // Architecture metadata (at byte 64, after header)
    bool readArchMeta(Nanof32BraidArchMeta& outMeta);

    // Read all tensors into memory (for model load)
    bool readAllTensors(std::vector<std::pair<std::string, NQBraidBlock>>& outTensors);

    // RAWRXD_BRAID_BLOCK_OWNERSHIP_001
    //
    // The engine's loader binds WeightTensor::data straight into a block's
    // bfloat16 buffer and then returns. Those buffers must therefore outlive
    // the loading function, or every bound WeightTensor dangles. The engine
    // parks the blocks here for exactly that reason.
    std::mutex& cacheMutex() noexcept { return cacheMtx_; }
    std::unordered_map<uint32_t, NQBraidBlock>& cache() noexcept { return cache_; }

private:
    std::ifstream file_;
    std::unique_ptr<Nanof32BraidHeader> header_;
    uint64_t readHead_ = 0;           // current backward offset
    uint64_t bytesRead_ = 0;
    uint64_t tensorsLoaded_ = 0;

    mutable std::mutex cacheMtx_;
    std::unordered_map<uint32_t, NQBraidBlock> cache_;

    // Decompress 1.15-bit braid to BF16 (23 bits per 20 weights)
    bool decompressBraid(const uint8_t* compressed, size_t compBytes,
                         bfloat16_t* output, size_t elements,
                         float scaleMin, float scaleMax);

    // Decompress codebook-quantized to BF16
    bool decompressCodebook(const uint8_t* compressed, size_t compBytes,
                            uint32_t bits, bfloat16_t* output, size_t elements,
                            float scaleMin, float scaleMax);

    // Read raw bytes from file at absolute offset
    bool readAt(uint64_t offset, void* buffer, size_t bytes);
};

} // namespace Deep2
