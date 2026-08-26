// ============================================================================
// Batch 15A — GGUF Alignment Diagnostic
// Instruments blk.29.attn_qkv.weight (or any tensor by name)
// Logs: offset, size, file size, quant type, alignment, block count,
//       expected bytes/block, verifies bounds, copies to aligned buffer,
//       runs certified dequant.
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <chrono>
#include "GGUFLoader.hpp"

using namespace Deep2;

static void printUsage(const char* prog) {
    printf("Usage: %s <model.gguf> [tensor_name]\n", prog);
    printf("  Default tensor: blk.29.attn_qkv.weight\n");
    printf("  Environment: RAWRXD_DIAG_VERBOSE=1 for full hex dump\n");
}

static bool g_verbose = false;

static void logTensorAudit(const TensorInfo& t, uint64_t dataOffset, uint64_t fileSize) {
    uint64_t tensorStart = dataOffset + t.offset;
    uint64_t tensorEnd   = tensorStart + t.size;
    bool     boundsOk    = (tensorEnd <= fileSize);
    size_t   alignment   = (tensorStart % 64);
    size_t   blockSize   = t.GetBlockSize();
    size_t   elemsPerBlk = t.GetElemsPerBlock();
    size_t   numBlocks   = t.GetNumBlocks();
    size_t   expectedBytes = numBlocks * blockSize;

    printf("\n");
    printf("============================================================\n");
    printf("TENSOR AUDIT: %s\n", t.name.c_str());
    printf("============================================================\n");
    printf("  GGUF tensor offset (relative) : %llu\n", (unsigned long long)t.offset);
    printf("  Data section offset            : %llu\n", (unsigned long long)dataOffset);
    printf("  Absolute file offset           : %llu\n", (unsigned long long)tensorStart);
    printf("  Tensor size (bytes)            : %zu\n", t.size);
    printf("  Tensor end in file             : %llu\n", (unsigned long long)tensorEnd);
    printf("  File size                      : %llu\n", (unsigned long long)fileSize);
    printf("  Bounds check                   : %s\n", boundsOk ? "PASS" : "FAIL");
    printf("  Alignment (mod 64)             : %zu (%s)\n", alignment,
           alignment == 0 ? "64-byte aligned" : "NOT 64-byte aligned");
    printf("  Quantization type              : %s (%d)\n", GGUFLoader::GetTypeName(t.type), (int)t.type);
    printf("  Dimensions                     : ");
    for (auto d : t.dimensions) printf("%llu ", (unsigned long long)d);
    printf("\n");
    printf("  Element count                  : %llu\n", (unsigned long long)t.GetNumElements());
    printf("  Block size (bytes)             : %zu\n", blockSize);
    printf("  Elements per block             : %zu\n", elemsPerBlk);
    printf("  Computed block count           : %zu\n", numBlocks);
    printf("  Expected bytes (blocks*bsize)  : %zu\n", expectedBytes);
    printf("  Size match                     : %s\n",
           expectedBytes == t.size ? "PASS" : "MISMATCH");
    printf("============================================================\n");
}

static void hexDump(const uint8_t* data, size_t len, const char* label) {
    printf("\n%s (first %zu bytes):\n", label, len > 64 ? 64 : len);
    for (size_t i = 0; i < len && i < 64; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len > 64) printf("... (%zu more bytes omitted)\n", len - 64);
    printf("\n");
}

static void verifyDequantQ4_K(const uint8_t* src, size_t numBlocks) {
    printf("[DEQUANT] Verifying Q4_K dequant on %zu blocks...\n", numBlocks);
    const block_q4_K* blocks = (const block_q4_K*)src;
    float minVal = 1e30f, maxVal = -1e30f;
    size_t totalElems = 0;
    bool allFinite = true;

    for (size_t b = 0; b < numBlocks; ++b) {
        float d  = 0.0f, dmin = 0.0f;
        // FP16 -> FP32 for super-scale and super-min
        uint16_t hD = blocks[b].d;
        uint16_t hDmin = blocks[b].dmin;
        // Simple FP16 unpack (non-IEEE subnormal path)
        auto fp16_to_f32 = [](uint16_t h) -> float {
            uint32_t sign = (h >> 15) & 0x1;
            uint32_t exp  = (h >> 10) & 0x1F;
            uint32_t mant = h & 0x3FF;
            if (exp == 0) return 0.0f; // subnormal -> 0 for diagnostic
            if (exp == 31) return (sign ? -1.0f : 1.0f) * 1e30f; // inf
            uint32_t f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
            float r; memcpy(&r, &f, 4); return r;
        };
        d    = fp16_to_f32(hD);
        dmin = fp16_to_f32(hDmin);

        if (g_verbose && b == 0) {
            printf("[DEQUANT] Block 0: d=%g dmin=%g\n", d, dmin);
        }

        for (int sb = 0; sb < 8; ++sb) {
            uint8_t sc = blocks[b].scales[sb] & 63;
            uint8_t m  = blocks[b].scales[sb + 4] & 63;
            if (sb >= 4) {
                sc = (blocks[b].scales[sb + 4] & 0x0F) | ((blocks[b].scales[sb - 4] >> 6) << 4);
                m  = (blocks[b].scales[sb + 4] >> 4) | ((blocks[b].scales[sb] >> 6) << 4);
            }
            float scale = d * sc;
            float min   = dmin * m;
            for (int k = 0; k < 16; ++k) {
                uint8_t byte = blocks[b].qs[sb * 16 + k];
                int lo = byte & 0xF;
                int hi = (byte >> 4) & 0xF;
                float vLo = scale * lo - min;
                float vHi = scale * hi - min;
                if (!std::isfinite(vLo) || !std::isfinite(vHi)) allFinite = false;
                if (vLo < minVal) minVal = vLo;
                if (vLo > maxVal) maxVal = vLo;
                if (vHi < minVal) minVal = vHi;
                if (vHi > maxVal) maxVal = vHi;
                totalElems += 2;
            }
        }
    }

    printf("[DEQUANT] Elements checked: %zu\n", totalElems);
    printf("[DEQUANT] All finite      : %s\n", allFinite ? "PASS" : "FAIL");
    printf("[DEQUANT] Value range     : [%g, %g]\n", minVal, maxVal);
}

static void verifyDequantQ8_0(const uint8_t* src, size_t numBlocks) {
    printf("[DEQUANT] Verifying Q8_0 dequant on %zu blocks...\n", numBlocks);
    const block_q8_0* blocks = (const block_q8_0*)src;
    float minVal = 1e30f, maxVal = -1e30f;
    size_t totalElems = 0;
    bool allFinite = true;

    auto fp16_to_f32 = [](uint16_t h) -> float {
        uint32_t sign = (h >> 15) & 0x1;
        uint32_t exp  = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;
        if (exp == 0) return 0.0f;
        if (exp == 31) return (sign ? -1.0f : 1.0f) * 1e30f;
        uint32_t f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
        float r; memcpy(&r, &f, 4); return r;
    };

    for (size_t b = 0; b < numBlocks; ++b) {
        float d = fp16_to_f32(blocks[b].d);
        for (int i = 0; i < 32; ++i) {
            float v = d * (float)blocks[b].qs[i];
            if (!std::isfinite(v)) allFinite = false;
            if (v < minVal) minVal = v;
            if (v > maxVal) maxVal = v;
            totalElems++;
        }
    }
    printf("[DEQUANT] Elements checked: %zu\n", totalElems);
    printf("[DEQUANT] All finite      : %s\n", allFinite ? "PASS" : "FAIL");
    printf("[DEQUANT] Value range     : [%g, %g]\n", minVal, maxVal);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    const char* modelPath = argv[1];
    const char* targetTensor = (argc > 2) ? argv[2] : "blk.29.attn_qkv.weight";
    g_verbose = (getenv("RAWRXD_DIAG_VERBOSE") != nullptr && getenv("RAWRXD_DIAG_VERBOSE")[0] == '1');

    printf("[BATCH15A] GGUF Alignment Diagnostic\n");
    printf("[BATCH15A] Model: %s\n", modelPath);
    printf("[BATCH15A] Target tensor: %s\n", targetTensor);
    printf("[BATCH15A] Verbose: %s\n", g_verbose ? "YES" : "NO");
    printf("\n");

    // Step 1: Get file size via stat
    struct __stat64 st;
    if (_stat64(modelPath, &st) != 0) {
        printf("[BATCH15A] FAIL: Cannot stat file: %s\n", modelPath);
        return 1;
    }
    uint64_t fileSize = (uint64_t)st.st_size;
    printf("[BATCH15A] File size: %llu bytes\n", (unsigned long long)fileSize);

    // Step 2: Load metadata (no tensor data) to get dataOffset
    GGUFLoadOptions metaOpts;
    metaOpts.loadTensors = false;
    metaOpts.verbose = false;
    GGUFLoadResult metaResult = GGUFLoader::Load(modelPath, metaOpts);
    if (!metaResult.success && metaResult.tensors.empty()) {
        printf("[BATCH15A] FAIL: Could not load metadata\n");
        return 1;
    }
    uint64_t dataOffset = metaResult.dataOffset;
    printf("[BATCH15A] Data section offset: %llu\n", (unsigned long long)dataOffset);

    // Step 2: Load metadata + tensor info (no data yet)
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = true;

    // Step 3: Find target tensor
    const TensorInfo* target = nullptr;
    for (const auto& t : metaResult.tensors) {
        if (t.name == targetTensor) {
            target = &t;
            break;
        }
    }

    if (!target) {
        printf("[BATCH15A] FAIL: Tensor '%s' not found in model\n", targetTensor);
        printf("[BATCH15A] Available tensors (first 20):\n");
        size_t shown = 0;
        for (const auto& t : metaResult.tensors) {
            if (shown++ < 20) printf("  - %s\n", t.name.c_str());
        }
        return 1;
    }

    // Step 4: Full audit log
    logTensorAudit(*target, dataOffset, fileSize);

    // Step 5: Load ONLY the target tensor data into aligned buffer
    printf("[BATCH15A] Loading target tensor data into aligned buffer...\n");
    FILE* fp = fopen(modelPath, "rb");
    if (!fp) {
        printf("[BATCH15A] FAIL: Cannot open file for read\n");
        return 1;
    }

    uint64_t tensorStart = dataOffset + target->offset;
    size_t allocSize = target->size + 63; // room for alignment padding
    void* rawBuf = _aligned_malloc(allocSize, 64);
    if (!rawBuf) {
        printf("[BATCH15A] FAIL: _aligned_malloc(%zu, 64) failed\n", allocSize);
        fclose(fp);
        return 1;
    }

    if (_fseeki64(fp, (long long)tensorStart, SEEK_SET) != 0) {
        printf("[BATCH15A] FAIL: _fseeki64 to %llu failed\n", (unsigned long long)tensorStart);
        _aligned_free(rawBuf);
        fclose(fp);
        return 1;
    }

    size_t read = fread(rawBuf, 1, target->size, fp);
    fclose(fp);

    if (read != target->size) {
        printf("[BATCH15A] FAIL: fread expected %zu, got %zu\n", target->size, read);
        _aligned_free(rawBuf);
        return 1;
    }
    printf("[BATCH15A] Tensor data loaded: %zu bytes at %p (64-byte aligned: %s)\n",
           read, rawBuf,
           (((uintptr_t)rawBuf) % 64 == 0) ? "YES" : "NO");

    if (g_verbose) {
        hexDump((const uint8_t*)rawBuf, target->size, "Tensor raw bytes");
    }

    // Step 6: Verify first-block header sanity
    printf("\n[BATCH15A] First-block header sanity check...\n");
    if (target->type == GGMLType::GGML_TYPE_Q4_K && target->size >= sizeof(block_q4_K)) {
        const block_q4_K* b0 = (const block_q4_K*)rawBuf;
        printf("  block_q4_K[0].d     = 0x%04X\n", b0->d);
        printf("  block_q4_K[0].dmin  = 0x%04X\n", b0->dmin);
        printf("  block_q4_K[0].scales= ");
        for (int i = 0; i < 12; ++i) printf("%02X ", b0->scales[i]);
        printf("\n");
    } else if (target->type == GGMLType::GGML_TYPE_Q8_0 && target->size >= sizeof(block_q8_0)) {
        const block_q8_0* b0 = (const block_q8_0*)rawBuf;
        printf("  block_q8_0[0].d     = 0x%04X\n", b0->d);
        printf("  block_q8_0[0].qs[0..7]= ");
        for (int i = 0; i < 8; ++i) printf("%02X ", (uint8_t)b0->qs[i]);
        printf("\n");
    } else if (target->type == GGMLType::GGML_TYPE_F32 && target->size >= 4) {
        float f0 = ((const float*)rawBuf)[0];
        printf("  f32[0] = %g\n", f0);
    } else if (target->type == GGMLType::GGML_TYPE_F16 && target->size >= 2) {
        printf("  f16[0] = 0x%04X\n", ((const uint16_t*)rawBuf)[0]);
    }

    // Step 7: Run dequant verification
    printf("\n[BATCH15A] Running dequant verification...\n");
    if (target->type == GGMLType::GGML_TYPE_Q4_K) {
        verifyDequantQ4_K((const uint8_t*)rawBuf, target->GetNumBlocks());
    } else if (target->type == GGMLType::GGML_TYPE_Q8_0) {
        verifyDequantQ8_0((const uint8_t*)rawBuf, target->GetNumBlocks());
    } else if (target->type == GGMLType::GGML_TYPE_F32 || target->type == GGMLType::GGML_TYPE_F16) {
        printf("[DEQUANT] Skipping dequant for non-quantized type (no blocks to verify)\n");
    } else {
        printf("[DEQUANT] WARNING: No certified dequant for type %s yet\n",
               GGUFLoader::GetTypeName(target->type));
    }

    // Step 8: Copy-to-aligned verification (the exact pattern Deep2Engine should use)
    printf("\n[BATCH15A] Aligned-copy verification...\n");
    void* alignedCopy = _aligned_malloc(target->size + 63, 64);
    if (!alignedCopy) {
        printf("[BATCH15A] FAIL: _aligned_malloc for copy failed\n");
        _aligned_free(rawBuf);
        return 1;
    }
    memcpy(alignedCopy, rawBuf, target->size);
    printf("  Source      : %p\n", rawBuf);
    printf("  Destination : %p\n", alignedCopy);
    printf("  Bytes copied: %zu\n", target->size);
    printf("  Dest aligned: %s\n", (((uintptr_t)alignedCopy) % 64 == 0) ? "YES" : "NO");
    printf("  Byte-match  : %s\n",
           (memcmp(rawBuf, alignedCopy, target->size) == 0) ? "PASS" : "FAIL");

    _aligned_free(alignedCopy);
    _aligned_free(rawBuf);

    printf("\n[BATCH15A] DIAGNOSTIC COMPLETE — tensor '%s'\n", targetTensor);
    printf("[BATCH15A] If all checks PASS, the GGUF loader is correct.\n");
    printf("[BATCH15A] If any check FAILS, the loader or file is corrupt.\n");
    return 0;
}
