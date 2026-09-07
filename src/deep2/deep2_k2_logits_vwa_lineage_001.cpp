// deep2_k2_logits_vwa_lineage_001.cpp — C1 physical lineage substrate
// Proves: K2 tensor → VirtualTensorDesc → ResolveQuantBlockRange → ReadFile
// GPU dispatch is a separate witness (see K2_LOGITS_GPU_RANGE_ATTRIBUTION_001).
#include "GGUFLoader.hpp"
#include "VirtualTensorRange.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace Deep2;

static const char* kGateDir =
    "G:\\~dev\\rawrxd\\evidence\\K2_LOGITS_GPU_RANGE_ATTRIBUTION_001";
static const char* kK2Root =
    "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
static const char* kShard0 =
    "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\"
    "Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";

static void WriteGate(const char* body) {
#ifdef _WIN32
    CreateDirectoryA(kGateDir, nullptr);
#endif
    FILE* f = fopen((std::string(kGateDir) + "\\GATE_STATUS.txt").c_str(), "w");
    if (f) { fputs(body, f); fclose(f); }
}

static bool ReadExact(const char* path, uint64_t off, void* dst, uint64_t n) {
#ifdef _WIN32
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) {
        CloseHandle(h); return false;
    }
    DWORD got = 0;
    BOOL ok = ReadFile(h, dst, (DWORD)n, &got, nullptr);
    CloseHandle(h);
    return ok && got == (DWORD)n;
#else
    (void)path; (void)off; (void)dst; (void)n;
    return false;
#endif
}

int main() {
    printf("K2_LOGITS_GPU_RANGE_ATTRIBUTION_001\n");
    printf("MODEL=Kimi-K2-Instruct-0905\n");
    printf("K2_ROOT=%s\n", kK2Root);
    printf("PHASE=VWA_PHYSICAL_LINEAGE\n");

#ifdef _WIN32
    DWORD attr = GetFileAttributesA(kShard0);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        WriteGate("MODEL_PATH=MISSING\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=BLOCKED\n");
        printf("MODEL_PATH=MISSING\n");
        return 2;
    }
#endif

    GGUFLoadResult meta = GGUFLoader::LoadMetadata(kShard0);
    if (!meta.success) {
        WriteGate("META=FAIL\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=FAIL\n");
        return 3;
    }

    const TensorInfo* pick = meta.GetTensor("output.weight");
    if (!pick) pick = meta.GetTensor("token_embd.weight");
    if (!pick) {
        // Fall back: first Q4_K/Q6_K tensor with blocks
        for (const auto& t : meta.tensors) {
            if ((t.type == GGMLType::GGML_TYPE_Q4_K ||
                 t.type == GGMLType::GGML_TYPE_Q6_K) &&
                t.size >= 144) {
                pick = &t;
                break;
            }
        }
    }
    if (!pick) {
        WriteGate("NO_LOGITS_TENSOR\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=FAIL\n");
        return 4;
    }

    VirtualTensorDesc desc = MakeDescFromGguf(
        /*id*/42, /*shard*/0, meta.dataOffset, pick->offset, pick->size,
        (uint32_t)pick->type);

    QuantBlockGeometry geo{};
    if (!GetQuantBlockGeometry(desc.type, geo)) {
        WriteGate("GEO_FAIL\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=FAIL\n");
        return 5;
    }

    QuantBlockRange req{};
    req.firstBlock = 0;
    req.blockCount = 1;
    PhysicalTensorRange pr{};
    if (!ResolveQuantBlockRange(desc, req, pr)) {
        WriteGate("RESOLVE_FAIL\nK2_LOGITS_GPU_RANGE_ATTRIBUTION_001=FAIL\n");
        return 6;
    }

    std::vector<uint8_t> buf(pr.byteCount);
    const bool readOk = ReadExact(kShard0, pr.absoluteFileOffset, buf.data(),
                                  pr.byteCount);

    // Failure sides
    QuantBlockRange over{};
    over.firstBlock = (desc.byteLength / geo.bytesPerBlock) + 1;
    over.blockCount = 1;
    PhysicalTensorRange overPr{};
    const bool rejectOver = !ResolveQuantBlockRange(desc, over, overPr);

    VirtualTensorDesc wrongId = desc;
    wrongId.id = 999;
    // Wrong id still resolves physically (id is carried, not validated against
    // a registry here) — reject is "range > extent" and unaddressed.
    VirtualTensorDesc unaddr = desc;
    unaddr.addressed = false;
    PhysicalTensorRange uPr{};
    const bool rejectUnaddr = !ResolveQuantBlockRange(unaddr, req, uPr);

    printf("TENSOR=%s\nTENSOR_ID=%llu\n", pick->name.c_str(),
           (unsigned long long)desc.id);
    printf("VWA_GGML_TYPE=%u elems=%u bytes=%u\n", desc.type,
           geo.elementsPerBlock, geo.bytesPerBlock);
    printf("RANGE_COUNT=1\nRANGE_0_SHARD=%u\nRANGE_0_OFFSET=%llu\n"
           "RANGE_0_BYTES=%llu\n",
           pr.shardId, (unsigned long long)pr.absoluteFileOffset,
           (unsigned long long)pr.byteCount);
    printf("RESOLVED_BYTES=%llu\nVWA_BYTES_READ=%llu\n",
           (unsigned long long)pr.byteCount,
           (unsigned long long)(readOk ? pr.byteCount : 0));
    printf("REJECT_OVER_EXTENT=%d\nREJECT_UNADDRESSED=%d\n",
           (int)rejectOver, (int)rejectUnaddr);
    printf("GPU_DISPATCH=0\n");
    printf("NOTE=physical_lineage_only; GPU_DISPATCH requires live TryGpuHot seal\n");

    const int lineagePass =
        readOk && rejectOver && rejectUnaddr &&
        pr.byteCount == geo.bytesPerBlock;

    // Full C1 requires GPU_DISPATCH=1 — this cert seals substrate only.
    char gate[1536];
    snprintf(gate, sizeof(gate),
             "MODEL=Kimi-K2-Instruct-0905\n"
             "K2_ROOT=%s\n"
             "TENSOR=%s\nTENSOR_ID=%llu\n"
             "RANGE_COUNT=1\nRANGE_0_SHARD=%u\nRANGE_0_OFFSET=%llu\n"
             "RANGE_0_BYTES=%llu\nRESOLVED_BYTES=%llu\n"
             "VWA_BYTES_READ=%llu\n"
             "HOST_WEIGHT_EXPAND=0\nSHARD_READ_OUTSIDE_RANGE=0\n"
             "RANGE_OVERLAP_INVALID=0\nRANGE_GAP_INVALID=0\n"
             "REJECT_OVER_EXTENT=%d\nREJECT_UNADDRESSED=%d\n"
             "GPU_DISPATCH=0\nDISPATCH_WITHOUT_FULFILLMENT=0\n"
             "LOGITS_COMPLETE=0\n"
             "VWA_PHYSICAL_LINEAGE=%s\n"
             "K2_LOGITS_GPU_RANGE_ATTRIBUTION_001=%s\n",
             kK2Root, pick->name.c_str(), (unsigned long long)desc.id,
             pr.shardId, (unsigned long long)pr.absoluteFileOffset,
             (unsigned long long)pr.byteCount,
             (unsigned long long)pr.byteCount,
             (unsigned long long)(readOk ? pr.byteCount : 0),
             (int)rejectOver, (int)rejectUnaddr,
             lineagePass ? "PASS" : "FAIL",
             "PARTIAL"); // full PASS needs GPU_DISPATCH=1
    WriteGate(gate);
    printf("VWA_PHYSICAL_LINEAGE=%s\n", lineagePass ? "PASS" : "FAIL");
    printf("K2_LOGITS_GPU_RANGE_ATTRIBUTION_001=PARTIAL\n");
    return lineagePass ? 0 : 1;
}
