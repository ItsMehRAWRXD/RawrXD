// ============================================================================
// Deep2Engine_GpuMoEMLA.cpp — Batch 10 dual-GPU row split + GPU MoE/MLA
// ============================================================================
#include "Deep2Engine.h"
#include "Deep2DualGpuRowSplit.hpp"
#include "Deep2GpuOverlapWitness.hpp"
#include "Deep2PeerDeviceGroup.hpp"
#include "vulkan_compute.h"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <future>
#include <limits>
#include <stdexcept>
#include <vector>

namespace Deep2 {
namespace {

bool finiteVec(const float* p,size_t n) noexcept {
    if(!p) return false;
    for(size_t i=0;i<n;++i) if(!std::isfinite(p[i])) return false;
    return true;
}

bool fullView(const WeightTensor& wt,GpuWeightView& v) noexcept {
    if(wt.rows==0 || wt.rows>std::numeric_limits<uint32_t>::max())
        return false;
    return Deep2BuildGpuWeightView(
        wt,0,static_cast<uint32_t>(wt.rows),v);
}

void applyMlaRope(float* qFull,float* kPe,
                  size_t heads,size_t nope,size_t rope,
                  size_t pos,float theta,float scaling)
{
    if(!qFull||!kPe||!heads||!rope||(rope&1u)||
       !(theta>1.0f)||!(scaling>0.0f))
        throw std::runtime_error("MLA RoPE: invalid geometry");

    const float position=static_cast<float>(pos)/scaling;
    for(size_t pair=0;pair<rope/2;++pair){
        const size_t d=pair*2;
        const float freq=std::pow(
            theta,-static_cast<float>(d)/static_cast<float>(rope));
        const float angle=position*freq;
        const float cs=std::cos(angle);
        const float sn=std::sin(angle);

        for(size_t h=0;h<heads;++h){
            float* qr=qFull+h*(nope+rope)+nope;
            const float a=qr[d],b=qr[d+1];
            qr[d]=a*cs-b*sn;
            qr[d+1]=a*sn+b*cs;
        }

        const float a=kPe[d],b=kPe[d+1];
        kPe[d]=a*cs-b*sn;
        kPe[d+1]=a*sn+b*cs;
    }
}

} // namespace

bool Deep2Engine::tryVulkanHostGEMV(
    const WeightTensor& wt,const float* input,float* output,size_t outDim,
    bool* usedDualGpu)
{
    if (usedDualGpu) *usedDualGpu = false;
    const bool compressedF32Path = static_cast<bool>(wt.compressedF32);
    const bool compressedBytesPath = !compressedF32Path &&
        static_cast<bool>(wt.compressedBytes);
    if(!vulkanInitialized_||vulkanDevices_.empty()||
       !input||!output||(!wt.data && !compressedF32Path && !compressedBytesPath)||wt.rows!=outDim||
       wt.rows==0||wt.cols==0||
       wt.rows>std::numeric_limits<uint32_t>::max()||
       wt.cols>std::numeric_limits<uint32_t>::max())
        return false;

    const uint64_t epoch=kvCache?kvCache->currentLength():0;

    // Compressed tensors use two independent Vulkan devices when available.
    // Each device receives only its own bounded row tiles and downloads into
    // a disjoint final output range; no full expanded matrix or host merge is
    // required.
    if ((compressedF32Path || compressedBytesPath) &&
        vulkanDevices_.size() >= 2 && wt.rows >= 2) {
        struct TileStats {
            uint64_t f16Ops = 0;
            uint64_t bf16Ops = 0;
            uint64_t bytes = 0;
        };
        auto* device0 = getVulkanComputeSlot(0);
        auto* device1 = getVulkanComputeSlot(1);
        size_t quantRowBytes = 0;
        bool quantGeometryValid = true;
        if (compressedBytesPath) {
            if (wt.type == 1 || wt.type == 30) {
                quantGeometryValid =
                    wt.cols <= std::numeric_limits<size_t>::max() /
                                   sizeof(uint16_t);
                if (quantGeometryValid)
                    quantRowBytes = wt.cols * sizeof(uint16_t);
            } else {
                const BlockGeometry geometry =
                    QuantKernelRegistry::Instance().GetGeometry(wt.type);
                if (!geometry.blockBytes || !geometry.blockElements ||
                    wt.cols > std::numeric_limits<size_t>::max() -
                                  (geometry.blockElements - 1u)) {
                    quantGeometryValid = false;
                } else {
                    const size_t blocks =
                        (wt.cols + geometry.blockElements - 1u) /
                        geometry.blockElements;
                    quantGeometryValid =
                        blocks <= std::numeric_limits<size_t>::max() /
                                      geometry.blockBytes;
                    if (quantGeometryValid)
                        quantRowBytes = blocks * geometry.blockBytes;
                }
            }
        }

        auto runCompressedSlice = [&](VulkanCompute* device,
                                      size_t sliceBegin, size_t sliceRows,
                                      TileStats& stats) -> bool {
            if (!device || !sliceRows ||
                sliceRows > std::numeric_limits<uint32_t>::max() ||
                !device->EnsureScratch(30, wt.cols) ||
                !device->EnsureScratch(31, sliceRows))
                return false;
            auto& inputBuffer = device->Scratch(30);
            auto& outputBuffer = device->Scratch(31);
            if (!device->UploadVector(inputBuffer, input, wt.cols))
                return false;
            device->SetWorkEpoch(epoch);
            constexpr size_t kMaxTileBytes = 256u * 1024u;
            std::vector<uint8_t> packedTile;
            std::vector<uint8_t> decodeScratch;
            if (compressedF32Path) {
                if (wt.cols > std::numeric_limits<size_t>::max() /
                                  sizeof(float))
                    return false;
                const size_t rowBytes = wt.cols * sizeof(float);
                const size_t rowsPerTile =
                    std::max<size_t>(1, kMaxTileBytes / rowBytes);
                size_t rowBase = sliceBegin;
                const size_t sliceEnd = sliceBegin + sliceRows;
                while (rowBase < sliceEnd) {
                    const size_t maxRows =
                        std::min(sliceEnd - rowBase, rowsPerTile);
                    uint32_t actualRows = 0;
                    int tileType = -1;
                    if (maxRows > std::numeric_limits<uint32_t>::max() ||
                        !wt.BuildCompressedF32GpuTile(
                            static_cast<uint32_t>(rowBase),
                            static_cast<uint32_t>(maxRows), actualRows,
                            packedTile, tileType) || !actualRows)
                        return false;
                    uint64_t key = 1469598103934665603ull;
                    for (unsigned char ch : wt.name) {
                        key ^= ch;
                        key *= 1099511628211ull;
                    }
                    key ^= wt.fileOffset +
                        (static_cast<uint64_t>(wt.shardId) << 32);
                    key *= 1099511628211ull;
                    key ^= static_cast<uint64_t>(
                        reinterpret_cast<uintptr_t>(wt.compressedF32.get()));
                    key *= 1099511628211ull;
                    key ^= (static_cast<uint64_t>(rowBase) << 16) ^
                           (static_cast<uint64_t>(tileType) << 56);
                    if (!key) key = 1;
                    const uint32_t outputBase =
                        static_cast<uint32_t>(rowBase - sliceBegin);
                    if (!device->DispatchGemvQuantRows(
                            tileType, packedTile.data(), packedTile.size(),
                            inputBuffer, outputBuffer, static_cast<uint32_t>(actualRows),
                            static_cast<uint32_t>(wt.cols), outputBase, key))
                        return false;
                    if (tileType == 1) ++stats.f16Ops;
                    else if (tileType == 30) ++stats.bf16Ops;
                    stats.bytes += packedTile.size();
                    rowBase += actualRows;
                }
            } else {
                if (!quantGeometryValid || !quantRowBytes ||
                    wt.rows > std::numeric_limits<size_t>::max() /
                                  quantRowBytes ||
                    wt.rows * quantRowBytes != wt.sizeBytes ||
                    wt.compressedBytes->size() != wt.sizeBytes)
                    return false;
                const size_t rowsPerTile =
                    std::max<size_t>(1, kMaxTileBytes / quantRowBytes);
                size_t rowBase = sliceBegin;
                const size_t sliceEnd = sliceBegin + sliceRows;
                while (rowBase < sliceEnd) {
                    const size_t tileRows =
                        std::min(sliceEnd - rowBase, rowsPerTile);
                    if (tileRows > std::numeric_limits<uint32_t>::max() ||
                        tileRows > std::numeric_limits<size_t>::max() /
                                       quantRowBytes)
                        return false;
                    const size_t tileBytes = tileRows * quantRowBytes;
                    packedTile.resize(tileBytes);
                    try {
                        wt.compressedBytes->ReadRange(
                            rowBase * quantRowBytes, tileBytes,
                            packedTile.data(), decodeScratch);
                    } catch (...) {
                        return false;
                    }
                    uint64_t key = 1469598103934665603ull;
                    for (unsigned char ch : wt.name) {
                        key ^= ch;
                        key *= 1099511628211ull;
                    }
                    key ^= wt.fileOffset +
                        (static_cast<uint64_t>(wt.shardId) << 32);
                    key *= 1099511628211ull;
                    key ^= static_cast<uint64_t>(
                        reinterpret_cast<uintptr_t>(wt.compressedBytes.get()));
                    key *= 1099511628211ull;
                    key ^= (static_cast<uint64_t>(rowBase) << 16) ^
                           (static_cast<uint64_t>(wt.type) << 48);
                    if (!key) key = 1;
                    const uint32_t outputBase =
                        static_cast<uint32_t>(rowBase - sliceBegin);
                    if (!device->DispatchGemvQuantRows(
                            wt.type, packedTile.data(), tileBytes,
                            inputBuffer, outputBuffer, static_cast<uint32_t>(tileRows),
                            static_cast<uint32_t>(wt.cols), outputBase, key))
                        return false;
                    if (wt.type == 1) ++stats.f16Ops;
                    else if (wt.type == 30) ++stats.bf16Ops;
                    stats.bytes += tileBytes;
                    rowBase += tileRows;
                }
            }
            return device->DownloadVector(
                outputBuffer, output + sliceBegin, sliceRows);
        };

        if (device0 && device1 && quantGeometryValid) {
            const size_t rows0 = wt.rows / 2;
            const size_t rows1 = wt.rows - rows0;
            TileStats stats0{}, stats1{};
            bool ok0 = false, ok1 = false;
            try {
                auto task0 = std::async(std::launch::async, [&] {
                    return runCompressedSlice(device0, 0, rows0, stats0);
                });
                auto task1 = std::async(std::launch::async, [&] {
                    return runCompressedSlice(device1, rows0, rows1, stats1);
                });
                ok0 = task0.get();
                ok1 = task1.get();
            } catch (...) {
                // Failed launch/submit on either device falls through to the
                // existing single-device attempt; no partial output is trusted.
                ok0 = false;
                ok1 = false;
            }
            if (ok0 && ok1 && finiteVec(output, outDim)) {
                if (usedDualGpu) *usedDualGpu = true;
                ++gpuFwd_.dualRowSplitOps;
                ++gpuFwd_.dualRowSlot[0];
                ++gpuFwd_.dualRowSlot[1];
                gpuFwd_.hostMaterializations += 2;
                ++gpuFwd_.matDualRowSingle;
                gpuFwd_.compressedF16GemvOps += stats0.f16Ops + stats1.f16Ops;
                gpuFwd_.compressedBF16GemvOps += stats0.bf16Ops + stats1.bf16Ops;
                gpuFwd_.compressedWeightBytesSubmitted +=
                    stats0.bytes + stats1.bytes;
                return true;
            }
        }
    }

    // First preference: true simultaneous independent row partitions.
    if(wt.data && !compressedF32Path && !compressedBytesPath && vulkanDevices_.size()>=2 && wt.rows>=2){
        RowSplitReceipt r{};
        if(Deep2RunDualGpuRowSplit(
                *vulkanDevices_[0],*vulkanDevices_[1],
                wt,input,output,epoch,&r)){
            if (usedDualGpu) *usedDualGpu = true;
            ++gpuFwd_.dualRowSplitOps;
            ++gpuFwd_.dualRowSlot[0];
            ++gpuFwd_.dualRowSlot[1];
            ++gpuFwd_.hostMergeOps;
            ++gpuFwd_.hostMaterializations; // explicit row-slice merge
            ++gpuFwd_.matDualRowSingle;
            gpuFwd_.dualArithmeticOverlapNs=
                std::max(gpuFwd_.dualArithmeticOverlapNs,
                         r.calibratedOverlapNs);
            return finiteVec(output,outDim);
        }
    }

    // One valid device is still a real GPU path; no fake two-stick claim.
    auto* g=getVulkanComputeSlot(0);
    if(!g){
        std::fprintf(stderr,"GEMV_SINGLE getVulkanComputeSlot(0)=null name=%s\n",wt.name.empty()?"null":wt.name.c_str()); std::fflush(stderr);
        return false;
    }
    const char* wtn = wt.name.empty() ? "null" : wt.name.c_str();
    GpuWeightView view{};
    if (!compressedF32Path && !compressedBytesPath && !fullView(wt,view)) {
        std::fprintf(stderr,"GEMV_SINGLE fullView failed name=%s\\n",wtn); std::fflush(stderr);
        return false;
    }

    g->SetWorkEpoch(epoch);
    if(!g->EnsureScratch(30,wt.cols)){
        std::fprintf(stderr,"GEMV_SINGLE EnsureScratch(30,cols) failed name=%s cols=%zu\n",wtn,wt.cols); std::fflush(stderr);
        return false;
    }
    if(!g->EnsureScratch(31,wt.rows)){
        std::fprintf(stderr,"GEMV_SINGLE EnsureScratch(31,rows) failed name=%s rows=%zu\n",wtn,wt.rows); std::fflush(stderr);
        return false;
    }
    auto& x=g->Scratch(30);
    auto& y=g->Scratch(31);
    if(!g->UploadVector(x,input,wt.cols)){
        std::fprintf(stderr,"GEMV_SINGLE UploadVector failed name=%s\n",wtn); std::fflush(stderr);
        return false;
    }
    if (compressedF32Path) {
        // Keep conversion scratch bounded independently of model size. Each
        // tile is uploaded in its native F16/BF16 form when safe, or exact F32
        // when the configured error budget cannot be met.
        constexpr size_t kMaxCompressedGpuTileBytes = 256u * 1024u;
        const size_t rowBytes = wt.cols * sizeof(float);
        if (!rowBytes) return false;
        const size_t rowsPerTile = std::max<size_t>(
            1, kMaxCompressedGpuTileBytes / rowBytes);
        std::vector<uint8_t> packedTile;
        for (size_t rowBase = 0; rowBase < wt.rows;) {
            const size_t tileRows = std::min(wt.rows - rowBase, rowsPerTile);
            if (tileRows > std::numeric_limits<uint32_t>::max()) return false;
            int tileType = -1;
            uint32_t actualTileRows = 0;
            if (!wt.BuildCompressedF32GpuTile(
                    static_cast<uint32_t>(rowBase),
                    static_cast<uint32_t>(tileRows), actualTileRows,
                    packedTile, tileType) || !actualTileRows)
                return false;
            uint64_t cacheKey = 1469598103934665603ull;
            for (unsigned char ch : wt.name) {
                cacheKey ^= ch;
                cacheKey *= 1099511628211ull;
            }
            cacheKey ^= wt.fileOffset + (static_cast<uint64_t>(wt.shardId) << 32);
            cacheKey *= 1099511628211ull;
            cacheKey ^= static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(wt.compressedF32.get()));
            cacheKey *= 1099511628211ull;
            cacheKey ^= (static_cast<uint64_t>(rowBase) << 16) ^
                        (static_cast<uint64_t>(tileType) << 56);
            if (!cacheKey) cacheKey = 1;
            if (!g->DispatchGemvQuantRows(
                    tileType, packedTile.data(), packedTile.size(),
                    x, y, actualTileRows,
                    static_cast<uint32_t>(wt.cols),
                    static_cast<uint32_t>(rowBase), cacheKey)) {
                std::fprintf(stderr,
                    "GEMV_COMPRESSED_TILE dispatch failed name=%s type=%d row=%zu count=%zu bytes=%zu\\n",
                    wtn,tileType,rowBase,actualTileRows,packedTile.size());
                return false;
            }
            if (tileType == 1) ++gpuFwd_.compressedF16GemvOps;
            else if (tileType == 30) ++gpuFwd_.compressedBF16GemvOps;
            gpuFwd_.compressedWeightBytesSubmitted += packedTile.size();
            rowBase += actualTileRows;
        }
    } else if (compressedBytesPath) {
        // Losslessly compressed GGUF quantized bytes stay packed in host
        // residency. Expand only bounded row tiles, then let the existing
        // Vulkan shader decode the original GGML block representation.
        size_t rowBytes = 0;
        if (wt.type == 1 || wt.type == 30) {
            if (wt.cols > std::numeric_limits<size_t>::max() / sizeof(uint16_t))
                return false;
            rowBytes = wt.cols * sizeof(uint16_t);
        } else {
            const BlockGeometry geometry =
                QuantKernelRegistry::Instance().GetGeometry(wt.type);
            if (!geometry.blockBytes || !geometry.blockElements ||
                wt.cols > std::numeric_limits<size_t>::max() -
                              (geometry.blockElements - 1u))
                return false;
            const size_t blocks =
                (wt.cols + geometry.blockElements - 1u) / geometry.blockElements;
            if (blocks > std::numeric_limits<size_t>::max() / geometry.blockBytes)
                return false;
            rowBytes = blocks * geometry.blockBytes;
        }
        if (!rowBytes || wt.rows > std::numeric_limits<size_t>::max() / rowBytes ||
            wt.rows * rowBytes != wt.sizeBytes ||
            wt.compressedBytes->size() != wt.sizeBytes)
            return false;

        constexpr size_t kMaxCompressedGpuTileBytes = 256u * 1024u;
        const size_t rowsPerTile = std::max<size_t>(
            1, kMaxCompressedGpuTileBytes / rowBytes);
        std::vector<uint8_t> packedTile;
        std::vector<uint8_t> decodeScratch;
        for (size_t rowBase = 0; rowBase < wt.rows;) {
            const size_t tileRows = std::min(wt.rows - rowBase, rowsPerTile);
            if (tileRows > std::numeric_limits<uint32_t>::max() ||
                tileRows > std::numeric_limits<size_t>::max() / rowBytes)
                return false;
            const size_t tileBytes = tileRows * rowBytes;
            packedTile.resize(tileBytes);
            try {
                wt.compressedBytes->ReadRange(
                    rowBase * rowBytes, tileBytes, packedTile.data(), decodeScratch);
            } catch (...) {
                return false;
            }

            uint64_t cacheKey = 1469598103934665603ull;
            for (unsigned char ch : wt.name) {
                cacheKey ^= ch;
                cacheKey *= 1099511628211ull;
            }
            cacheKey ^= wt.fileOffset +
                (static_cast<uint64_t>(wt.shardId) << 32);
            cacheKey *= 1099511628211ull;
            cacheKey ^= static_cast<uint64_t>(
                reinterpret_cast<uintptr_t>(wt.compressedBytes.get()));
            cacheKey *= 1099511628211ull;
            cacheKey ^= (static_cast<uint64_t>(rowBase) << 16) ^
                        (static_cast<uint64_t>(wt.type) << 48);
            if (!cacheKey) cacheKey = 1;
            if (!g->DispatchGemvQuantRows(
                    wt.type, packedTile.data(), tileBytes,
                    x, y, static_cast<uint32_t>(tileRows),
                    static_cast<uint32_t>(wt.cols),
                    static_cast<uint32_t>(rowBase), cacheKey)) {
                std::fprintf(stderr,
                    "GEMV_COMPRESSED_QUANT_TILE dispatch failed name=%s type=%d row=%zu count=%zu bytes=%zu\\n",
                    wtn,wt.type,rowBase,tileRows,tileBytes);
                return false;
            }
            gpuFwd_.compressedWeightBytesSubmitted += tileBytes;
            rowBase += tileRows;
        }
    } else if (!g->DispatchWeight(view,x,y)) {
        std::fprintf(stderr,"GEMV_SINGLE DispatchWeight failed name=%s type=%d rows=%u cols=%u bytes=%zu\\n",wtn,view.type,view.rows,view.cols,view.bytes); std::fflush(stderr);
        return false;
    }
    if(!g->DownloadVector(y,output,wt.rows)){
        std::fprintf(stderr,"GEMV_SINGLE DownloadVector failed name=%s\n",wtn); std::fflush(stderr);
        return false;
    }

    ++gpuFwd_.hostMaterializations;
    ++gpuFwd_.matGemvSingleRoundTrip;
    bool fin=finiteVec(output,outDim);
    if(!fin) std::fprintf(stderr,"GEMV_SINGLE finiteVec failed name=%s\n",wtn), std::fflush(stderr);
    return fin;
}

bool Deep2Engine::tryVulkanHostGEMVBatch4(
    const WeightTensor& wt,const float* inputBatch,size_t count,
    float* outputBatch,size_t outDim)
{
    if(!vulkanInitialized_||vulkanDevices_.size()<2||
       !inputBatch||!outputBatch||count==0||count>4||
       wt.compressedF32||wt.compressedBytes||
       wt.rows!=outDim||wt.type!=(int)GGMLType::GGML_TYPE_Q4_K)
        return false;
    const uint64_t epoch=kvCache?kvCache->currentLength():0;
    RowSplitReceipt r{};
    if(!Deep2RunDualGpuRowSplitBatch4(
            *vulkanDevices_[0],*vulkanDevices_[1],
            wt,inputBatch,outputBatch,(uint32_t)count,epoch,&r))
        return false;
    ++gpuFwd_.dualRowSplitOps;
    ++gpuFwd_.dualRowSlot[0];
    ++gpuFwd_.dualRowSlot[1];
    ++gpuFwd_.hostMergeOps;
    gpuFwd_.dualArithmeticOverlapNs=
        std::max(gpuFwd_.dualArithmeticOverlapNs,r.calibratedOverlapNs);
    return true;
}


bool Deep2Engine::tryVulkanHostGEMVGroup(
    const WeightTensor* const* weights,float* const* outputs,size_t count,
    const float* input,size_t inputCount)
{
    if(!vulkanInitialized_||vulkanDevices_.size()<2||
       !weights||!outputs||!input||count<2||count>3||
       inputCount==0||inputCount>UINT32_MAX)
        return false;

    // Grouped dual-row upload still consumes raw GGUF pointers. If any member
    // has private compressed backing, force the caller through LinearW so each
    // matrix uses its compressed bounded-row Vulkan uploader instead.
    for (size_t i = 0; i < count; ++i) {
        if (!weights[i] || !weights[i]->data ||
            weights[i]->compressedF32 || weights[i]->compressedBytes)
            return false;
    }

    const uint64_t epoch=kvCache?kvCache->currentLength():0;
    RowSplitReceipt r{};
    if(!Deep2RunDualGpuRowSplitGroup(
            *vulkanDevices_[0],*vulkanDevices_[1],
            weights,outputs,count,input,(uint32_t)inputCount,epoch,&r))
        return false;

    ++gpuFwd_.dualRowSplitOps;
    ++gpuFwd_.dualRowSlot[0];
    ++gpuFwd_.dualRowSlot[1];
    ++gpuFwd_.hostMergeOps;
    ++gpuFwd_.hostMaterializations;
    ++gpuFwd_.matDualRowGroup; // grouped dual-row host round-trip
    gpuFwd_.dualArithmeticOverlapNs=
        std::max(gpuFwd_.dualArithmeticOverlapNs,r.calibratedOverlapNs);
    return true;
}

bool Deep2Engine::computeMoEFFNGpu(

    size_t layer,const float* input,float* output)
{
    if(!vulkanInitialized_||vulkanDevices_.empty()||
       !input||!output||layer>=modelWeights.layers.size())
        return false;

    const LayerWeights& lw=modelWeights.layers[layer];
    const size_t H=modelWeights.hiddenDim;
    const size_t E=modelWeights.numExperts;
    const size_t K=modelWeights.numExpertsPerToken;
    const size_t I=modelWeights.moeIntermediateDim;
    if(!H||!E||!K||K>E||!I||
       H>UINT32_MAX||I>UINT32_MAX||
       !lw.moeRouter.data||
       lw.moeGate.size()!=E||
       lw.moeUp.size()!=E||
       lw.moeDown.size()!=E||
       layer>=moeRouters_.size()||!moeRouters_[layer])
        return false;

    // RunExpertFFN currently binds raw mapped gate/up/down views directly.
    // Do not silently bypass private compressed residency in this fused path;
    // let the caller use the per-tensor LinearW route until compressed expert
    // descriptors are wired into the fused expert kernel.
    for (size_t ex = 0; ex < E; ++ex) {
        if (lw.moeGate[ex].compressedF32 || lw.moeGate[ex].compressedBytes ||
            lw.moeUp[ex].compressedF32 || lw.moeUp[ex].compressedBytes ||
            lw.moeDown[ex].compressedF32 || lw.moeDown[ex].compressedBytes)
            return false;
    }
    if (lw.moeSharedGate.compressedF32 || lw.moeSharedGate.compressedBytes ||
        lw.moeSharedUp.compressedF32 || lw.moeSharedUp.compressedBytes ||
        lw.moeSharedDown.compressedF32 || lw.moeSharedDown.compressedBytes)
        return false;

    std::vector<float> logits(E,0.0f);
    if(!tryVulkanHostGEMV(lw.moeRouter,input,logits.data(),E))
        return false;

    TokenRoute route=
        moeRouters_[layer]->RouteFromLogits(logits.data(),E);
    if(!route.valid||route.expertIds.size()!=K||
       route.expertWeights.size()!=K)
        return false;

    std::fill(output,output+H,0.0f);
    const size_t gpuN=vulkanDevices_.size();
    const uint64_t epoch=kvCache?kvCache->currentLength():0;
    std::vector<std::vector<float>> expertOut(
        K,std::vector<float>(H,0.0f));

    // Run at most one expert per device at a time. Experts in each round are
    // mathematically independent and therefore genuinely concurrent.
    for(size_t base=0;base<K;base+=gpuN){
        const size_t n=std::min(gpuN,K-base);
        std::vector<std::future<bool>> futures;
        futures.reserve(n);

        for(size_t j=0;j<n;++j){
            const size_t routeIndex=base+j;
            const int expertId=route.expertIds[routeIndex];
            if(expertId<0||(size_t)expertId>=E) return false;
            const size_t ex=(size_t)expertId;

            GpuWeightView gate{},up{},down{};
            if(!fullView(lw.moeGate[ex],gate)||
               !fullView(lw.moeUp[ex],up)||
               !fullView(lw.moeDown[ex],down))
                return false;

            VulkanCompute* g=vulkanDevices_[j].get();
            futures.emplace_back(std::async(
                std::launch::async,
                [g,gate,up,down,input,&expertOut,routeIndex,H,I,epoch]{
                    return g->RunExpertFFN(
                        gate,up,down,input,
                        expertOut[routeIndex].data(),
                        (uint32_t)H,(uint32_t)I,epoch);
                }));
        }

        for(auto& f:futures) if(!f.get()) return false;
    }

    for(size_t j=0;j<K;++j){
        const float w=route.expertWeights[j];
        if(!std::isfinite(w)) return false;
        for(size_t i=0;i<H;++i)
            output[i]+=w*expertOut[j][i];
    }

    gpuFwd_.gpuExpertDispatches+=K;
    gpuFwd_.hostMaterializations+=K; // one returned vector per routed expert
    gpuFwd_.matOther+=K; // expert host round-trips: MoE residue class

    // Shared expert is independent of top-k route and runs on GPU0.
    const bool anyShared=
        lw.moeSharedGate.data||lw.moeSharedUp.data||lw.moeSharedDown.data;
    if(anyShared){
        if(!lw.moeSharedGate.data||!lw.moeSharedUp.data||
           !lw.moeSharedDown.data)
            return false;
        const size_t SI=lw.moeSharedGate.rows;
        if(!SI||SI>UINT32_MAX) return false;

        GpuWeightView gate{},up{},down{};
        if(!fullView(lw.moeSharedGate,gate)||
           !fullView(lw.moeSharedUp,up)||
           !fullView(lw.moeSharedDown,down))
            return false;

        std::vector<float> shared(H,0.0f);
        if(!vulkanDevices_[0]->RunExpertFFN(
            gate,up,down,input,shared.data(),
            (uint32_t)H,(uint32_t)SI,epoch))
            return false;
        for(size_t i=0;i<H;++i) output[i]+=shared[i];
        ++gpuFwd_.gpuExpertDispatches;
        ++gpuFwd_.hostMaterializations;
        ++gpuFwd_.matOther; // shared expert host round-trip: MoE residue class
    }

    if(vulkanDevices_.size()>=2){
        auto w=Deep2Gpu_MeasureArithmeticOverlap(
            *vulkanDevices_[0],*vulkanDevices_[1],epoch);
        gpuFwd_.dualArithmeticOverlapNs=
            std::max(gpuFwd_.dualArithmeticOverlapNs,
                     w.calibratedOverlapNs);
    }

    return finiteVec(output,H);
}

bool Deep2Engine::computeMLAAttentionGpu(
    size_t layer,const float* input,float* output,size_t seqLen)
{
    if(!vulkanInitialized_||vulkanDevices_.empty()||
       !input||!output||layer>=modelWeights.layers.size()||
       !kvCache)
        return false;

    const LayerWeights& lw=modelWeights.layers[layer];
    if(!(lw.useMLA||modelWeights.useMLA)) return false;

    const size_t H=modelWeights.hiddenDim;
    const size_t heads=modelWeights.numHeads;
    const size_t qRank=modelWeights.qLoraRank;
    const size_t kvRank=modelWeights.kvLoraRank;
    const size_t nope=modelWeights.qkNopeHeadDim;
    const size_t rope=modelWeights.qkRopeHeadDim;
    const size_t valueLen=modelWeights.vHeadDim;
    const size_t keyLen=nope+rope;

    if(!H||!heads||!qRank||!kvRank||!nope||!rope||!valueLen||
       (rope&1u)||
       H>UINT32_MAX||heads>UINT32_MAX||keyLen>UINT32_MAX||
       valueLen>UINT32_MAX||
       !lw.attnQ_a.data||!lw.attnQ_a_norm.data||!lw.attnQ_b.data||
       !lw.attnKV_a_mqa.data||!lw.attnKV_a_norm.data||
       !lw.attnK_b.data||!lw.attnV_b.data||!lw.attnO.data)
        return false;

    if(lw.attnQ_a.rows!=qRank||lw.attnQ_a.cols!=H||
       lw.attnQ_b.rows!=heads*keyLen||lw.attnQ_b.cols!=qRank||
       lw.attnKV_a_mqa.rows!=kvRank+rope||lw.attnKV_a_mqa.cols!=H||
       lw.attnK_b.rows!=heads*nope||lw.attnK_b.cols!=kvRank||
       lw.attnV_b.rows!=heads*valueLen||lw.attnV_b.cols!=kvRank||
       lw.attnO.rows!=H||lw.attnO.cols!=heads*valueLen)
        return false;

    const size_t pos=kvCache->currentLength();
    if(seqLen!=pos+1||pos>=config.maxSeqLen) return false;

    std::vector<float> qa(qRank,0.0f);
    std::vector<float> qaNorm(qRank,0.0f);
    std::vector<float> qFull(heads*keyLen,0.0f);
    std::vector<float> kva(kvRank+rope,0.0f);
    std::vector<float> cNorm(kvRank,0.0f);
    std::vector<float> kNope(heads*nope,0.0f);
    std::vector<float> values(heads*valueLen,0.0f);

    if(!tryVulkanHostGEMV(lw.attnQ_a,input,qa.data(),qRank))
        return false;
    RMSNormW(lw.attnQ_a_norm,qa.data(),qaNorm.data(),
             qRank,modelWeights.normEps);
    if(!tryVulkanHostGEMV(lw.attnQ_b,qaNorm.data(),
                          qFull.data(),qFull.size()))
        return false;

    if(!tryVulkanHostGEMV(lw.attnKV_a_mqa,input,kva.data(),kva.size()))
        return false;
    RMSNormW(lw.attnKV_a_norm,kva.data(),cNorm.data(),
             kvRank,modelWeights.normEps);

    if(!tryVulkanHostGEMV(lw.attnK_b,cNorm.data(),
                          kNope.data(),kNope.size())||
       !tryVulkanHostGEMV(lw.attnV_b,cNorm.data(),
                          values.data(),values.size()))
        return false;

    std::vector<float> kPe(rope,0.0f);
    std::memcpy(kPe.data(),kva.data()+kvRank,rope*sizeof(float));

    const float theta=modelWeights.ropeTheta>1.0f
        ?modelWeights.ropeTheta:config.ropeTheta;
    const float scaling=modelWeights.ropeScaling>0.0f
        ?modelWeights.ropeScaling:config.ropeScaling;
    applyMlaRope(
        qFull.data(),kPe.data(),heads,nope,rope,pos,theta,scaling);

    std::vector<float> kFull(heads*keyLen,0.0f);
    for(size_t h=0;h<heads;++h){
        float* dst=kFull.data()+h*keyLen;
        std::memcpy(dst,kNope.data()+h*nope,nope*sizeof(float));
        std::memcpy(dst+nope,kPe.data(),rope*sizeof(float));
    }

    std::vector<float> attn(heads*valueLen,0.0f);
    const float scale=1.0f/std::sqrt((float)keyLen);
    const uint64_t epoch=pos;
    auto* g0=getVulkanComputeSlot(0);
    if(!g0||!g0->RunMLAAttentionHost(
        qFull.data(),kFull.data(),values.data(),attn.data(),
        (uint32_t)heads,(uint32_t)keyLen,(uint32_t)valueLen,
        (uint32_t)layer,(uint32_t)pos,
        (uint32_t)modelWeights.numLayers,
        (uint32_t)config.maxSeqLen,scale,epoch))
        return false;

    if(!tryVulkanHostGEMV(lw.attnO,attn.data(),output,H))
        return false;

    ++gpuFwd_.mlaGpuAttentionOps;
    // MLA projections are currently host-staged between device GEMVs. Keep
    // authority fail-closed until a fully resident absorbed-matrix path lands.
    ++gpuFwd_.hostMergeOps;
    return finiteVec(output,H);
}

bool Deep2Engine::forwardTokenGpuHybrid(float* hidden,size_t seqLen)
{
    if(!hidden||!seqLen||!vulkanInitialized_||vulkanDevices_.empty()||
       modelWeights.layers.size()<modelWeights.numLayers)
        return false;

    try{
        for(size_t l=0;l<modelWeights.numLayers;++l){
            forwardLayer(l,hidden,layerTemp,seqLen);
            std::memcpy(hidden,layerTemp,config.hiddenDim*sizeof(float));
            ++gpuFwd_.hostForwardLayerCalls; // explicit host orchestration
        }
    }catch(const std::exception& ex){
        std::fprintf(stderr,"BATCH10_GPU_HYBRID_FAIL layer_math=%s\n",ex.what());
        return false;
    }

    gpuFwdCommitted_=false; // heavy GPU compute != fully resident authority
    return finiteVec(hidden,config.hiddenDim);
}

PeerDeviceGroupProbe Deep2Engine::probeVulkanPeerGroup() const {
    if(vulkanDevices_.size()<2||!vulkanDevices_[0]||!vulkanDevices_[1])
        return {};
    return Deep2ProbePeerDeviceGroup(
        vulkanDevices_[0]->physicalInfo(),
        vulkanDevices_[1]->physicalInfo());
}

} // namespace Deep2
