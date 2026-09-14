// Batch10_PeerRowSplitCert.cpp
// Hardware cert for physical dual-GPU arithmetic and peer-group capability.
// It does NOT mint full-model E2E authority.
#include "Deep2DualGpuRowSplit.hpp"
#include "Deep2PeerDeviceGroup.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <vector>

int main() {
    using namespace Deep2;

    auto devs=VulkanCompute::EnumeratePhysicalDevices();
    std::vector<VulkanPhysicalInfo> compute;
    for(const auto& d:devs) if(d.compute) compute.push_back(d);

    std::printf("BATCH10_COMPUTE_DEVICE_COUNT=%zu\n",compute.size());
    if(compute.size()<2){
        std::puts("BATCH10_DUAL_GPU=HOLD_NEED_TWO_COMPUTE_DEVICES");
        return 0;
    }

    PeerDeviceGroupProbe peer=
        Deep2ProbePeerDeviceGroup(compute[0],compute[1]);
    std::printf(
        "BATCH10_PEER same_group=%u logical=%u copy=%u generic=%u "
        "heaps=%u vkCreateDevice=%d\n",
        peer.sameDeviceGroup?1u:0u,
        peer.logicalDeviceCreated?1u:0u,
        peer.copyPeer?1u:0u,
        peer.genericPeer?1u:0u,
        peer.peerHeapCount,
        (int)peer.createDeviceResult);

    VulkanCompute g0(compute[0].ordinal);
    VulkanCompute g1(compute[1].ordinal);
    if(!g0.initialize()||!g1.initialize()){
        std::puts("BATCH10_DUAL_GPU_INIT=FAIL");
        return 2;
    }
    if(!g0.computeReady()||!g1.computeReady()){
        std::puts("BATCH10_SHADER_PIPELINE=HOLD");
        return 3;
    }

    constexpr uint32_t rows=512;
    constexpr uint32_t cols=256;
    std::vector<float> w((size_t)rows*cols);
    std::vector<float> x(cols);
    std::vector<float> y(rows,0.0f);
    std::vector<float> ref(rows,0.0f);

    for(size_t i=0;i<w.size();++i)
        w[i]=((int)(i%31)-15)*0.00390625f;
    for(size_t i=0;i<x.size();++i)
        x[i]=((int)(i%17)-8)*0.03125f;

    for(uint32_t r=0;r<rows;++r){
        double acc=0.0;
        for(uint32_t c=0;c<cols;++c)
            acc+=(double)w[(size_t)r*cols+c]*(double)x[c];
        ref[r]=(float)acc;
    }

    WeightTensor wt{};
    wt.data=w.data();
    wt.type=0;
    wt.rows=rows;
    wt.cols=cols;
    wt.sizeBytes=w.size()*sizeof(float);
    wt.name="batch10.cert.f32";

    constexpr uint64_t epoch=0xB100001ull;
    RowSplitReceipt receipt{};
    if(!Deep2RunDualGpuRowSplit(
        g0,g1,wt,x.data(),y.data(),epoch,&receipt)){
        std::puts("BATCH10_ROW_SPLIT_EXEC=FAIL");
        return 4;
    }

    float maxErr=0.0f;
    for(size_t i=0;i<y.size();++i)
        maxErr=std::max(maxErr,std::fabs(y[i]-ref[i]));

    const bool parity=maxErr<1e-4f;
    std::printf(
        "BATCH10_ROW_SPLIT rows0=%u rows1=%u parity=%u max_err=%.9g "
        "calibrated_overlap_ns=%llu host_overlap_ns=%llu\n",
        receipt.rows0,receipt.rows1,parity?1u:0u,maxErr,
        (unsigned long long)receipt.calibratedOverlapNs,
        (unsigned long long)receipt.hostEnvelopeOverlapNs);

    if(!parity) return 5;

    std::printf("BATCH10_DUAL_ARITHMETIC_EXEC=PASS\n");
    std::printf("BATCH10_DUAL_ARITHMETIC_CALIBRATED_OVERLAP=%u\n",
        receipt.calibratedOverlapNs>0?1u:0u);
    std::printf("PEER_DIRECT_PRODUCT_AUTHORITY=0\n");
    std::printf("FULLY_RESIDENT_MULTI_GPU_AUTHORITY=0\n");
    std::printf("FULL_MODEL_E2E_PASS=0\n");
    return 0;
}
