// ============================================================================
// mla_upload_contract_cert.cpp
//   RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001 — runtime confirmation of the
//   primary failure site, without needing an MLA model.
//
// What this proves
//   vulkan_compute.cpp:3987 passes `qElems*sizeof(float)` to a parameter whose
//   contract is a FLOAT ELEMENT count. This harness measures, on a real Vulkan
//   device, whether that distinction actually decides the outcome:
//     UploadVector(buf, host, n)              -> expected true
//     UploadVector(buf, host, n*sizeof(float))-> expected false
//   and it measures which check refuses, by size delta.
//
// What it does NOT prove
//   That an MLA model fails end to end. That still requires a DeepSeek-2/3 GGUF,
//   which is not present on this machine. This certifies the mechanism; the
//   control flow above it remains CODE_PROVEN_RUNTIME_UNOBSERVED.
// ============================================================================
#include <cstdio>
#include <vector>

#include "deep2/vulkan_compute.h"

using Deep2::VulkanCompute;

namespace {

const size_t kElems = 1024;  // stands in for qElems = heads*keyLen

}  // namespace

int main() {
    const auto devices = VulkanCompute::EnumeratePhysicalDevices();
    std::printf("PHYSICAL_DEVICES=%zu\n", devices.size());
    for (const auto& d : devices) {
        std::printf("DEVICE name=%s ordinal=%u discrete=%d compute=%d localBytes=%llu\n",
                    d.name.c_str(), d.ordinal, d.discrete ? 1 : 0, d.compute ? 1 : 0,
                    (unsigned long long)d.deviceLocalBytes);
    }
    if (devices.empty()) {
        std::printf("VERDICT=FAIL reason=no_vulkan_physical_device\n");
        return 2;
    }

    VulkanCompute vc(0);
    if (!vc.initialize()) {
        std::printf("INIT_OK=0\nVERDICT=FAIL reason=initialize_failed\n");
        return 3;
    }
    std::printf("INIT_OK=1\n");

    if (!vc.EnsureScratch(0, kElems)) {
        std::printf("ENSURE_SCRATCH_OK=0\nVERDICT=FAIL reason=scratch_alloc_failed\n");
        return 4;
    }
    VulkanCompute::DeviceBuf& buf = vc.Scratch(0);
    std::printf("SCRATCH_ELEMENT_COUNT=%zu\n", kElems);
    std::printf("SCRATCH_SIZE_BYTES=%llu\n", (unsigned long long)buf.size);
    std::printf("SCRATCH_BYTES_IF_ELEMENT_COUNT_WERE_SCALED=%llu\n",
                (unsigned long long)(kElems * sizeof(float) * sizeof(float)));

    std::vector<float> host(kElems, 1.25f);

    // The contract case: count is an element count.
    const bool okElements = vc.UploadVector(buf, host.data(), kElems);
    std::printf("UPLOAD_WITH_ELEMENT_COUNT_OK=%d\n", okElements ? 1 : 0);

    // The :3987 case: bytes supplied where elements are contracted.
    const bool okBytes = vc.UploadVector(buf, host.data(), kElems * sizeof(float));
    std::printf("UPLOAD_WITH_BYTE_COUNT_OK=%d\n", okBytes ? 1 : 0);

    // The mirror image on the read side, which is the :4024 shape.
    std::vector<float> back(kElems, 0.0f);
    const bool okDownElements = vc.DownloadVector(buf, back.data(), kElems);
    const bool okDownBytes = vc.DownloadVector(buf, back.data(), kElems * sizeof(float));
    std::printf("DOWNLOAD_WITH_ELEMENT_COUNT_OK=%d\n", okDownElements ? 1 : 0);
    std::printf("DOWNLOAD_WITH_BYTE_COUNT_OK=%d\n", okDownBytes ? 1 : 0);

    float maxDiff = 0.0f;
    for (size_t i = 0; i < kElems; ++i) {
        float d = back[i] - host[i];
        if (d < 0) d = -d;
        if (d > maxDiff) maxDiff = d;
    }
    std::printf("ELEMENT_COUNT_ROUNDTRIP_MAXDIFF=%g\n", maxDiff);

    const bool pass = okElements && !okBytes && okDownElements && !okDownBytes;
    std::printf("UNIT_ERROR_IS_RUNTIME_DECIDED=%d\n", pass ? 1 : 0);
    std::printf("MLA_FORWARD_CHAIN_RUNTIME_OBSERVED=0\n");
    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
