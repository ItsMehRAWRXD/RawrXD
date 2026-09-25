#include "Deep2ExpertCacheBridge.h"
#include "PackedExpertSlicer.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unordered_map>
#include <vector>

using namespace rawrxd::deep2;

struct FakeGpu { std::unordered_map<void*, size_t> allocations; uint64_t tick = 1; };
static void* allocDevice(void* u, size_t bytes, uint32_t) { auto* g=(FakeGpu*)u; void* p=std::malloc(bytes); if(p) g->allocations[p]=bytes; return p; }
static void freeDevice(void* u, void* p, uint32_t) { auto* g=(FakeGpu*)u; g->allocations.erase(p); std::free(p); }
static bool upload(void* u, void* dst, const void* src, size_t bytes, uint32_t) { auto* g=(FakeGpu*)u; auto it=g->allocations.find(dst); if(it==g->allocations.end()||it->second<bytes) return false; std::memcpy(dst,src,bytes); return true; }
static uint64_t nowMicros(void* u) { return ++((FakeGpu*)u)->tick; }

int main() {
    // Q4_K: 256 logical elements/block, 144 bytes/block.
    // Tensor = [512 columns, 2 rows/expert, 4 experts].
    // row=288 bytes, expert=576 bytes, total=2304 bytes.
    std::vector<uint8_t> packed(2304);
    for (size_t i=0;i<packed.size();++i) packed[i]=static_cast<uint8_t>(i & 0xff);

    PackedTensorDescriptor d{};
    d.name="blk.9.ffn_gate_exps.weight";
    d.data=packed.data(); d.bytes=packed.size(); d.fileOffset=4096;
    d.type=GgmlStorageType::Q4_K; d.dims={512,2,4}; d.expertAxis=2; d.layer=9;

    std::vector<ExpertTensorSlice> slices;
    PackedSliceReceipt sr{};
    const bool sliceOk = PackedExpertSlicer::slice(d,slices,&sr) && slices.size()==4 &&
                         sr.rowBytes==288 && sr.expertStrideBytes==576 && sr.coveredBytes==2304 &&
                         slices[2].tensorByteOffset==1152 && slices[2].bytes==576 &&
                         slices[2].fileOffset==4096+1152;

    // Unknown storage type is still legal when Deep2 provides byte strides.
    std::vector<uint8_t> explicitPacked(1200,0x5a);
    PackedTensorDescriptor e{};
    e.name="blk.10.ffn_down_exps.weight"; e.data=explicitPacked.data(); e.bytes=explicitPacked.size(); e.fileOffset=9000;
    e.type=GgmlStorageType::Unknown; e.dims={100,3,4}; e.byteStrides={1,100,300}; e.expertAxis=2; e.layer=10;
    PackedSliceReceipt er{};
    std::vector<ExpertTensorSlice> explicitSlices;
    const bool explicitOk = PackedExpertSlicer::slice(e, explicitSlices, &er) && er.usedExplicitStrides &&
                            explicitSlices.size()==4 && explicitSlices[3].tensorByteOffset==900 && explicitSlices[3].bytes==300;

    PackedTensorDescriptor bad=d; bad.dims={510,2,4}; bad.bytes=packed.size();
    PackedSliceReceipt br{}; std::vector<ExpertTensorSlice> badOut;
    const bool rejectMisaligned = !PackedExpertSlicer::slice(bad,badOut,&br) && br.failure && std::strcmp(br.failure,"QUANT_BLOCK_MISALIGN")==0;

    PackedTensorDescriptor oob=d; oob.bytes=2000;
    PackedSliceReceipt obr{}; std::vector<ExpertTensorSlice> oobOut;
    const bool rejectOob = !PackedExpertSlicer::slice(oob,oobOut,&obr) && obr.failure && std::strcmp(obr.failure,"OUT_OF_BOUNDS")==0;

    ExpertTensorCatalog catalog;
    PackedSliceReceipt cr{};
    const bool catalogOk = catalog.addPackedTensor(d,&cr) && catalog.stats().expertsDiscovered==4 && catalog.stats().packedSlicesAdded==4;

    // Add a second packed projection so each expert owns two tensor spans.
    PackedTensorDescriptor d2=d; d2.name="blk.9.ffn_down_exps.weight"; d2.fileOffset=8192;
    const bool catalog2Ok = catalog.addPackedTensor(d2,nullptr) && catalog.find({9,2}) && catalog.find({9,2})->tensors.size()==2;

    FakeGpu gpu;
    ExpertTransport tx{}; tx.user=&gpu; tx.allocDevice=allocDevice; tx.freeDevice=freeDevice; tx.upload=upload; tx.nowMicros=nowMicros;
    ExpertCacheConfig cfg{}; cfg.budgetBytes=2304; cfg.deviceOrdinal=0; cfg.prefetchDepth=1;

    bool bridgeOk=false, offsetsOk=false, strictOk=false;
    BridgeReceipt rr{};
    {
        Deep2ExpertCacheBridge bridge(cfg,tx,true);
        bridgeOk=bridge.importCatalog(catalog);
        auto bind=bridge.acquire({9,2},44);
        offsetsOk=bind && bind.totalBytes==1152 && bind.tensorOffsets.size()==2 && bind.tensorOffsets[0]==0 && bind.tensorOffsets[1]==576;
        rr=bridge.receipt();
        strictOk=rr.strictViolations==0 && rr.acquireFailures==0;
    }
    const bool freed=gpu.allocations.empty();
    const bool pass=sliceOk&&explicitOk&&rejectMisaligned&&rejectOob&&catalogOk&&catalog2Ok&&bridgeOk&&offsetsOk&&strictOk&&freed;

    std::cout << "GATE=RAWRXD_EXPERT_CACHE_003\n";
    std::cout << "PACKED_Q4K_SLICE=" << (sliceOk?"PASS":"FAIL") << "\n";
    std::cout << "EXPLICIT_STRIDE_FALLBACK=" << (explicitOk?"PASS":"FAIL") << "\n";
    std::cout << "QUANT_ALIGNMENT_GUARD=" << (rejectMisaligned?"PASS":"FAIL") << "\n";
    std::cout << "BOUNDS_GUARD=" << (rejectOob?"PASS":"FAIL") << "\n";
    std::cout << "PACKED_CATALOG=" << ((catalogOk&&catalog2Ok)?"PASS":"FAIL") << "\n";
    std::cout << "EXPERTS_DISCOVERED=" << catalog.stats().expertsDiscovered << "\n";
    std::cout << "PACKED_SLICES=" << catalog.stats().packedSlicesAdded << "\n";
    std::cout << "GPU_BINDING_OFFSETS=" << (offsetsOk?"PASS":"FAIL") << "\n";
    std::cout << "STRICT_GPU_VIOLATIONS=" << rr.strictViolations << "\n";
    std::cout << "GPU_FREED=" << (freed?"PASS":"FAIL") << "\n";
    std::cout << "VERDICT=" << (pass?"PASS":"FAIL") << "\n";
    return pass?0:3;
}
