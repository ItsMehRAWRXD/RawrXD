#include "../src/deep2/control/GpuForwardChain.hpp"
#include <cassert>
#include <iostream>
using namespace deep2::control;

int main() {
    const std::string s =
        "GATE=G1_GPU_QKV\n"
        "GPU_FORWARD_CHILD_IGNORE=QKV\n"
        "MODEL_FP=abc\n"
        "CLAIM_AUTHORITY=OWN_RUNTIME_EMISSION_ONLY\n"
        "RUNTIME_AUTHORITY=1\n"
        "MODEL_PROVENANCE_MATCH=1\n"
        "PROMOTE=0\n"
        "OLLAMA_HTTP=0\n"
        "TOKENS_COMMITTED=20\n"
        "GPU_FORWARD_MS=500\n"
        "QKV_MS=500\n"
        "QKV_CALLS=20\n"
        "QKV_IGNORE_REQUESTED=1\n"
        "QKV_IGNORE_APPLIED=1\n"
        "BLOCKED_AT=NONE\n";
    GateReceipt r; std::string why;
    assert(ParseGateReceipt(s,r,why));
    ChainPolicy p;
    assert(ValidateGateReceipt(r,p,"abc",why));

    GateReceipt g0=r;
    g0.gate="G0_REFERENCE"; g0.child="NONE"; g0.gpuForwardMs=1000;
    auto a=CompareAgainstBaseline(g0,r,p);
    assert(a.observedCandidate);
    assert(a.attributionRatio==0.5);
    std::cout << "PASS\n";
}
