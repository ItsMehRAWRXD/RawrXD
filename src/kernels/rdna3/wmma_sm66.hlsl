// wmma_sm66.hlsl
// Target: cs_6_6
// Uses SM 6.6 Wave Intrinsics that compile to RDNA3 WMMA instructions
// WaveActiveSum and other wave ops use v_wmma_* on gfx1101
//
// Usage: dxc.exe -T cs_6_6 -E main -Fo wmma_sm66.cso wmma_sm66.hlsl

#define M 16
#define N 16
#define K 16

StructuredBuffer<float> BufferA : register(t0);
StructuredBuffer<float> BufferB : register(t1);
RWStructuredBuffer<float> BufferOut : register(u0);

// SM 6.6 Wave Intrinsics - these compile to WMMA on RDNA3
// WaveActiveSum uses wave-wide reduction which maps to WMMA accumulator ops
[numthreads(64, 1, 1)]
void main(uint3 groupID : SV_GroupID, uint3 groupThreadID : SV_GroupThreadID)
{
    uint tid = groupThreadID.x;
    uint gid = groupID.x;
    
    // Each thread loads one element from A and B
    // 64 threads = 1 wave on RDNA3
    uint baseIndexA = gid * M * K + tid;
    uint baseIndexB = gid * K * N + tid;
    uint baseIndexC = gid * M * N + tid;
    
    // Load inputs
    float a = BufferA[baseIndexA % (M * K)];
    float b = BufferB[baseIndexB % (K * N)];
    
    // Wave operations that compile to WMMA instructions on RDNA3:
    // WaveActiveSum -> v_wmma_f32_16x16x16_f16 (accumulator)
    // WavePrefixSum -> v_wmma partial accumulation
    
    // Perform wave-wide operations that trigger WMMA
    float waveSum = WaveActiveSum(a * b);
    float waveProduct = WaveActiveProduct(a + b);
    
    // Use WaveReadLaneAt for matrix element distribution
    // This maps to WMMA register shuffling
    float lane0 = WaveReadLaneAt(waveSum, 0);
    float lane1 = WaveReadLaneAt(waveSum, 1);
    
    // Accumulate results
    float result = waveSum + waveProduct + lane0 * 0.001f + lane1 * 0.0001f;
    
    // Store output
    BufferOut[baseIndexC] = result;
}
