#include "../src/deep2/Deep2ModelArchitecture.hpp"
#include "../src/deep2/Deep2RecurrentMath.hpp"
#include <cstdio>
#include <vector>

int main() {
    using namespace Deep2::Arch;
    using namespace Deep2::Arch::Ref;

    if(resolve("qwen3next").family != ForwardFamily::GatedDeltaNet) return 1;
    if(resolve("qwen35moe").family != ForwardFamily::GatedDeltaNet) return 2;
    if(resolve("nemotron_h").family != ForwardFamily::Mamba2) return 3;
    if(resolve("gpt-oss").family != ForwardFamily::SpecialGraph) return 4;
    if(resolve("laguna").family != ForwardFamily::SpecialGraph) return 5;
    if(resolve("deepseek32").family != ForwardFamily::MLA) return 6;

    // Tiny deterministic GDN state test.
    constexpr std::size_t KH=1,VH=2,KD=2,VD=2;
    float q[KH*KD]={0.6f,0.8f};
    float k[KH*KD]={0.8f,0.6f};
    float v[VH*VD]={1,2,3,4};
    float g[VH]={-0.2f,-0.1f};
    float b[VH]={0.5f,0.75f};
    std::vector<float> S(VH*KD*VD,0.0f), out(VH*VD,0.0f);
    gatedDeltaNetStep(q,k,v,g,b,KH,VH,KD,VD,S.data(),out.data());
    if(!finite(out.data(),out.size())) return 7;

    // Tiny deterministic Mamba2 state test.
    constexpr std::size_t H=2,G=1,HD=2,N=3;
    float x[H*HD]={1,2,3,4};
    float B[G*N]={0.1f,0.2f,0.3f};
    float C[G*N]={0.3f,0.2f,0.1f};
    float dt[H]={0.1f,0.2f};
    float A[H]={-1.0f,-2.0f};
    float D[H]={1.0f,1.0f};
    std::vector<float> MS(H*HD*N,0.0f), my(H*HD,0.0f);
    mamba2Step(x,B,C,dt,A,D,H,G,HD,N,MS.data(),my.data());
    if(!finite(my.data(),my.size())) return 8;

    std::puts("RAWRXD_MODEL_ARCH_PACK_001_SELFTEST=PASS");
    return 0;
}
