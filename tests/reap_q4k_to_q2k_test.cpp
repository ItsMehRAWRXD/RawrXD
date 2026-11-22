#include "deep2/ReapQ4KToQ2K.hpp"
#include <cstdio>
#if defined(_WIN32) && defined(_MSC_VER)
#include <intrin.h>
static bool hasAvx2(){
    int info[4]{};
    __cpuidex(info,7,0);
    return (info[1] & (1<<5)) != 0;
}
#endif
using namespace Deep2::ReapQuant;
int main(){
    int pass=0,fail=0;auto check=[&](bool ok,const char* n){std::printf("%s %s\n",ok?"PASS":"FAIL",n);ok?++pass:++fail;};
    uint16_t h=0;
    check(PositiveHalf(1,h)&&h==0x3c00&&Half(h)==1,"binary16 one");
    check(PositiveHalf(std::ldexp(1.0,-24),h)&&h==1,"binary16 subnormal");
    check(PositiveHalf(std::ldexp(1.0,-14),h)&&h==0x400,"binary16 min normal");
    check(PositiveHalf(65504,h)&&h==0x7bff,"binary16 max finite");
    check(PositiveHalf(1+std::ldexp(1.0,-11),h)&&h==0x3c00,"ties to even");
    check(!PositiveHalf(65505,h)&&!PositiveHalf(-1,h),"invalid scale rejected");
    Q4Block q4{};Q2Block q2{};Values x{},y{};Error e;
    check(Convert(q4,q2,e)&&e.squared==0&&e.signal==0,"zero block conversion");
    StoreHalf(q4.data(),0x3c00);StoreHalf(q4.data()+2,0x3c00);
    for(unsigned g=0;g<4;++g){q4[4+g]=1;q4[8+g]=2;q4[12+g]=0x21;}
    for(unsigned i=16;i<144;++i)q4[i]=0x53;
    check(DecodeQ4(q4,x)&&x[0]==1&&x[32]==3&&x[128]==1&&x[224]==3,"known Q4_K packed layout");
    q4[4]|=0x40;q4[8]|=0x80;
    check(DecodeQ4(q4,x)&&x[128]==3*17-34,"upper scale bits");
    q2={};StoreHalf(q2.data()+80,0x3c00);StoreHalf(q2.data()+82,0x3c00);
    for(unsigned i=0;i<16;++i)q2[i]=0x21;
    for(unsigned i=16;i<80;++i)q2[i]=0xe4;
    check(DecodeQ2(q2,y)&&y[0]==-2&&y[16]==-2&&y[32]==-1&&y[64]==0&&y[96]==1&&y[128]==-2,"known Q2_K bitplanes");
    for(unsigned i=0;i<256;++i)x[i]=float(int(i%4)-2);
    check(EncodeQ2(x,q2)&&DecodeQ2(q2,y),"encode signed four-level grid");
    double max=0;for(unsigned i=0;i<256;++i)max=std::max(max,std::abs(double(x[i])-y[i]));
    check(max<.003,"four-level reconstruction");
    x.fill(-2);check(EncodeQ2(x,q2)&&DecodeQ2(q2,y)&&std::abs(y[255]+2)<.003,"negative constant");
    x.fill(3);check(EncodeQ2(x,q2)&&DecodeQ2(q2,y)&&std::abs(y[255]-3)<.003,"positive constant");
    x[17]=std::numeric_limits<float>::quiet_NaN();auto prior=q2;
    check(!EncodeQ2(x,q2)&&q2==prior,"NaN rejected without publishing");
    check(Convert(q4,q2,e)&&e.signal>0&&e.squared>=0&&std::isfinite(e.maxAbs),"Q4_K to Q2_K actual conversion and error");
#if defined(__AVX2__)
#if defined(_WIN32) && defined(_MSC_VER)
    if(!hasAvx2()){
        std::printf("R23_AVX2_UNVERIFIED=CPU_DOES_NOT_REPORT_AVX2\n");
        return 2;
    }
#endif
    // Independent packed fixture: generate logical scales and codes first,
    // then encode the GGUF bytes without using either decoder.
    uint32_t rng=0x923abcdu;
    auto next=[&](){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;};
    bool oracle=true, bytesParity=true;
    for(unsigned trial=0;trial<4096 && oracle && bytesParity;++trial){
        Q4Block block{}; Values expected{}, a{}, b{};
        StoreHalf(block.data(),0x3c00); StoreHalf(block.data()+2,0x3800);
        for(unsigned g=0;g<8;++g){
            unsigned sc=next()&63u,mn=next()&63u;
            if(g<4){block[4+g]|=sc;block[8+g]|=mn;}
            else {
                block[g]|=(sc>>4)<<6;
                block[4+g]|=(mn>>4)<<6;
                block[8+g]=(sc&15u)|((mn&15u)<<4);
            }
            for(unsigned i=0;i<32;++i){
                unsigned q=next()&15u;
                block[16+32*(g/2)+i]|=q<<(4*(g%2));
                expected[32*g+i]=float(sc*q)-0.5f*float(mn);
            }
        }
        oracle=DecodeQ4(block,a)&&DecodeQ4AVX2(block,b)&&a==expected&&b==expected;
        Q2Block qa{},qb{}; Error ea{},eb{};
        bytesParity=Convert(block,qa,ea)&&ConvertAVX2(block,qb,eb)&&qa==qb&&
            ea.squared==eb.squared&&ea.signal==eb.signal&&ea.maxAbs==eb.maxAbs;
    }
    check(oracle,"R23 independent 4096-block packed oracle");
    check(bytesParity,"R23 independent fixtures exact conversion parity");
    Values scalarValues{},simdValues{};
    Q2Block scalarConverted{},simdConverted{};
    Error scalarError{},simdError{};
    const bool scalarDecoded=DecodeQ4(q4,scalarValues);
    const bool simdDecoded=DecodeQ4AVX2(q4,simdValues);
    bool decodeParity=scalarDecoded&&simdDecoded;
    unsigned firstDecodeMismatch=Elements; float maxDecodeDiff=0;
    for(unsigned i=0;i<Elements&&decodeParity;++i){
        const float diff=std::abs(scalarValues[i]-simdValues[i]);
        maxDecodeDiff=std::max(maxDecodeDiff,diff);
        if(diff>1e-6f){firstDecodeMismatch=i;decodeParity=false;}
    }
    if(!decodeParity) std::printf("R23_DECODE_DIFF index=%u scalar=%g simd=%g max=%g\n",
                                  firstDecodeMismatch,scalarValues[firstDecodeMismatch],
                                  simdValues[firstDecodeMismatch],maxDecodeDiff);
    check(decodeParity,"R23 AVX2/scalar Q4_K decode parity");
    const bool converted=Convert(q4,scalarConverted,scalarError)&&
        ConvertAVX2(q4,simdConverted,simdError);
    const bool conversionParity=converted && scalarConverted==simdConverted &&
        std::abs(scalarError.squared-simdError.squared)<=1e-5 &&
        std::abs(scalarError.signal-simdError.signal)<=1e-5 &&
        std::abs(scalarError.maxAbs-simdError.maxAbs)<=1e-6;
    if(!conversionParity) std::printf("R23_CONVERSION_DIFF bytes=%d squared=%g/%g signal=%g/%g max=%g/%g\n",
                                      scalarConverted==simdConverted,
                                      scalarError.squared,simdError.squared,
                                      scalarError.signal,simdError.signal,
                                      scalarError.maxAbs,simdError.maxAbs);
    check(conversionParity,"R23 AVX2/scalar Q4_K to Q2_K parity");
#else
    std::printf("R23_AVX2_UNVERIFIED=AVX2_BUILD_REQUIRED\n");
    return 2;
#endif
    StoreHalf(q4.data(),0x7c00);prior=q2;check(!Convert(q4,q2,e)&&q2==prior,"nonfinite source rejected");
    uint64_t bytes=0;check(ConvertedBytes(7168,144*28*3,bytes)&&bytes==84*28*3,"exact Kimi row byte conversion");
    check(!ConvertedBytes(255,144,bytes)&&!ConvertedBytes(256,145,bytes)&&!ConvertedBytes(512,144,bytes),"partial blocks and rows rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
