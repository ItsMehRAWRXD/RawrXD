#include "../src/reap/NativeF16Accuracy.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
    const char* source="reap_accuracy_source.bin";
    const char* target="reap_accuracy_target.bin";
    const uint32_t values[]={0x3f800000u,0x3f801000u,0xbf800000u,
                             0x33800000u,0x7f800000u,0x47800000u};
    {
        std::ofstream out(source,std::ios::binary);
        for(uint32_t value:values)for(unsigned shift=0;shift<32;shift+=8)
            out.put(static_cast<char>(value>>shift));
    }
    {
        std::ofstream out(target,std::ios::binary);
        for(uint32_t value:values){
            const uint16_t half=Float32BitsToFloat16(value);
            out.put(static_cast<char>(half));
            out.put(static_cast<char>(half>>8));
        }
    }
    int fails=0;
    auto check=[&](bool ok,const char* name){
        std::cout<<(ok?"PASS ":"FAIL ")<<name<<"\n";
        if(!ok)++fails;
    };
    F16Accuracy accuracy;
    check(AuditF32ToF16(source,target,0,0,6,accuracy) &&
          accuracy.elements==6 && accuracy.finite==4 &&
          accuracy.nonfinite==1 && accuracy.overflowed==1 &&
          accuracy.max_abs>0 && accuracy.rms_abs>0,
          "f16_accuracy_and_nonfinite_accounting");
    // A finite nonzero F32 value below half-subnormal range must
    // report 100% relative error when it rounds to FP16 zero.
    {
        const char* underflowSource="reap_f16_underflow_source.bin";
        const char* underflowTarget="reap_f16_underflow_target.bin";
        {
            std::ofstream out(underflowSource,std::ios::binary);
            const uint32_t bits=0x33000000u; // 2^-25, ties to zero
            for(unsigned shift=0;shift<32;shift+=8)
                out.put(static_cast<char>(bits>>shift));
        }
        {
            std::ofstream out(underflowTarget,std::ios::binary);
            out.put('\0');out.put('\0');
        }
        F16Accuracy underflow;
        check(AuditF32ToF16(underflowSource,underflowTarget,0,0,1,underflow)
              && underflow.finite==1 && underflow.max_rel==1.0
              && underflow.max_abs>0.0,
              "underflow_reports_full_relative_error");
        std::remove(underflowSource);
        std::remove(underflowTarget);
    }
    // Failed audits must leave the caller's prior certified measurement intact.
    const F16Accuracy baseline=accuracy;
    {
        std::fstream out(target,std::ios::binary|std::ios::in|std::ios::out);
        out.seekp(0);out.put('\x01');
    }
    check(!AuditF32ToF16(source,target,0,0,6,accuracy),
          "corrupted_conversion_rejected");
    check(accuracy.elements==baseline.elements &&
          accuracy.finite==baseline.finite &&
          accuracy.max_abs==baseline.max_abs &&
          accuracy.rms_abs==baseline.rms_abs,
          "corrupt_audit_preserves_previous_result");
    check(!AuditF32ToF16(source,target,0,0,7,accuracy),
          "truncated_tensor_rejected");
    check(!AuditF32ToF16(source,target,UINT64_MAX,0,1,accuracy),
          "source_offset_overflow_rejected");
    check(!AuditF32ToF16(source,target,0,UINT64_MAX,1,accuracy),
          "destination_offset_overflow_rejected");
    check(!AuditF32ToF16(source,target,0,0,0,accuracy),
          "zero_elements_rejected");
    std::remove(source);std::remove(target);
    std::cout<<"REAP_F16_ACCURACY_RESULT="<<(fails?"FAIL":"PASS")
             <<" failures="<<fails<<"\n";
    return fails?1:0;
}
