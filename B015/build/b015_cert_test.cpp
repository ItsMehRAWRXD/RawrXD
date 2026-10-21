// ============================================================================
// B015: Standalone Certification Test
// ============================================================================
// Compiles independently to verify correctness + benchmark before integration.
// Usage: cl /arch:AVX512 /O2 /EHsc b015_cert_test.cpp /Fe:b015_cert_test.exe
//        g++ -mavx512f -O2 -o b015_cert_test b015_cert_test.cpp
//
// Expected output:
//   Blocks: 4096
//   Scalar:  X.XXX ms
//   AVX-512: Y.YYY ms
//   Speedup: Z.ZZ×
//   Bit-exact: PASS
// ============================================================================

#define B015_ENABLE_CERTIFICATION
#include "b015_dequantize_q4k_avx512.hpp"
#include <cstdio>

int main() {
    printf("B015: AVX-512 Q4_K_M Dequantization Certification\n");
    printf("=================================================\n\n");

    auto result = b015::B015_Certify(4096);
    b015::B015_PrintCert(result);

    printf("\n");
    if (result.bit_exact) {
        printf("CERTIFICATION: PASS\n");
        return 0;
    } else {
        printf("CERTIFICATION: FAIL (bit-exactness mismatch)\n");
        return 1;
    }
}
