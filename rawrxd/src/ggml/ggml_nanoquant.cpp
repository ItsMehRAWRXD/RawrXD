// ============================================================================
// ggml_nanoquant.cpp — C++ bridge for NanoQuant MASM kernels
// Replaces the previous STUB.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <windows.h>
#include <cstdio>

// ----------------------------------------------------------------------------
// MASM exports
// ----------------------------------------------------------------------------
extern "C" {
    __declspec(dllimport) int NanoQuant_ReverseReadFooter(
        HANDLE hFile,
        uint64_t* readHead,
        void* outFooter);

    __declspec(dllimport) int NanoQuant_DecompressBraid115(
        const uint8_t* compressed,
        size_t compBytes,
        void* output,         // bfloat16_t*
        size_t elements);
}

// ----------------------------------------------------------------------------
// C++ wrapper
// ----------------------------------------------------------------------------
namespace Deep2 {

    // g_braid115Table — 128-entry float table for 1.15-bit braid dequant
    // Exported for MASM access via extern reference
    extern "C" {
        __declspec(dllexport) float g_braid115Table[128] = {
            -8.000000f, -7.500000f, -7.000000f, -6.500000f, -6.000000f, -5.600000f,
            -5.200000f, -4.800000f, -4.400000f, -4.000000f, -3.700000f, -3.400000f,
            -3.100000f, -2.800000f, -2.500000f, -2.300000f, -2.100000f, -1.900000f,
            -1.700000f, -1.500000f, -1.350000f, -1.200000f, -1.080000f, -0.960000f,
            -0.850000f, -0.750000f, -0.660000f, -0.580000f, -0.500000f, -0.430000f,
            -0.360000f, -0.300000f, -0.240000f, -0.190000f, -0.140000f, -0.100000f,
            -0.060000f, -0.030000f, -0.010000f, 0.000000f, 0.010000f, 0.030000f,
            0.060000f, 0.100000f, 0.140000f, 0.190000f, 0.240000f, 0.300000f,
            0.360000f, 0.430000f, 0.500000f, 0.580000f, 0.660000f, 0.750000f,
            0.850000f, 0.960000f, 1.080000f, 1.200000f, 1.350000f, 1.500000f,
            1.700000f, 1.900000f, 2.100000f, 2.300000f, 2.500000f, 2.800000f,
            3.100000f, 3.400000f, 3.700000f, 4.000000f, 4.400000f, 4.800000f,
            5.200000f, 5.600000f, 6.000000f, 6.500000f, 7.000000f, 7.500000f,
            8.000000f, 8.500000f, 9.000000f, 9.500000f, 10.000000f, 10.500000f,
            11.000000f, 11.500000f, 12.000000f, 12.500000f, 13.000000f, 13.500000f,
            14.000000f, 14.500000f, 15.000000f, 15.500000f, 16.000000f, 16.500000f,
            17.000000f, 17.500000f, 18.000000f, 18.500000f, 19.000000f, 19.500000f,
            20.000000f, 20.500000f, 21.000000f, 21.500000f, 22.000000f, 22.500000f,
            23.000000f, 23.500000f, 24.000000f, 24.500000f, 25.000000f, 25.500000f,
            26.000000f, 26.500000f, 27.000000f, 27.500000f, 28.000000f, 28.500000f,
            29.000000f, 29.500000f, 30.000000f, 30.500000f, 31.000000f, 31.500000f,
            32.000000f
        };
    }

    // Wrapper: reverse-read footer from file
    int nanoquant_reverse_read_footer(HANDLE hFile, uint64_t* readHead, void* outFooter) {
        return NanoQuant_ReverseReadFooter(hFile, readHead, outFooter);
    }

    // Wrapper: decompress braid
    int nanoquant_decompress_braid115(const uint8_t* compressed, size_t compBytes,
                                        void* output, size_t elements) {
        return NanoQuant_DecompressBraid115(compressed, compBytes, output, elements);
    }

} // namespace Deep2
