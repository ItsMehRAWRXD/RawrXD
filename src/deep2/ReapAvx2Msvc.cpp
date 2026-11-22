// Compile this translation unit only with /arch:AVX2.
// The caller must validate CPUID and XGETBV before invoking this entry.
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#ifndef __AVX2__
#error ReapAvx2Msvc.cpp requires /arch:AVX2
#endif
#include "ReapQ4KToQ2K.hpp"
namespace Deep2 { namespace ReapQuant {
bool ConvertMsvcAvx2(const Q4Block& source,Q2Block& target,Error& error) noexcept {
    return ConvertAVX2(source,target,error);
}
} }
#endif
