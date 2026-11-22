// Production linker contract for the isolated MSVC AVX2 kernel.
// This object is compiled without /arch:AVX2 and added to the native IDE.
// /include prevents /OPT:REF from dropping the symbol reference.
#include "deep2/ReapQ4KToQ2K.hpp"

#if defined(_MSC_VER) && defined(_M_X64) && defined(RAWRXD_REAP_MSVC_ISOLATED_AVX2)
namespace Deep2 { namespace ReapQuant {
using IsolatedAvx2Kernel = bool (*)(const Q4Block&,Q2Block&,Error&) noexcept;
}}
extern "C" {
__declspec(selectany) Deep2::ReapQuant::IsolatedAvx2Kernel
    RawrXDReapLinkContractAnchor = &Deep2::ReapQuant::ConvertMsvcAvx2;
}
#pragma comment(linker, "/include:RawrXDReapLinkContractAnchor")
#endif
