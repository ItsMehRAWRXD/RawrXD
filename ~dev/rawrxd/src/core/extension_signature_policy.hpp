#pragma once
#include <string_view>
namespace rawrxd::extensions {
// Explicit opt-in only; unsigned VSIX packages are untrusted by default.
inline bool allowUnsignedVSIX(std::string_view flag) noexcept {
    return flag == "1" || flag == "Y" || flag == "y";
}
inline bool mayInstallVSIX(bool signatureVerified, std::string_view unsignedFlag) noexcept {
    return signatureVerified || allowUnsignedVSIX(unsignedFlag);
}
}
