#pragma once
#include <string_view>
#include <cctype>
namespace rawrxd::extensions {
inline bool validIdentifier(std::string_view value) noexcept {
    if (value.empty() || value.size() > 128) return false;
    for (unsigned char c : value) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    return true;
}
inline bool validVersion(std::string_view value) noexcept {
    if (value.empty() || value.size() > 64) return false;
    unsigned dots = 0;
    bool digitInSegment = false;
    bool firstDigitZero = false;
    for (unsigned char c : value) {
        if (c == '.') {
            if (!digitInSegment || dots == 2) return false;
            ++dots;
            digitInSegment = false;
            firstDigitZero = false;
        } else if (c >= '0' && c <= '9') {
            if (digitInSegment && firstDigitZero) return false;
            if (!digitInSegment) firstDigitZero = (c == '0');
            digitInSegment = true;
        } else return false;
    }
    // SemVer numeric core identifiers must not contain leading zeroes.
    // This parser intentionally accepts only the MAJOR.MINOR.PATCH core.
    return dots == 2 && digitInSegment;
}
inline bool validManifestIdentity(std::string_view publisher,
                                  std::string_view name,
                                  std::string_view version) noexcept {
    return validIdentifier(name) &&
           (publisher.empty() || validIdentifier(publisher)) &&
           validVersion(version);
}
}
