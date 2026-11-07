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
    for (unsigned char c : value) {
        if (c == '.') {
            if (!digitInSegment || dots == 2) return false;
            ++dots;
            digitInSegment = false;
        } else if (c >= '0' && c <= '9') {
            digitInSegment = true;
        } else return false;
    }
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
