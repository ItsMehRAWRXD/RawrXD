// =============================================================================
// sbom_export.cpp — S4 CycloneDX SBOM implementation.
// =============================================================================
#include "sbom_export.h"

#include <cstdint>
#include <cstdio>
#include <sstream>

namespace rawrxd::security {

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    return out;
}

// FNV-1a 64-bit for the deterministic serial number.
std::string SerialNumber(const std::string& seed) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : seed) {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "urn:uuid:%016llx-%016llx",
                  (unsigned long long)(h >> 16), (unsigned long long)h);
    return buf;
}

}  // namespace

std::string SbomExporter::ToCycloneDx(
    const std::vector<Dependency>& deps, const std::string& component_name,
    const std::string& component_version) {
    std::ostringstream out;
    out << "{\n"
        << "  \"bomFormat\": \"CycloneDX\",\n"
        << "  \"specVersion\": \"1.4\",\n"
        << "  \"serialNumber\": \"" << SerialNumber(component_name + std::to_string(deps.size())) << "\",\n"
        << "  \"version\": 1,\n"
        << "  \"metadata\": {\n"
        << "    \"component\": {\n"
        << "      \"type\": \"application\",\n"
        << "      \"name\": \"" << JsonEscape(component_name) << "\",\n"
        << "      \"version\": \"" << JsonEscape(component_version) << "\"\n"
        << "    }\n"
        << "  },\n"
        << "  \"components\": [\n";
    for (size_t i = 0; i < deps.size(); ++i) {
        const auto& d = deps[i];
        out << "    {\n"
            << "      \"type\": \"library\",\n"
            << "      \"name\": \"" << JsonEscape(d.name) << "\",\n"
            << "      \"version\": \"" << JsonEscape(d.version) << "\",\n"
            << "      \"purl\": \"pkg:" << JsonEscape(d.ecosystem) << "/"
            << JsonEscape(d.name);
        if (!d.version.empty()) out << "@" << JsonEscape(d.version);
        out << "\"\n"
            << "    }";
        if (i + 1 < deps.size()) out << ",";
        out << "\n";
    }
    out << "  ]\n}\n";
    return out.str();
}

}  // namespace rawrxd::security