// =============================================================================
// dast_bridge.cpp — S5 ZAP JSON / Burp XML import.
// =============================================================================
#include "dast_bridge.h"

#include <cctype>
#include <cstdio>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>

namespace rawrxd::security {

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += (char)c;
        }
    }
    return out;
}

std::string ReadAll(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string SeverityFromRisk(const std::string& risk) {
    if (risk.find("High") != std::string::npos) return "high";
    if (risk.find("Medium") != std::string::npos) return "medium";
    if (risk.find("Low") != std::string::npos) return "low";
    return "info";
}

}  // namespace

bool DastBridge::Import(const std::string& path,
                        std::vector<DastFinding>& out) const {
    out.clear();
    const std::string body = ReadAll(path);
    if (body.empty()) return false;

    // ZAP JSON: {"site":[{"name":..., "alerts":[{"pluginId":"...","name":...,
    //   "riskdesc":"High (Medium)","instances":[{"uri":"...","evidence":"..."}]}]}]}
    static const std::regex zap_alert(
        R"re(\{[^{}]*"pluginId"\s*:\s*"([^"]*)"[^{}]*"name"\s*:\s*"([^"]*)"[^{}]*"riskdesc"\s*:\s*"([^"]*)")re");
    static const std::regex zap_instance(
        R"re(\{[^{}]*"uri"\s*:\s*"([^"]*)"[^{}]*"evidence"\s*:\s*"([^"]*)")re");
    bool anyZap = false;
    for (std::sregex_iterator it(body.begin(), body.end(), zap_alert), end;
         it != end; ++it) {
        DastFinding f;
        f.rule_id = (*it)[1].str();
        f.message = (*it)[2].str();
        f.severity = SeverityFromRisk((*it)[3].str());
        // Find the nearest instance block after this alert (bounded window).
        const size_t start = (size_t)(it->position(0) + it->length(0));
        const size_t window = body.size() < start + 4096 ? body.size()
                                                         : start + 4096;
        std::string slice = body.substr(start, window - start);
        std::smatch im;
        if (std::regex_search(slice, im, zap_instance)) {
            f.url = im[1].str();
            f.evidence = im[2].str();
        }
        out.push_back(std::move(f));
        anyZap = true;
    }
    if (anyZap) return true;

    // Burp XML: <issue><name>..</name><severity>..</severity><url>..</url>
    static const std::regex burp_issue(
        R"re(<issue>[\s\S]*?<name>([^<]*)</name>[\s\S]*?<severity>([^<]*)</severity>[\s\S]*?(?:<url>([^<]*)</url>)?[\s\S]*?</issue>)re");
    bool anyBurp = false;
    for (std::sregex_iterator it(body.begin(), body.end(), burp_issue), end;
         it != end; ++it) {
        DastFinding f;
        f.message = (*it)[1].str();
        f.severity = (*it)[2].str();
        f.url = (*it)[3].matched ? (*it)[3].str() : "";
        f.rule_id = "burp";
        out.push_back(std::move(f));
        anyBurp = true;
    }
    return anyBurp;
}

std::string DastBridge::ToJson(const std::vector<DastFinding>& findings) {
    std::ostringstream out;
    out << "[\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        out << "{\"rule_id\":\"" << JsonEscape(f.rule_id)
            << "\",\"severity\":\"" << JsonEscape(f.severity)
            << "\",\"url\":\"" << JsonEscape(f.url)
            << "\",\"evidence\":\"" << JsonEscape(f.evidence)
            << "\",\"message\":\"" << JsonEscape(f.message) << "\"}";
        if (i + 1 < findings.size()) out << ",";
        out << "\n";
    }
    out << "]\n";
    return out.str();
}

}  // namespace rawrxd::security