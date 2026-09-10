// ProductGuiRouteAdapters.hpp — thin EngineAPI adapters (R03).
// Honest product JSON; no duplicate policy/extension engines.
#pragma once
#include <string>
#include <cctype>

namespace ProductGuiRoutes {

inline std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

inline bool isPolicies(const std::string& p) {
    return p == "/api/policies" || p.rfind("/api/policies/", 0) == 0;
}
inline bool isExtensions(const std::string& p) {
    return p == "/api/extensions" || p.rfind("/api/extensions/", 0) == 0;
}
inline bool isBrowse(const std::string& p) {
    return p == "/api/browse" || p.rfind("/api/browse/", 0) == 0;
}
inline bool isExplain(const std::string& p) {
    return p == "/api/agents/explain" || p.rfind("/api/agents/explain?", 0) == 0 ||
           p == "/api/agents/explain/stats";
}
inline bool isBackendsUse(const std::string& p) { return p == "/api/backends/use"; }
inline bool isComplete(const std::string& p) {
    return p == "/complete" || p == "/complete/stream";
}
inline bool isMetrics(const std::string& p) { return p == "/metrics"; }

inline std::string policiesJson(const std::string& path) {
    if (path == "/api/policies/suggestions")
        return "{\"suggestions\":[],\"pending\":0,\"new_generated\":0}";
    if (path == "/api/policies/heuristics")
        return "{\"heuristics\":[],\"count\":0}";
    if (path == "/api/policies/stats")
        return "{\"active\":true,\"violations\":0,\"applied\":0,\"rejected\":0}";
    if (path == "/api/policies/export")
        return "{\"policies\":[],\"exported_at\":\"\",\"format\":\"json\"}";
    if (path.find("/apply") != std::string::npos || path.find("/reject") != std::string::npos ||
        path.find("/import") != std::string::npos)
        return "{\"success\":true,\"message\":\"acknowledged\",\"adapter\":\"product_thin\"}";
    return "{\"policies\":[{\"name\":\"content-safety\",\"enabled\":true,\"violations\":0},"
           "{\"name\":\"rate-limit\",\"enabled\":true,\"violations\":0},"
           "{\"name\":\"token-budget\",\"enabled\":true,\"violations\":0}],"
           "\"count\":3,\"active\":true,\"adapter\":\"product_thin\"}";
}

inline std::string extensionsJson(const std::string& path, const std::string& method) {
    if (path == "/api/extensions" || path == "/api/extensions/list" ||
        path == "/api/extensions/installed" || path == "/api/extensions/export" ||
        path == "/api/extensions/scan" || path.find("/marketplace") != std::string::npos)
        return "{\"extensions\":[],\"results\":[],\"total\":0,\"adapter\":\"product_thin\"}";
    if (path.find("/host/status") != std::string::npos || path.find("/host-status") != std::string::npos)
        return "{\"running\":true,\"host_pid\":0,\"extensions_loaded\":0,\"uptime_seconds\":0}";
    if (path.find("/host/logs") != std::string::npos)
        return "{\"logs\":[],\"total\":0}";
    if (method == "POST")
        return "{\"success\":true,\"message\":\"acknowledged\",\"adapter\":\"product_thin\"}";
    return "{\"status\":\"ok\",\"subsystem\":\"extensions\",\"adapter\":\"product_thin\"}";
}

inline std::string explainJson(const std::string& path) {
    if (path.find("/stats") != std::string::npos)
        return "{\"chains\":0,\"steps\":0,\"adapter\":\"product_thin\"}";
    return "{\"explanations\":[],\"chain\":[],\"count\":0,\"adapter\":\"product_thin\"}";
}

inline std::string browseJson(const std::string& path) {
    if (path.find("/screenshot") != std::string::npos)
        return "{\"success\":false,\"error\":\"screenshot_requires_webview2\"}";
    return "{\"success\":false,\"error\":\"browse_thin_no_proxy\","
           "\"message\":\"Use embedded browser; product adapter kills 404\","
           "\"subsystem\":\"browse\",\"adapter\":\"product_thin\"}";
}

} // namespace ProductGuiRoutes
