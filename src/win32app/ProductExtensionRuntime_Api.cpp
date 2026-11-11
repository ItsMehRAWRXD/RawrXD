// ProductExtensionRuntime_Api.cpp — LocalServer route dispatcher.
#include "ProductExtensionRuntime_Internal.hpp"

namespace ProductExtensionRuntime {

static std::string ExtractId(const std::string& body) {
    auto p = body.find("\"id\"");
    if (p == std::string::npos) return {};
    p = body.find(':', p + 4);
    if (p == std::string::npos) return {};
    p = body.find('"', p + 1);
    if (p == std::string::npos) return {};
    auto e = body.find('"', p + 1);
    if (e == std::string::npos) return {};
    return body.substr(p + 1, e - p - 1);
}

static std::string ExtractPath(const std::string& body) {
    auto p = body.find("\"path\"");
    if (p == std::string::npos) return {};
    p = body.find(':', p + 6);
    if (p == std::string::npos) return {};
    p = body.find('"', p + 1);
    if (p == std::string::npos) return {};
    auto e = body.find('"', p + 1);
    if (e == std::string::npos) return {};
    return body.substr(p + 1, e - p - 1);
}

std::string HandleRoute(const std::string& method, const std::string& path,
                        const std::string& body) {
    if (path == "/api/extensions" || path == "/api/extensions/list" ||
        path == "/api/extensions/installed" || path == "/api/extensions/scan" ||
        path == "/api/extensions/export" ||
        path.find("/marketplace") != std::string::npos) {
        return ListJson();
    }
    if (path.find("/host/status") != std::string::npos ||
        path.find("/host-status") != std::string::npos) {
        return HostStatusJson();
    }
    if (path.find("/host/kill") != std::string::npos && method == "POST") {
        return KillHost();
    }
    if (path.find("/host/logs") != std::string::npos) {
        return "{\"logs\":[],\"total\":0,\"adapter\":\"product_extension_runtime\"}";
    }
    if (method == "POST" &&
        (path.find("/load-vsix") != std::string::npos ||
         path.find("/install") != std::string::npos)) {
        return LoadManifestPath(ExtractPath(body));
    }
    if (method == "POST" && path.find("/activate") != std::string::npos) {
        return Activate(ExtractId(body));
    }
    if (method == "POST" && path.find("/enable") != std::string::npos) {
        return Enable(ExtractId(body), true);
    }
    if (method == "POST" && path.find("/disable") != std::string::npos) {
        return Enable(ExtractId(body), false);
    }
    return "{\"status\":\"ok\",\"subsystem\":\"extensions\","
           "\"adapter\":\"product_extension_runtime\"}";
}

} // namespace ProductExtensionRuntime
