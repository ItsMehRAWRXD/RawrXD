// HeadlessIDE_AgentRun.cpp — local-only /api/agent/run
// Same production AgentHttpRun as GUI LocalServer handleAgentRun.
#include "HeadlessIDE.h"
#include "AgentProduct.hpp"
#include "Win32IDE_AgenticBridge.h"
#include "../product/gateway/product_deep2_infer.hpp"
#include "../subagent_core.h"

namespace {

bool isLoopbackPeer(const std::string& address) {
    return address == "::1" || address == "localhost" ||
        address.compare(0, 4, "127.") == 0 ||
        address.compare(0, 11, "::ffff:127.") == 0;
}

} // namespace

void HeadlessIDE::routeAgentRunRequest(const HostedHttpRequest& request,
                                       HostedHttpResponse& response) {
    const bool localLoopback =
        m_config.ingressMode == HeadlessIngressMode::Local &&
        isLoopbackPeer(request.peer) &&
        isLoopbackPeer(m_config.bindAddress);
    if (!localLoopback) {
        response.status = 403;
        response.body =
            "{\"error\":\"agent_run_local_only\",\"detail\":\"non_loopback_denied\"}";
        return;
    }
    bool ready = !m_loadedModelPath.empty() || rawr::ProductSessionOpen();
    AgenticBridge bridge(nullptr);
    bridge.Initialize("", "");
    SubAgentManager* mgr = bridge.GetSubAgentManager();
    std::string out;
    int code = AgentHttpRun(request.body, ready, mgr, &out);
    response.status = code;
    response.body = out.empty() ? "{\"error\":\"empty\"}" : out;
    response.contentType = "application/json; charset=utf-8";
}
