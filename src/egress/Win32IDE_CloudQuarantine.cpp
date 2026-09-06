// Fail-closed cloud/update/HTTP replacements — RAWRXD_OPTIONAL_CLOUD=OFF only.
#include "../../include/auto_update_system.h"
#include "../cloud_api_client.h"
#include "VSCodeMarketplaceAPI.hpp"
#include "../agent/llm_http_client.hpp"

#include <future>

namespace RawrXD {
namespace Update {

AutoUpdateSystem& AutoUpdateSystem::instance()
{
    static AutoUpdateSystem s;
    return s;
}

AutoUpdateSystem::AutoUpdateSystem()
    : m_currentVersion{0, 0, 0, 0}, m_lastResult{}, m_checked(false)
{
    m_repoOwner[0] = '\0';
    m_repoName[0] = '\0';
    InitializeCriticalSection(&m_cs);
}

AutoUpdateSystem::~AutoUpdateSystem() { DeleteCriticalSection(&m_cs); }

void AutoUpdateSystem::setCurrentVersion(uint32_t, uint32_t, uint32_t, uint32_t) {}
void AutoUpdateSystem::setRepository(const char*, const char*) {}
bool AutoUpdateSystem::parseVersionTag(const char*, VersionInfo*) { return false; }

UpdateCheckResult AutoUpdateSystem::httpGet(const wchar_t*, const wchar_t*, char*, size_t)
{
    return {};
}

UpdateCheckResult AutoUpdateSystem::parseReleasesJson(const char*, size_t) { return {}; }
UpdateCheckResult AutoUpdateSystem::checkForUpdates() { return {}; }

void AutoUpdateSystem::checkForUpdatesAsync(UpdateCheckCallback callback, void* userData)
{
    if (callback) {
        UpdateCheckResult r{};
        callback(&r, userData);
    }
}

void AutoUpdateSystem::openDownloadUrl(const char*) {}

} // namespace Update

CloudApiClient::CloudApiClient(UniversalModelRouter*) {}
CloudApiClient::~CloudApiClient() = default;

std::string CloudApiClient::generate(const std::string&, const CloudModelConfig&) { return {}; }

void CloudApiClient::generateAsync(const std::string&, const CloudModelConfig&,
                                   std::function<void(std::string)> cb)
{
    if (cb) cb({});
}

void CloudApiClient::generateStream(const std::string&, const CloudModelConfig&,
                                    std::function<void(const std::string&)>,
                                    std::function<void(const std::string&)> done)
{
    if (done) done({});
}

bool CloudApiClient::checkProviderHealth(const CloudModelConfig&) { return false; }

void CloudApiClient::checkProviderHealthAsync(const CloudModelConfig&,
                                              std::function<void(bool)> cb)
{
    if (cb) cb(false);
}

std::vector<std::string> CloudApiClient::listModels(const CloudModelConfig&) { return {}; }

void CloudApiClient::listModelsAsync(const CloudModelConfig&,
                                     std::function<void(const std::vector<std::string>&)> cb)
{
    if (cb) cb({});
}

nlohmann::json CloudApiClient::buildRequestBody(const std::string&, const CloudModelConfig&)
{
    return nlohmann::json::object();
}

ApiResponse CloudApiClient::performRequest(const std::string&, const nlohmann::json&,
                                           const CloudModelConfig&,
                                           std::function<void(const std::string&)>)
{
    ApiResponse r{};
    r.success = false;
    r.error_message = "OPTIONAL_CLOUD=OFF";
    return r;
}

std::vector<ApiCallLog> CloudApiClient::getCallHistory() const { return {}; }
void CloudApiClient::clearCallHistory() {}
ApiCallLog CloudApiClient::getLastCall() const { return {}; }
double CloudApiClient::getAverageLatency() const { return 0.0; }
int CloudApiClient::getSuccessRate() const { return 0; }

} // namespace RawrXD

namespace VSCodeMarketplace {

bool Query(const std::string&, int, int, std::vector<MarketplaceEntry>& out)
{
    out.clear();
    return false;
}

bool GetById(const std::string&, MarketplaceEntry&) { return false; }

bool DownloadVsix(const std::string&, const std::string&, const std::string&,
                  const std::string&)
{
    return false;
}

} // namespace VSCodeMarketplace

StlHttpClient::StlHttpClient() = default;
StlHttpClient::~StlHttpClient() = default;

StlHttpClient& StlHttpClient::instance()
{
    static StlHttpClient s;
    return s;
}

HttpResponse StlHttpClient::send(const HttpRequest&)
{
    return HttpResponse::fail("OPTIONAL_CLOUD=OFF");
}

HttpResponse StlHttpClient::postJson(const std::string&, const std::string&, int)
{
    return HttpResponse::fail("OPTIONAL_CLOUD=OFF");
}

HttpResponse StlHttpClient::get(const std::string&, int)
{
    return HttpResponse::fail("OPTIONAL_CLOUD=OFF");
}

std::future<HttpResponse> StlHttpClient::sendAsync(const HttpRequest& req)
{
    return std::async(std::launch::deferred, [this, req]() { return send(req); });
}

std::future<HttpResponse> StlHttpClient::postJsonAsync(const std::string& url,
                                                       const std::string& body, int ms)
{
    return std::async(std::launch::deferred,
                      [this, url, body, ms]() { return postJson(url, body, ms); });
}

void StlHttpClient::cancelAll() { m_cancelled.store(true); }
void StlHttpClient::resetStats() {}

HttpResponse StlHttpClient::platformSend(const HttpRequest&)
{
    return HttpResponse::fail("OPTIONAL_CLOUD=OFF");
}

HttpChainStep::~HttpChainStep() = default;

void HttpChainStep::start(const std::string&, const std::string&, int)
{
    m_state = State::Failed;
    m_result = HttpResponse::fail("OPTIONAL_CLOUD=OFF");
}

bool HttpChainStep::poll()
{
    return m_state == State::Completed || m_state == State::Failed;
}

bool HttpChainStep::waitFor(int)
{
    return poll();
}

void HttpChainStep::cancel()
{
    m_state = State::Cancelled;
}

HttpChainExecutor::~HttpChainExecutor() = default;

void HttpChainExecutor::addStep(const std::string&, const std::string&,
                                const std::string&, int)
{
}

void HttpChainExecutor::cancel()
{
    m_cancelled.store(true);
}
