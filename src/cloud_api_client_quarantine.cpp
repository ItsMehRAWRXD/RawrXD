// Fail-closed CloudApiClient — linked when RAWRXD_OPTIONAL_CLOUD=OFF.
#include "cloud_api_client.h"

namespace RawrXD {

CloudApiClient::CloudApiClient(UniversalModelRouter*) {}
CloudApiClient::~CloudApiClient() = default;

ApiResponse CloudApiClient::performRequest(const std::string&, const nlohmann::json&,
                                           const CloudModelConfig&,
                                           std::function<void(const std::string&)>)
{
    ApiResponse r;
    r.success = false;
    r.status_code = 0;
    r.error_message = "RAWRXD_OPTIONAL_CLOUD=OFF: cloud client not linked";
    return r;
}

std::string CloudApiClient::generate(const std::string&, const CloudModelConfig&)
{
    return {};
}

void CloudApiClient::generateAsync(const std::string&, const CloudModelConfig&,
                                   std::function<void(std::string)> callback)
{
    if (callback)
        callback({});
}

void CloudApiClient::generateStream(const std::string&, const CloudModelConfig&,
                                    std::function<void(const std::string&)>,
                                    std::function<void(const std::string&)> complete)
{
    if (complete)
        complete("RAWRXD_OPTIONAL_CLOUD=OFF");
}

bool CloudApiClient::checkProviderHealth(const CloudModelConfig&) { return false; }

void CloudApiClient::checkProviderHealthAsync(const CloudModelConfig&,
                                              std::function<void(bool)> callback)
{
    if (callback)
        callback(false);
}

std::vector<std::string> CloudApiClient::listModels(const CloudModelConfig&) { return {}; }

void CloudApiClient::listModelsAsync(const CloudModelConfig&,
                                     std::function<void(const std::vector<std::string>&)> cb)
{
    if (cb)
        cb({});
}

nlohmann::json CloudApiClient::buildRequestBody(const std::string&, const CloudModelConfig&)
{
    return nlohmann::json::object();
}

std::vector<ApiCallLog> CloudApiClient::getCallHistory() const { return {}; }
void CloudApiClient::clearCallHistory() {}
ApiCallLog CloudApiClient::getLastCall() const { return {}; }
double CloudApiClient::getAverageLatency() const { return 0.0; }
int CloudApiClient::getSuccessRate() const { return 0; }

}  // namespace RawrXD
