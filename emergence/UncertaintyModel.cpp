#include "emergence/UncertaintyModel.hpp"
#include <unordered_map>

static std::unordered_map<std::string, float> uncertainties;

void UncertaintyModel::Init() {
    uncertainties.clear();
}

void UncertaintyModel::SetUncertainty(const std::string& key, float confidence) {
    uncertainties[key] = confidence;
}

float UncertaintyModel::GetUncertainty(const std::string& key) {
    auto it = uncertainties.find(key);
    return (it != uncertainties.end()) ? it->second : 0.5f;
}

nlohmann::json UncertaintyModel::GetAll() {
    return nlohmann::json(uncertainties);
}
