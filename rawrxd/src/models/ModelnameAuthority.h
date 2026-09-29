// ModelnameAuthority.h — RAWRXD_MODELNAME_AUTHORITY_001
#pragma once
#include <string>
namespace rawrxd { namespace models {
struct ModelResolution { std::string path; bool isLocalGguf; bool isOllama; bool exists; bool headerValid; std::string alias; };
ModelResolution resolveModelName(const std::string& name);
ModelResolution resolveAlias(const std::string& alias);
ModelResolution resolveOllamaManifest(const std::string& model);
void writeModelResolutionReceipt(const std::string& path, const ModelResolution& mr);
}} // namespace rawrxd::models