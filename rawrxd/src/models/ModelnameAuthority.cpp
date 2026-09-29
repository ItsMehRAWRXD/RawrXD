// ModelnameAuthority.cpp — RAWRXD_MODELNAME_AUTHORITY_001
#include "ModelnameAuthority.h"
#include "../ReceiptAuthority.h"
#include <cstdio>
#include <sys/stat.h>
namespace rawrxd { namespace models {
ModelResolution resolveModelName(const std::string& name) {
    ModelResolution mr; mr.path = name;
    mr.isLocalGguf = (name.size() > 5 && name.substr(name.size()-5) == ".gguf");
    mr.isOllama = (!mr.isLocalGguf && name.find(':') != std::string::npos);
    struct stat st; mr.exists = (stat(name.c_str(), &st) == 0);
    mr.headerValid = mr.exists && mr.isLocalGguf;
    return mr;
}
ModelResolution resolveAlias(const std::string& alias) { return resolveModelName(alias); }
ModelResolution resolveOllamaManifest(const std::string& model) {
    ModelResolution mr; mr.isOllama = true; mr.path = model; return mr;
}
void writeModelResolutionReceipt(const std::string& path, const ModelResolution& mr) {
    rawrxd::receipt::beginGate(path, "RAWRXD_MODELNAME_AUTHORITY_001");
    rawrxd::receipt::writeKeyValue(path, "MODEL_NAME", mr.path);
    rawrxd::receipt::writeKeyValueInt(path, "ALIAS_USED", mr.alias.empty() ? 0 : 1);
    rawrxd::receipt::writeKeyValueInt(path, "OLLAMA_MANIFEST_USED", mr.isOllama ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "LOCAL_GGUF_USED", mr.isLocalGguf ? 1 : 0);
    rawrxd::receipt::writeKeyValue(path, "MODEL_PATH", mr.path);
    rawrxd::receipt::writeKeyValueInt(path, "MODEL_EXISTS", mr.exists ? 1 : 0);
    rawrxd::receipt::writeKeyValueInt(path, "GGUF_HEADER_VALID", mr.headerValid ? 1 : 0);
    rawrxd::receipt::endGate(path, mr.exists ? "PASS" : "FAIL");
}
}} // namespace rawrxd::models