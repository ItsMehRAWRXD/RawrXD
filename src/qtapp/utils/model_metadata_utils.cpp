#include "model_metadata_utils.hpp"
#include <QFileInfo>
#include <QRegularExpression>
#include "../../ai/streaming_gguf_loader_qt.h"

namespace model_metadata {

static QString fileSizeMB(const QString& path) {
    QFileInfo fi(path);
    if (!fi.exists()) return QString();
    double mb = fi.size() / (1024.0 * 1024.0);
    return QString::number(mb, 'f', 1);
}

QString parseQuantFromFilename(const QString& filename) {
    // Look for q4_0, q4_1, q5_0, q8_0, mxfp4, q2_k, etc.
    QRegularExpression re("(q[0-9](?:_[0-9A-Za-z]+)?|mxfp4|mxfp|fp32|f16|q2_k|q3_k|q4_k|q5_k|q6_k)", QRegularExpression::CaseInsensitiveOption);
    auto m = re.match(filename);
    if (m.hasMatch()) return m.captured(0).toLower();
    return QString();
}

std::optional<uint64_t> parseParamCountFromFilename(const QString& filename) {
    // Common patterns: 7B, 13B, 125M, 350M, 2.9B
    QRegularExpression re("(\\d+(?:\\.\\d+)?)([BMbm])\\b");
    auto m = re.match(filename);
    if (!m.hasMatch()) return std::nullopt;
    double num = m.captured(1).toDouble();
    QString unit = m.captured(2).toUpper();
    uint64_t params = 0;
    if (unit == "B") params = static_cast<uint64_t>(num * 1000000000.0);
    else if (unit == "M") params = static_cast<uint64_t>(num * 1000000.0);
    return params;
}

QString formatParamCount(uint64_t params) {
    if (params >= 1000000000ULL) {
        double v = params / 1000000000.0;
        return QString::number(v, 'f', 1) + "B";
    }
    if (params >= 1000000ULL) {
        double v = params / 1000000.0;
        return QString::number(v, 'f', 1) + "M";
    }
    return QString::number(params);
}

std::optional<GgufMetadata> extractGgufMetadata(const QString& filePath) {
    GgufMetadata meta;
    QFileInfo fi(filePath);
    if (!fi.exists()) return std::nullopt;
    meta.sizeMB = fi.size() / (1024.0 * 1024.0);

    // Use StreamingGGUFLoaderQt to read header
    StreamingGGUFLoaderQt loader;
    if (!loader.loadModel(filePath.toStdString())) {
        return std::nullopt;
    }
    meta.name = QString::fromStdString(loader.getModelName());
    meta.architecture = QString::fromStdString(loader.getModelArchitecture());
    meta.contextLength = static_cast<int>(loader.getModelContextLength());

    // heuristics for quant and param counts
    meta.quantization = parseQuantFromFilename(fi.fileName());
    if (meta.quantization.isEmpty()) {
        // try metadata keys
        for (const auto& key : loader.getAllMetadataKeys()) {
            if (key.find("quant") != std::string::npos) {
                auto val = loader.getMetadata(key);
                meta.quantization = QString::fromStdString(val.AsString());
                break;
            }
        }
    }

    // parameter count metadata
    for (const auto& key : loader.getAllMetadataKeys()) {
        std::string k = key;
        std::transform(k.begin(), k.end(), k.begin(), ::tolower);
        if (k.find("param") != std::string::npos || k.find("n_params") != std::string::npos) {
            try {
                auto val = loader.getMetadata(key);
                // try various numeric accesses
                uint64_t p = val.AsUInt64();
                meta.parameterCount = p;
                break;
            } catch (...) {
                // ignore
            }
        }
    }

    // fallback parse from filename
    if (!meta.parameterCount.has_value()) {
        meta.parameterCount = parseParamCountFromFilename(fi.fileName());
    }

    return meta;
}

} // namespace model_metadata
