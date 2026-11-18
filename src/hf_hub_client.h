#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace RawrXD {

// HFHubClient — HuggingFace Hub API client
// Native implementation using WinHTTP (no external dependencies)
class HFHubClient {
public:
    struct ModelMetadata {
        std::string repo_id;
        std::string model_name;
        std::string description;
        std::vector<std::string> tags;
        std::vector<std::string> files;
        uint64_t total_size = 0;
        bool private_model = false;
        uint64_t downloads = 0;
        std::string last_modified;
    };

    explicit HFHubClient(const std::string& apiToken = "");

    // Search for models on HuggingFace Hub
    std::vector<ModelMetadata> searchModels(
        const std::string& query,
        int limit = 10,
        const std::string& token = ""
    );

    // Get model metadata
    ModelMetadata getModelInfo(const std::string& repoId);

    // Download a model file
    bool downloadFile(
        const std::string& repoId,
        const std::string& filename,
        const std::string& outputDir,
        std::function<void(uint64_t, uint64_t)> progressCallback = nullptr
    );

    // Download a model with progress
    bool downloadModel(
        const std::string& repoId,
        const std::string& modelFilename,
        const std::string& outputDir,
        std::function<void(uint64_t, uint64_t)> progressCallback = nullptr
    );

    // Validate HF access token
    bool validateToken(const std::string& token);

private:
    std::string m_apiToken;

    // Internal HTTP helpers
    std::string fetchJSON(const std::string& url);
    bool downloadFileRaw(
        const std::string& url,
        const std::string& outputPath,
        std::function<void(uint64_t, uint64_t)> progressCallback
    );
};

} // namespace RawrXD