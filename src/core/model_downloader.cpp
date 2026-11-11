// ============================================================================
// Model Downloader Implementation
// ============================================================================

#include "model_downloader.hpp"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace Core {

// Forward declarations
std::vector<RemoteModelInfo> GetRecommendedModels();
std::string FormatBytes(uint64_t bytes);

// ============================================================================
// Model Downloader Implementation
// ============================================================================

ModelDownloader::ModelDownloader() = default;
ModelDownloader::~ModelDownloader() {
    CleanupSession();
}

bool ModelDownloader::InitializeSession() {
    if (session_) return true;
    
    session_ = WinHttpOpen(L"RawrXD-ModelDownloader/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS, 0);
    return session_ != nullptr;
}

void ModelDownloader::CleanupSession() {
    if (session_) {
        WinHttpCloseHandle(session_);
        session_ = nullptr;
    }
}

std::string ModelDownloader::BuildHuggingFaceUrl(
    const std::string& repo_id,
    const std::string& filename) {
    return "https://huggingface.co/" + repo_id + "/resolve/main/" + filename;
}

bool ModelDownloader::DownloadFile(
    const std::string& url,
    const std::string& output_path,
    uint64_t resume_from) {
    
    if (!InitializeSession()) {
        progress_.failed = true;
        progress_.error_message = "Failed to initialize HTTP session";
        return false;
    }
    
    // Convert URL to wide string
    int url_len = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
    if (url_len <= 0) return false;
    std::vector<wchar_t> url_w(url_len);
    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, url_w.data(), url_len);
    
    // Parse URL
    URL_COMPONENTS urlComp = {};
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.dwHostNameLength = (DWORD)-1;
    urlComp.dwUrlPathLength = (DWORD)-1;
    urlComp.dwExtraInfoLength = (DWORD)-1;
    
    if (!WinHttpCrackUrl(url_w.data(), 0, 0, &urlComp)) {
        progress_.failed = true;
        progress_.error_message = "Failed to parse URL";
        return false;
    }
    
    std::wstring hostname(urlComp.lpszHostName, urlComp.dwHostNameLength);
    std::wstring urlpath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
    
    // Connect
    HINTERNET hConnect = WinHttpConnect(session_, hostname.c_str(),
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        progress_.failed = true;
        progress_.error_message = "Failed to connect to server";
        return false;
    }
    
    // Open request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlpath.c_str(),
                                             nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        progress_.failed = true;
        progress_.error_message = "Failed to open request";
        return false;
    }
    
    // Enable automatic redirect following (Hugging Face uses redirects to CDN)
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_ALWAYS;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));
    
    // Add resume header if needed and User-Agent (required by Hugging Face)
    std::wstring headers;
    headers = L"User-Agent: RawrXD-ModelDownloader/1.0\r\n";
    if (resume_from > 0) {
        headers += L"Range: bytes=" + std::to_wstring(resume_from) + L"-\r\n";
    }
    
    // Send request
    if (!WinHttpSendRequest(hRequest, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                            headers.empty() ? 0 : (DWORD)headers.length(),
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        progress_.failed = true;
        progress_.error_message = "Failed to send request";
        return false;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        progress_.failed = true;
        progress_.error_message = "Failed to receive response";
        return false;
    }
    
    // Check status code
    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    
    if (statusCode != 200 && statusCode != 206) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        progress_.failed = true;
        progress_.error_message = "HTTP error: " + std::to_string(statusCode);
        return false;
    }
    
    // Get content length
    DWORD contentLength = 0;
    DWORD lengthSize = sizeof(contentLength);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &contentLength, &lengthSize, WINHTTP_NO_HEADER_INDEX);
    
    progress_.total_bytes = contentLength + resume_from;
    progress_.bytes_downloaded = resume_from;
    
    // Open output file
    std::ios_base::openmode mode = std::ios::binary | std::ios::out;
    if (resume_from > 0) mode |= std::ios::app;
    
    std::ofstream outFile(output_path, mode);
    if (!outFile) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        progress_.failed = true;
        progress_.error_message = "Failed to open output file";
        return false;
    }
    
    // Download data
    downloading_ = true;
    cancel_requested_ = false;
    
    std::vector<char> buffer(65536);
    auto startTime = std::chrono::steady_clock::now();
    
    while (!cancel_requested_) {
        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), (DWORD)buffer.size(), &bytesRead)) {
            break;
        }
        
        if (bytesRead == 0) break;
        
        outFile.write(buffer.data(), bytesRead);
        progress_.bytes_downloaded += bytesRead;
        
        // Calculate progress
        if (progress_.total_bytes > 0) {
            progress_.percent_complete = 
                (double)progress_.bytes_downloaded / progress_.total_bytes * 100.0;
        }
        
        // Calculate speed
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        if (elapsed > 0) {
            progress_.bytes_per_second = (double)progress_.bytes_downloaded / (elapsed / 1000.0);
        }
        
        // Estimate remaining time
        if (progress_.bytes_per_second > 0) {
            uint64_t remaining = progress_.total_bytes - progress_.bytes_downloaded;
            progress_.estimated_seconds_remaining = (uint32_t)(remaining / progress_.bytes_per_second);
        }
    }
    
    outFile.close();
    downloading_ = false;
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    
    if (cancel_requested_) {
        progress_.failed = true;
        progress_.error_message = "Download cancelled";
        return false;
    }
    
    progress_.completed = true;
    return true;
}

bool ModelDownloader::DownloadFromHuggingFace(
    const std::string& repo_id,
    const std::string& filename,
    const std::string& output_path,
    ProgressCallback callback) {
    
    std::string url = BuildHuggingFaceUrl(repo_id, filename);
    std::string final_path = output_path;
    
    if (final_path.empty()) {
        final_path = GetCacheDirectory() + "/" + filename;
    }
    
    // Create directory
    size_t lastSlash = final_path.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        std::string dir = final_path.substr(0, lastSlash);
        CreateDirectoryA(dir.c_str(), nullptr);
    }
    
    // Reset progress
    progress_ = {};
    
    // Download
    bool success = DownloadFile(url, final_path, 0);
    
    return success;
}

bool ModelDownloader::DownloadWithResume(
    const std::string& url,
    const std::string& output_path,
    ProgressCallback callback) {
    
    uint64_t resume_from = 0;
    
    // Check if file exists
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (GetFileAttributesExA(output_path.c_str(), GetFileExInfoStandard, &attr)) {
        LARGE_INTEGER size;
        size.HighPart = attr.nFileSizeHigh;
        size.LowPart = attr.nFileSizeLow;
        resume_from = size.QuadPart;
    }
    
    progress_ = {};
    progress_.bytes_downloaded = resume_from;
    
    return DownloadFile(url, output_path, resume_from);
}

void ModelDownloader::CancelDownload() {
    cancel_requested_ = true;
}

std::vector<RemoteModelInfo> ModelDownloader::ListModelsInRepo(const std::string& repo_id) {
    std::vector<RemoteModelInfo> models;
    // Would query Hugging Face API
    return models;
}

std::vector<RemoteModelInfo> ModelDownloader::SearchModels(
    const std::string& query,
    const std::string& filter_quant) {
    std::vector<RemoteModelInfo> results;
    // Would query Hugging Face API
    return results;
}

RemoteModelInfo ModelDownloader::GetModelInfo(
    const std::string& repo_id,
    const std::string& filename) {
    
    RemoteModelInfo info;
    info.repo_id = repo_id;
    info.filename = filename;
    info.url = BuildHuggingFaceUrl(repo_id, filename);
    
    // Parse quantization from filename
    size_t qpos = filename.find(".Q");
    if (qpos != std::string::npos) {
        size_t end = filename.find(".", qpos + 1);
        if (end == std::string::npos) end = filename.length();
        info.quantization = filename.substr(qpos + 1, end - qpos - 1);
    }
    
    // Parse parameters
    if (filename.find("7b") != std::string::npos || filename.find("7B") != std::string::npos) {
        info.num_params = 7;
    } else if (filename.find("13b") != std::string::npos || filename.find("13B") != std::string::npos) {
        info.num_params = 13;
    } else if (filename.find("70b") != std::string::npos || filename.find("70B") != std::string::npos) {
        info.num_params = 70;
    }
    
    return info;
}

bool ModelDownloader::VerifyFile(const std::string& filepath, const std::string& expected_hash) {
    // Would compute SHA256 and compare
    return true;
}

bool ModelDownloader::ParseJsonModelList(
    const std::string& json_data,
    std::vector<RemoteModelInfo>& models) {
    // Would parse JSON response from Hugging Face API
    return true;
}

// Static cache directory
static std::string g_cache_directory = "models/";

std::string ModelDownloader::GetCacheDirectory() {
    return g_cache_directory;
}

void ModelDownloader::SetCacheDirectory(const std::string& path) {
    g_cache_directory = path;
    if (!g_cache_directory.empty() && g_cache_directory.back() != '/' && g_cache_directory.back() != '\\') {
        g_cache_directory += '/';
    }
    CreateDirectoryA(g_cache_directory.c_str(), nullptr);
}

std::vector<std::string> ModelDownloader::ListCachedModels() {
    std::vector<std::string> models;
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((g_cache_directory + "*.gguf").c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                models.push_back(findData.cFileName);
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    return models;
}

bool ModelDownloader::ClearCache() {
    auto models = ListCachedModels();
    for (const auto& model : models) {
        DeleteFileA((g_cache_directory + model).c_str());
    }
    return true;
}

// ============================================================================
// Model Manager Implementation
// ============================================================================

ModelManager::ModelManager() = default;
ModelManager::~ModelManager() = default;

bool ModelManager::Initialize(const std::string& cache_dir) {
    if (!cache_dir.empty()) {
        ModelDownloader::SetCacheDirectory(cache_dir);
    }
    return true;
}

bool ModelManager::DownloadModel(
    const std::string& repo_id,
    const std::string& filename,
    ProgressCallback callback) {
    
    ModelDownloader downloader;
    std::string output_path = ModelDownloader::GetCacheDirectory() + filename;
    
    return downloader.DownloadFromHuggingFace(repo_id, filename, output_path, callback);
}

std::string ModelManager::GetModelPath(
    const std::string& repo_id,
    const std::string& filename) {
    
    std::string path = ModelDownloader::GetCacheDirectory() + filename;
    
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &attr)) {
        return path;
    }
    
    return "";
}

bool ModelManager::IsModelCached(
    const std::string& repo_id,
    const std::string& filename) {
    return !GetModelPath(repo_id, filename).empty();
}

RemoteModelInfo ModelManager::GetCachedModelInfo(
    const std::string& repo_id,
    const std::string& filename) {
    RemoteModelInfo info;
    info.repo_id = repo_id;
    info.filename = filename;
    
    // Parse from filename
    size_t qpos = filename.find(".Q");
    if (qpos != std::string::npos) {
        size_t end = filename.find(".", qpos + 1);
        if (end == std::string::npos) end = filename.length();
        info.quantization = filename.substr(qpos + 1, end - qpos - 1);
    }
    
    return info;
}

std::vector<RemoteModelInfo> ModelManager::ListCachedModels() {
    std::vector<RemoteModelInfo> models;
    
    auto cached = ModelDownloader::ListCachedModels();
    for (const auto& filename : cached) {
        RemoteModelInfo info;
        info.filename = filename;
        info.quantization = "unknown";
        
        // Parse from filename
        size_t qpos = filename.find(".Q");
        if (qpos != std::string::npos) {
            size_t end = filename.find(".", qpos + 1);
            if (end == std::string::npos) end = filename.length();
            info.quantization = filename.substr(qpos + 1, end - qpos - 1);
        }
        
        models.push_back(info);
    }
    
    return models;
}

bool ModelManager::DeleteCachedModel(
    const std::string& repo_id,
    const std::string& filename) {
    std::string path = GetCachePath(repo_id, filename);
    return DeleteFileA(path.c_str()) != 0;
}

uint64_t ModelManager::GetCacheSize() const {
    // Calculate total size of cache directory
    uint64_t total_size = 0;
    std::string cache_dir = ModelDownloader::GetCacheDirectory();
    
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA((cache_dir + "*").c_str(), &find_data);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                total_size += (static_cast<uint64_t>(find_data.nFileSizeHigh) << 32) | find_data.nFileSizeLow;
            }
        } while (FindNextFileA(hFind, &find_data));
        FindClose(hFind);
    }
    
    return total_size;
}

std::vector<RemoteModelInfo> ModelManager::GetPopularModels() {
    return GetRecommendedModels();
}

RemoteModelInfo ModelManager::RecommendModel(
    uint32_t preferred_size_gb,
    const std::string& quantization) {
    auto models = GetRecommendedModels();
    if (models.empty()) {
        return RemoteModelInfo{};
    }
    
    // Return first model as default recommendation
    return models[0];
}

std::string ModelManager::GetCachePath(
    const std::string& repo_id,
    const std::string& filename) {
    return ModelDownloader::GetCacheDirectory() + filename;
}

std::string ModelManager::RepoIdToPath(const std::string& repo_id) {
    // Replace / with _ for filesystem
    std::string path = repo_id;
    std::replace(path.begin(), path.end(), '/', '_');
    return path;
}

void ModelManager::SaveModelMetadata(
    const std::string& repo_id,
    const std::string& filename,
    const RemoteModelInfo& info) {
    // Metadata saving stub
}

RemoteModelInfo ModelManager::LoadModelMetadata(
    const std::string& repo_id,
    const std::string& filename) {
    return GetCachedModelInfo(repo_id, filename);
}

// ============================================================================
// Convenience Functions
// ============================================================================

bool DownloadModel(const std::string& repo_id,
                   const std::string& filename,
                   const std::string& output_dir,
                   ProgressCallback callback) {
    ModelDownloader downloader;
    if (!output_dir.empty()) {
        ModelDownloader::SetCacheDirectory(output_dir);
    }
    return downloader.DownloadFromHuggingFace(repo_id, filename, "", callback);
}

std::vector<RemoteModelInfo> GetRecommendedModels() {
    std::vector<RemoteModelInfo> models;
    
    // Llama 2 models
    models.push_back({"TheBloke/Llama-2-7B-GGUF", "llama-2-7b.Q4_K_M.gguf", 
                       "", "Llama 2 7B Q4_K_M", 0, "Q4_K_M", 7, 4.0f});
    models.push_back({"TheBloke/Llama-2-13B-GGUF", "llama-2-13b.Q4_K_M.gguf",
                       "", "Llama 2 13B Q4_K_M", 0, "Q4_K_M", 13, 8.0f});
    
    // Qwen models
    models.push_back({"TheBloke/Qwen2-7B-Instruct-GGUF", "qwen2-7b-instruct.Q4_K_M.gguf",
                       "", "Qwen2 7B Instruct Q4_K_M", 0, "Q4_K_M", 7, 4.0f});
    
    // Phi models
    models.push_back({"TheBloke/Phi-3-mini-4k-instruct-GGUF", "phi-3-mini-4k-instruct.Q4_K_M.gguf",
                       "", "Phi-3 Mini 4K Instruct Q4_K_M", 0, "Q4_K_M", 3, 2.0f});
    
    return models;
}

std::string FormatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit];
    return oss.str();
}

} // namespace Core
} // namespace RawrXD
