#include "rawrxd/deployment/ModelServer.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>

namespace rawrxd {
namespace deployment {

ModelServer::ModelServer() = default;

ModelServer::~ModelServer() {
    Stop();
}

bool ModelServer::Initialize(const ModelServerConfig& config) {
    config_ = config;
    
    // Load model
    // model_ = std::make_unique<Model>();
    // if (!model_->Load(config_.modelPath)) {
    //     return false;
    // }
    
    // Load tokenizer
    // tokenizer_ = std::make_unique<Tokenizer>();
    // if (!tokenizer_->Load(config_.tokenizerPath)) {
    //     return false;
    // }
    
    return true;
}

bool ModelServer::Start() {
    if (running_) {
        return false;
    }
    
    running_ = true;
    shutdownRequested_ = false;
    
    // Start worker threads
    for (int i = 0; i < config_.numWorkers; ++i) {
        workerThreads_.emplace_back(&ModelServer::WorkerLoop, this, i);
    }
    
    // Start accept thread
    acceptThread_ = std::thread(&ModelServer::AcceptLoop, this);
    
    // Start monitor thread
    monitorThread_ = std::thread(&ModelServer::MonitorLoop, this);
    
    // Start metrics thread
    metricsThread_ = std::thread(&ModelServer::MetricsLoop, this);
    
    return true;
}

void ModelServer::Stop() {
    if (!running_) {
        return;
    }
    
    shutdownRequested_ = true;
    running_ = false;
    
    // Notify all waiting threads
    queueCV_.notify_all();
    
    // Join threads
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
    
    for (auto& thread : workerThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }
    
    if (metricsThread_.joinable()) {
        metricsThread_.join();
    }
}

std::future<InferenceResponse> ModelServer::SubmitRequest(const InferenceRequest& request,
                                                            RequestPriority priority) {
    std::promise<InferenceResponse> promise;
    std::future<InferenceResponse> future = promise.get_future();
    
    if (!running_ || shutdownRequested_) {
        InferenceResponse response;
        response.requestId = request.requestId;
        response.success = false;
        response.errorMessage = "Server not running";
        promise.set_value(response);
        return future;
    }
    
    // Check rate limit
    if (config_.enableRateLimiting && !CheckRateLimit(request.user)) {
        InferenceResponse response;
        response.requestId = request.requestId;
        response.success = false;
        response.errorMessage = "Rate limit exceeded";
        promise.set_value(response);
        return future;
    }
    
    // Check if request is valid
    if (!IsRequestValid(request)) {
        InferenceResponse response;
        response.requestId = request.requestId;
        response.success = false;
        response.errorMessage = "Invalid request";
        promise.set_value(response);
        return future;
    }
    
    // Queue request
    QueuedRequest queuedRequest;
    queuedRequest.request = request;
    queuedRequest.priority = priority;
    queuedRequest.promise = std::move(promise);
    queuedRequest.enqueueTime = std::chrono::system_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        if (static_cast<int>(requestQueue_.size()) >= config_.maxQueueSize) {
            InferenceResponse response;
            response.requestId = request.requestId;
            response.success = false;
            response.errorMessage = "Server overloaded";
            queuedRequest.promise.set_value(response);
            return future;
        }
        requestQueue_.push(std::move(queuedRequest));
    }
    
    queueCV_.notify_one();
    
    return future;
}

ModelServer::ServerStats ModelServer::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

bool ModelServer::HealthCheck() const {
    if (!running_) return false;
    // if (!model_) return false;
    // if (!tokenizer_) return false;
    return true;
}

ModelServer::ModelInfo ModelServer::GetModelInfo() const {
    ModelInfo info;
    info.modelId = "rawrxd-model";
    info.modelVersion = "1.0.0";
    // info.vocabSize = tokenizer_ ? tokenizer_->GetVocabSize() : 0;
    // info.numLayers = model_ ? model_->GetNumLayers() : 0;
    // info.numHeads = model_ ? model_->GetNumHeads() : 0;
    // info.hiddenSize = model_ ? model_->GetHiddenSize() : 0;
    info.maxContextLength = config_.maxSequenceLength;
    info.capabilities = {"completion", "chat", "embeddings"};
    return info;
}

void ModelServer::GracefulShutdown(std::chrono::seconds timeout) {
    shutdownRequested_ = true;
    
    // Wait for queue to drain or timeout
    auto startTime = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::steady_clock::now() - startTime) < timeout) {
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (requestQueue_.empty()) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    Stop();
}

bool ModelServer::ReloadModel(const std::string& modelPath) {
    // Reload model
    // if (model_) {
    //     return model_->Load(modelPath);
    // }
    return false;
}

void ModelServer::AcceptLoop() {
    // In real implementation, accept HTTP/WebSocket connections
    // For now, this is a placeholder
    
    while (running_ && !shutdownRequested_) {
        // Accept new connection
        // auto connection = httpServer_->Accept();
        // Handle connection...
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void ModelServer::WorkerLoop(int workerId) {
    while (running_) {
        QueuedRequest request;
        
        // Wait for request
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait(lock, [this] {
                return !requestQueue_.empty() || !running_;
            });
            
            if (!running_) break;
            
            if (requestQueue_.empty()) continue;
            
            request = std::move(const_cast<QueuedRequest>&(requestQueue_.top()));
            requestQueue_.pop();
        }
        
        // Update active requests
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.activeRequests++;
        }
        
        // Check deadline
        if (std::chrono::system_clock::now() > request.request.deadline) {
            InferenceResponse response;
            response.requestId = request.request.requestId;
            response.success = false;
            response.errorMessage = "Request timeout";
            request.promise.set_value(response);
            
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.activeRequests--;
            continue;
        }
        
        // Process request
        auto response = ProcessRequest(request.request);
        
        // Update stats
        UpdateStats(request.request, response);
        
        // Set promise value
        request.promise.set_value(response);
        
        // Update active requests
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.activeRequests--;
        }
    }
}

void ModelServer::MonitorLoop() {
    while (running_) {
        // Update server stats
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            stats_.queuedRequests = static_cast<int>(requestQueue_.size());
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void ModelServer::MetricsLoop() {
    while (running_) {
        // Calculate percentiles
        std::lock_guard<std::mutex> lock(statsMutex_);
        
        if (!latencies_.empty()) {
            std::vector<double> sortedLatencies = latencies_;
            std::sort(sortedLatencies.begin(), sortedLatencies.end());
            
            stats_.avgLatencyMs = std::accumulate(sortedLatencies.begin(), sortedLatencies.end(), 0.0) 
                                  / sortedLatencies.size();
            
            size_t p50Idx = sortedLatencies.size() * 0.5;
            size_t p95Idx = sortedLatencies.size() * 0.95;
            size_t p99Idx = sortedLatencies.size() * 0.99;
            
            if (p50Idx < sortedLatencies.size()) stats_.p50LatencyMs = sortedLatencies[p50Idx];
            if (p95Idx < sortedLatencies.size()) stats_.p95LatencyMs = sortedLatencies[p95Idx];
            if (p99Idx < sortedLatencies.size()) stats_.p99LatencyMs = sortedLatencies[p99Idx];
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

InferenceResponse ModelServer::ProcessRequest(const InferenceRequest& request) {
    InferenceResponse response;
    response.requestId = request.requestId;
    auto startTime = std::chrono::high_resolution_clock::now();
    
    try {
        switch (request.type) {
            case RequestType::COMPLETION:
            case RequestType::CHAT:
                // Generate text
                // response.generatedText = model_->Generate(request.prompt, request.maxTokens);
                response.generatedText = "Generated text placeholder";
                response.tokensGenerated = request.maxTokens;
                break;
                
            case RequestType::EMBEDDING:
                // Generate embedding
                // response.embedding = model_->Embed(request.prompt);
                response.embedding = std::vector<float>(768, 0.0f);
                break;
                
            case RequestType::TOKENIZE:
                // Tokenize
                // response.tokens = tokenizer_->Encode(request.prompt);
                response.tokens = {1, 2, 3, 4, 5};
                break;
                
            case RequestType::DETOKENIZE:
                // Detokenize
                // response.generatedText = tokenizer_->Decode(request.tokens);
                response.generatedText = "Detokenized text";
                break;
                
            case RequestType::HEALTH:
                response.success = true;
                return response;
        }
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);
        
        response.totalTimeMs = duration.count();
        response.timeToFirstTokenMs = duration.count() * 0.1f; // Approximate
        response.success = true;
        response.finishReason = "stop";
        
        // Calculate usage
        response.usage["prompt_tokens"] = std::to_string(request.prompt.length() / 4); // Approximate
        response.usage["completion_tokens"] = std::to_string(response.tokensGenerated);
        response.usage["total_tokens"] = std::to_string(
            std::stoi(response.usage["prompt_tokens"]) + response.tokensGenerated);
        
    } catch (const std::exception& e) {
        response.success = false;
        response.errorMessage = e.what();
    }
    
    return response;
}

void ModelServer::UpdateStats(const InferenceRequest& request, 
                               const InferenceResponse& response) {
    std::lock_guard<std::mutex> lock(statsMutex_);
    
    stats_.totalRequests++;
    if (response.success) {
        stats_.successfulRequests++;
    } else {
        stats_.failedRequests++;
    }
    
    latencies_.push_back(response.totalTimeMs);
    if (latencies_.size() > 10000) {
        latencies_.erase(latencies_.begin());
    }
    
    stats_.throughputTokensPerSec += response.tokensGenerated;
}

bool ModelServer::IsRequestValid(const InferenceRequest& request) const {
    if (request.requestId.empty()) return false;
    if (request.type != RequestType::HEALTH) {
        if (request.prompt.empty() && request.messages.empty()) return false;
    }
    if (request.maxTokens <= 0 || request.maxTokens > 8192) return false;
    if (request.temperature < 0.0f || request.temperature > 2.0f) return false;
    if (request.topP < 0.0f || request.topP > 1.0f) return false;
    return true;
}

bool ModelServer::CheckRateLimit(const std::string& user) {
    if (user.empty()) return true;
    
    std::lock_guard<std::mutex> lock(rateLimitMutex_);
    
    auto now = std::chrono::system_clock::now();
    auto window = std::chrono::minutes(1);
    
    auto& timestamps = rateLimitMap_[user];
    
    // Remove old timestamps
    timestamps.erase(
        std::remove_if(timestamps.begin(), timestamps.end(),
            [&now, window](const auto& ts) {
                return now - ts > window;
            }),
        timestamps.end());
    
    // Check if under limit
    if (static_cast<int>(timestamps.size()) >= config_.rateLimitRequestsPerMinute) {
        return false;
    }
    
    // Add current timestamp
    timestamps.push_back(now);
    return true;
}

std::string ModelServer::GenerateRequestId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << std::hex;
    for (int i = 0; i < 32; ++i) {
        ss << dis(gen);
    }
    return ss.str();
}

// RESTAPIHandler implementation
RESTAPIHandler::RESTAPIHandler(ModelServer* server) : server_(server) {}

RESTAPIHandler::~RESTAPIHandler() = default;

std::string RESTAPIHandler::HandleRequest(const std::string& method, const std::string& path,
                                          const std::string& body,
                                          const std::map<std::string, std::string>& headers) {
    if (method == "POST" && path == "/v1/completions") {
        return HandleCompletions(body);
    } else if (method == "POST" && path == "/v1/chat/completions") {
        return HandleChatCompletions(body);
    } else if (method == "POST" && path == "/v1/embeddings") {
        return HandleEmbeddings(body);
    } else if (method == "POST" && path == "/v1/tokenize") {
        return HandleTokenize(body);
    } else if (method == "GET" && path == "/health") {
        return HandleHealth();
    } else if (method == "GET" && path == "/v1/models") {
        return HandleModels();
    }
    
    return "{\"error\": \"Not found\"}";
}

void RESTAPIHandler::HandleStreamingRequest(const std::string& method, const std::string& path,
                                           const std::string& body,
                                           const std::map<std::string, std::string>& headers,
                                           std::function<void(const std::string&)> callback) {
    // Handle streaming request
    // Parse request
    // Generate tokens one by one
    // Call callback for each token
}

std::string RESTAPIHandler::HandleCompletions(const std::string& body) {
    auto request = ParseCompletionRequest(body);
    auto future = server_->SubmitRequest(request);
    auto response = future.get();
    return SerializeResponse(response);
}

std::string RESTAPIHandler::HandleChatCompletions(const std::string& body) {
    auto request = ParseChatRequest(body);
    auto future = server_->SubmitRequest(request);
    auto response = future.get();
    return SerializeResponse(response);
}

std::string RESTAPIHandler::HandleEmbeddings(const std::string& body) {
    InferenceRequest request;
    request.type = RequestType::EMBEDDING;
    // Parse body
    
    auto future = server_->SubmitRequest(request);
    auto response = future.get();
    return SerializeResponse(response);
}

std::string RESTAPIHandler::HandleTokenize(const std::string& body) {
    InferenceRequest request;
    request.type = RequestType::TOKENIZE;
    // Parse body
    
    auto future = server_->SubmitRequest(request);
    auto response = future.get();
    return SerializeResponse(response);
}

std::string RESTAPIHandler::HandleHealth() {
    bool healthy = server_->HealthCheck();
    return healthy ? "{\"status\": \"healthy\"}" : "{\"status\": \"unhealthy\"}";
}

std::string RESTAPIHandler::HandleModels() {
    auto info = server_->GetModelInfo();
    std::stringstream ss;
    ss << "{\"object\": \"list\", \"data\": [{";
    ss << "\"id\": \"" << info.modelId << "\",";
    ss << "\"object\": \"model\",";
    ss << "\"created\": " << std::time(nullptr) << ",";
    ss << "\"owned_by\": \"rawrxd\"";
    ss << "}]}";
    return ss.str();
}

InferenceRequest RESTAPIHandler::ParseCompletionRequest(const std::string& body) {
    InferenceRequest request;
    request.type = RequestType::COMPLETION;
    // Parse JSON body
    // request.prompt = ...
    // request.maxTokens = ...
    // etc.
    return request;
}

InferenceRequest RESTAPIHandler::ParseChatRequest(const std::string& body) {
    InferenceRequest request;
    request.type = RequestType::CHAT;
    // Parse JSON body
    // request.messages = ...
    // request.maxTokens = ...
    // etc.
    return request;
}

std::string RESTAPIHandler::SerializeResponse(const InferenceResponse& response) {
    std::stringstream ss;
    ss << "{";
    ss << "\"id\": \"" << response.requestId << "\",";
    ss << "\"object\": \"text_completion\",";
    ss << "\"created\": " << std::time(nullptr) << ",";
    ss << "\"model\": \"rawrxd-model\",";
    ss << "\"choices\": [{";
    ss << "\"text\": \"" << response.generatedText << "\",";
    ss << "\"index\": 0,";
    ss << "\"finish_reason\": \"" << response.finishReason << "\"";
    ss << "}],";
    ss << "\"usage\": {";
    ss << "\"prompt_tokens\": " << response.usage.at("prompt_tokens") << ",";
    ss << "\"completion_tokens\": " << response.usage.at("completion_tokens") << ",";
    ss << "\"total_tokens\": " << response.usage.at("total_tokens");
    ss << "}";
    ss << "}";
    return ss.str();
}

std::string RESTAPIHandler::SerializeStreamingChunk(const InferenceResponse& response, bool isLast) {
    std::stringstream ss;
    ss << "data: {";
    ss << "\"id\": \"" << response.requestId << "\",";
    ss << "\"object\": \"text_completion\",";
    ss << "\"choices\": [{";
    ss << "\"text\": \"" << response.generatedText << "\",";
    ss << "\"index\": 0,";
    if (isLast) {
        ss << "\"finish_reason\": \"stop\"";
    } else {
        ss << "\"finish_reason\": null";
    }
    ss << "}]";
    ss << "}\n\n";
    if (isLast) {
        ss << "data: [DONE]\n\n";
    }
    return ss.str();
}

} // namespace deployment
} // namespace rawrxd
