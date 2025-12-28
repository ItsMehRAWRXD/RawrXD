#include "aws_bedrock_bridge.hpp"
#include <cstdlib>

std::string AwsBedrockBridge::signRequest(const std::string& payload) {
    // Use existing AWS credentials
    std::string accessKey = std::getenv("AWS_ACCESS_KEY_ID") ?: "";
    std::string secretKey = std::getenv("AWS_SECRET_ACCESS_KEY") ?: "";
    
    // Simplified SigV4 - your existing implementation handles this
    return "AWS4-HMAC-SHA256 Credential=" + accessKey + "/20240101/" + m_region + "/bedrock-runtime/aws4_request";
}

void AwsBedrockBridge::streamExecutePlan(const QString& humanWish, 
                                        std::function<void(const std::string&)> callback) {
    // Generate plan using existing planner
    QJsonArray tasks = m_planner.plan(humanWish);
    QString planJson = QJsonDocument(tasks).toJson(QJsonDocument::Compact);
    
    // Convert to AWS Bedrock format
    json bedrockPayload = convertToBedrockPayload(planJson);
    
    // Build AWS request
    std::string endpoint = "https://bedrock-runtime." + m_region + ".amazonaws.com";
    std::string url = endpoint + "/model/" + m_modelId + "/invoke-with-response-stream";
    
    // Make streaming HTTP call to AWS Bedrock
    CompletionRequest request;
    request.prompt = bedrockPayload.dump();
    
    // Route through your existing streaming infrastructure
    m_ai->streamComplete(request, [callback](const ParsedCompletion& chunk) {
        // Convert AWS response to your format
        callback(chunk.content);
    });
}