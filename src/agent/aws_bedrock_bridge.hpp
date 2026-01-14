#pragma once
#include "agentic_bridge.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class AwsBedrockBridge : public AgenticBridge {
private:
    std::string m_region = "us-east-1";
    std::string m_modelId = "anthropic.claude-3-sonnet-20240229-v1:0";
    
    // Convert to AWS Bedrock format
    json convertToBedrockPayload(const QString& planJson) {
        return {
            {"anthropic_version", "bedrock-2023-05-31"},
            {"max_tokens", 4096},
            {"messages", {{{"role", "user"}, {"content", planJson.toStdString()}}}},
            {"temperature", 0.2},
            {"stream", true}
        };
    }
    
    // AWS SigV4 signing
    std::string signRequest(const std::string& payload);

public:
    AwsBedrockBridge(std::shared_ptr<AIImplementation> ai) : AgenticBridge(ai) {}
    
    // Override with AWS Bedrock streaming
    void streamExecutePlan(const QString& humanWish, 
                          std::function<void(const std::string&)> callback) override;
};
