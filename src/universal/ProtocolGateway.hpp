// Phase S.2/5: Protocol Gateway
// RawrXD Protocol Gateway - Universal protocol translation and interoperability

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Universal {

// Protocol types
enum class ProtocolType {
    HTTP_1_1,
    HTTP_2,
    HTTP_3,
    GRPC,
    WEBSOCKET,
    MQTT,
    AMQP,
    KAFKA,
    NATS,
    REDIS,
    GRAPHQL,
    JSON_RPC,
    XML_RPC,
    REST,
    CUSTOM
};

// Message format
enum class MessageFormat {
    JSON,
    PROTOBUF,
    AVRO,
    MESSAGEPACK,
    BSON,
    XML,
    YAML,
    BINARY,
    TEXT,
    CUSTOM
};

// Protocol endpoint
struct ProtocolEndpoint {
    std::string id;
    std::string name;
    ProtocolType protocol;
    
    // Connection
    std::string host;
    uint16_t port;
    bool use_tls;
    std::unordered_map<std::string, std::string> connection_params;
    
    // Authentication
    std::string auth_type;  // "none", "basic", "bearer", "mtls", "custom"
    std::unordered_map<std::string, std::string> auth_credentials;
    
    // Configuration
    std::chrono::seconds timeout;
    uint32_t max_connections;
    bool keep_alive;
    
    // State
    bool is_connected;
    uint32_t active_connections;
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t errors;
    std::chrono::system_clock::time_point last_activity;
};

// Message structure
struct ProtocolMessage {
    std::string id;
    std::string correlation_id;
    
    // Metadata
    ProtocolType source_protocol;
    ProtocolType target_protocol;
    MessageFormat format;
    
    // Headers
    std::unordered_map<std::string, std::string> headers;
    
    // Payload
    std::vector<uint8_t> payload;
    size_t payload_size;
    
    // Timing
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point sent_at;
    std::chrono::system_clock::time_point received_at;
    
    // Routing
    std::string source_endpoint;
    std::string target_endpoint;
    std::string reply_to;
    
    // Status
    enum class Status {
        PENDING,
        SENDING,
        SENT,
        DELIVERED,
        FAILED,
        EXPIRED
    } status;
    std::string error_message;
};

// Protocol handler interface
class IProtocolHandler {
public:
    virtual ~IProtocolHandler() = default;
    
    // Protocol identification
    virtual ProtocolType GetProtocolType() const = 0;
    virtual std::vector<MessageFormat> GetSupportedFormats() const = 0;
    
    // Connection management
    virtual bool Connect(const ProtocolEndpoint& endpoint) = 0;
    virtual void Disconnect() = 0;
    virtual bool IsConnected() const = 0;
    
    // Message operations
    virtual bool SendMessage(const ProtocolMessage& message) = 0;
    virtual std::optional<ProtocolMessage> ReceiveMessage(std::chrono::milliseconds timeout) = 0;
    virtual bool SendRequest(const ProtocolMessage& request, ProtocolMessage& response, std::chrono::milliseconds timeout) = 0;
    
    // Streaming
    virtual bool Subscribe(const std::string& topic) = 0;
    virtual bool Unsubscribe(const std::string& topic) = 0;
    virtual void SetMessageCallback(std::function<void(const ProtocolMessage&)> callback) = 0;
    
    // Format conversion
    virtual bool Serialize(const std::unordered_map<std::string, std::string>& data, 
                           MessageFormat format, std::vector<uint8_t>& output) = 0;
    virtual bool Deserialize(const std::vector<uint8_t>& input, 
                             MessageFormat format, std::unordered_map<std::string, std::string>& data) = 0;
};

// Protocol gateway interface
class IProtocolGateway {
public:
    virtual ~IProtocolGateway() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Endpoint management
    virtual std::string RegisterEndpoint(const ProtocolEndpoint& endpoint) = 0;
    virtual bool UnregisterEndpoint(const std::string& endpoint_id) = 0;
    virtual std::optional<ProtocolEndpoint> GetEndpoint(const std::string& endpoint_id) = 0;
    virtual std::vector<ProtocolEndpoint> ListEndpoints() = 0;
    virtual bool ConnectEndpoint(const std::string& endpoint_id) = 0;
    virtual void DisconnectEndpoint(const std::string& endpoint_id) = 0;
    
    // Message routing
    virtual bool RouteMessage(const ProtocolMessage& message) = 0;
    virtual bool SendMessage(const std::string& endpoint_id, const ProtocolMessage& message) = 0;
    virtual std::optional<ProtocolMessage> SendRequest(const std::string& endpoint_id, 
                                                          const ProtocolMessage& request,
                                                          std::chrono::milliseconds timeout) = 0;
    
    // Protocol translation
    virtual bool TranslateMessage(const ProtocolMessage& source, 
                                   ProtocolType target_protocol,
                                   ProtocolMessage& target) = 0;
    virtual bool ConvertFormat(const std::vector<uint8_t>& input,
                                MessageFormat source_format,
                                MessageFormat target_format,
                                std::vector<uint8_t>& output) = 0;
    
    // Bridging
    virtual bool CreateBridge(const std::string& source_endpoint_id,
                               const std::string& target_endpoint_id,
                               const std::string& bridge_id) = 0;
    virtual bool DestroyBridge(const std::string& bridge_id) = 0;
    virtual std::vector<std::string> ListBridges() = 0;
    
    // Protocol handlers
    virtual bool RegisterProtocolHandler(std::unique_ptr<IProtocolHandler> handler) = 0;
    virtual bool UnregisterProtocolHandler(ProtocolType protocol) = 0;
    virtual IProtocolHandler* GetProtocolHandler(ProtocolType protocol) = 0;
    
    // Statistics
    virtual struct GatewayStatistics {
        uint32_t registered_endpoints;
        uint32_t connected_endpoints;
        uint32_t active_bridges;
        uint64_t messages_routed;
        uint64_t messages_translated;
        uint64_t translation_failures;
        double average_routing_latency_ms;
        std::unordered_map<ProtocolType, uint64_t> messages_by_protocol;
    } GetStatistics() = 0;
};

// Local protocol gateway
class LocalProtocolGateway : public IProtocolGateway {
public:
    LocalProtocolGateway();
    ~LocalProtocolGateway() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RegisterEndpoint(const ProtocolEndpoint& endpoint) override;
    bool UnregisterEndpoint(const std::string& endpoint_id) override;
    std::optional<ProtocolEndpoint> GetEndpoint(const std::string& endpoint_id) override;
    std::vector<ProtocolEndpoint> ListEndpoints() override;
    bool ConnectEndpoint(const std::string& endpoint_id) override;
    void DisconnectEndpoint(const std::string& endpoint_id) override;
    
    bool RouteMessage(const ProtocolMessage& message) override;
    bool SendMessage(const std::string& endpoint_id, const ProtocolMessage& message) override;
    std::optional<ProtocolMessage> SendRequest(const std::string& endpoint_id, 
                                                const ProtocolMessage& request,
                                                std::chrono::milliseconds timeout) override;
    
    bool TranslateMessage(const ProtocolMessage& source, 
                          ProtocolType target_protocol,
                          ProtocolMessage& target) override;
    bool ConvertFormat(const std::vector<uint8_t>& input,
                        MessageFormat source_format,
                        MessageFormat target_format,
                        std::vector<uint8_t>& output) override;
    
    bool CreateBridge(const std::string& source_endpoint_id,
                       const std::string& target_endpoint_id,
                       const std::string& bridge_id) override;
    bool DestroyBridge(const std::string& bridge_id) override;
    std::vector<std::string> ListBridges() override;
    
    bool RegisterProtocolHandler(std::unique_ptr<IProtocolHandler> handler) override;
    bool UnregisterProtocolHandler(ProtocolType protocol) override;
    IProtocolHandler* GetProtocolHandler(ProtocolType protocol) override;
    
    GatewayStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, ProtocolEndpoint> endpoints_;
    std::unordered_map<ProtocolType, std::unique_ptr<IProtocolHandler>> handlers_;
    std::unordered_map<std::string, std::pair<std::string, std::string>> bridges_;
    bool initialized_ = false;
    
    bool TranslateHeaders(const ProtocolMessage& source, ProtocolMessage& target);
    bool TranslatePayload(const ProtocolMessage& source, ProtocolMessage& target);
};

// Protocol-specific handlers
class HttpHandler : public IProtocolHandler { /* ... */ };
class GrpcHandler : public IProtocolHandler { /* ... */ };
class WebSocketHandler : public IProtocolHandler { /* ... */ };
class MqttHandler : public IProtocolHandler { /* ... */ };
class KafkaHandler : public IProtocolHandler { /* ... */ };

// Format converters
class FormatConverter {
public:
    static bool JsonToProtobuf(const std::vector<uint8_t>& json, std::vector<uint8_t>& protobuf);
    static bool ProtobufToJson(const std::vector<uint8_t>& protobuf, std::vector<uint8_t>& json);
    static bool JsonToXml(const std::vector<uint8_t>& json, std::vector<uint8_t>& xml);
    static bool XmlToJson(const std::vector<uint8_t>& xml, std::vector<uint8_t>& json);
    static bool JsonToMessagePack(const std::vector<uint8_t>& json, std::vector<uint8_t>& msgpack);
    static bool MessagePackToJson(const std::vector<uint8_t>& msgpack, std::vector<uint8_t>& json);
};

// Global protocol gateway
extern std::unique_ptr<IProtocolGateway> g_protocol_gateway;

// Initialize protocol gateway
bool InitializeProtocolGateway(const std::string& config_path);
void ShutdownProtocolGateway();
bool IsProtocolGatewayEnabled();

// Protocol helpers
std::string ProtocolTypeToString(ProtocolType type);
ProtocolType ProtocolTypeFromString(const std::string& str);
std::string MessageFormatToString(MessageFormat format);
MessageFormat MessageFormatFromString(const std::string& str);

} // namespace Universal
} // namespace RawrXD
