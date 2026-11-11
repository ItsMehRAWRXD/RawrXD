// Phase D.14 Batch 4/5: IoT Gateway
// Connect and manage IoT devices
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace Edge {

// Forward declarations
struct IoTDevice;
struct SensorReading;
struct GatewayConfig;

// ============================================================================
// IoT Types
// ============================================================================

enum class IoTProtocol {
    MQTT = 0,
    COAP = 1,
    HTTP = 2,
    WEBSOCKET = 3,
    GRPC = 4,
    OPC_UA = 5,
    MODBUS = 6,
    BLE = 7,
    LORAWAN = 8,
    ZIGBEE = 9
};

enum class DeviceClass {
    SENSOR = 0,
    ACTUATOR = 1,
    GATEWAY = 2,
    EDGE_COMPUTE = 3,
    CAMERA = 4,
    WEARABLE = 5,
    INDUSTRIAL = 6,
    SMART_HOME = 7
};

enum class DataType {
    TEMPERATURE = 0,
    HUMIDITY = 1,
    PRESSURE = 2,
    LIGHT = 3,
    MOTION = 4,
    ACCELERATION = 5,
    GYROSCOPE = 6,
    MAGNETIC = 7,
    GPS = 8,
    IMAGE = 9,
    AUDIO = 10,
    VIDEO = 11,
    VIBRATION = 12,
    CURRENT = 13,
    VOLTAGE = 14,
    CUSTOM = 15
};

struct IoTDevice {
    std::string device_id;
    std::string name;
    DeviceClass device_class;
    IoTProtocol protocol;
    std::string address;
    int port;
    std::map<std::string, std::string> credentials;
    std::chrono::steady_clock::time_point last_seen;
    bool is_online;
    std::map<std::string, std::any> metadata;
    std::vector<DataType> supported_sensors;
    std::string firmware_version;
    int rssi_dbm;
    float battery_level;
};

struct SensorReading {
    std::string reading_id;
    std::string device_id;
    DataType data_type;
    std::any value;
    std::string unit;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::any> metadata;
    int quality_score;
    bool is_anomaly;
};

struct GatewayConfig {
    std::string gateway_id;
    std::string location;
    std::map<IoTProtocol, bool> enabled_protocols;
    int max_devices;
    std::chrono::seconds heartbeat_interval;
    std::chrono::seconds data_retention;
    std::string upstream_broker;
    int upstream_port;
    std::map<std::string, std::string> auth_config;
    bool enable_edge_processing;
    bool enable_local_storage;
};

// ============================================================================
// Protocol Handlers
// ============================================================================

class ProtocolHandler {
public:
    virtual ~ProtocolHandler() = default;
    
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    
    virtual bool Connect(const std::string& address, int port, 
                         const std::map<std::string, std::string>& credentials) = 0;
    virtual void Disconnect() = 0;
    virtual bool IsConnected() const = 0;
    
    virtual bool Subscribe(const std::string& topic) = 0;
    virtual bool Unsubscribe(const std::string& topic) = 0;
    virtual bool Publish(const std::string& topic, const std::vector<uint8_t>& data) = 0;
    
    virtual std::vector<SensorReading> PollDevice(const std::string& device_id) = 0;
    virtual bool SendCommand(const std::string& device_id, 
                             const std::string& command,
                             const std::map<std::string, std::any>& params) = 0;
    
    virtual IoTProtocol GetProtocol() const = 0;
};

class MQTThandler : public ProtocolHandler {
public:
    struct Config {
        std::string client_id;
        int keepalive_seconds = 60;
        bool clean_session = true;
        int qos = 1;
        std::string will_topic;
        std::vector<uint8_t> will_payload;
    };
    
    explicit MQTThandler(const Config& config);
    ~MQTThandler() override;
    
    bool Initialize() override;
    void Shutdown() override;
    bool Connect(const std::string& address, int port,
                 const std::map<std::string, std::string>& credentials) override;
    void Disconnect() override;
    bool IsConnected() const override;
    bool Subscribe(const std::string& topic) override;
    bool Unsubscribe(const std::string& topic) override;
    bool Publish(const std::string& topic, const std::vector<uint8_t>& data) override;
    std::vector<SensorReading> PollDevice(const std::string& device_id) override;
    bool SendCommand(const std::string& device_id, const std::string& command,
                     const std::map<std::string, std::any>& params) override;
    IoTProtocol GetProtocol() const override { return IoTProtocol::MQTT; }
    
private:
    Config config_;
    void* mqtt_client_;
    std::atomic<bool> connected_{false};
    std::map<std::string, std::vector<SensorReading>> message_buffer_;
    mutable std::mutex buffer_mutex_;
    
    static void OnMessage(void* context, const char* topic, 
                          const uint8_t* payload, int length);
};

class CoAPhandler : public ProtocolHandler {
public:
    struct Config {
        int ack_timeout_ms = 2000;
        int max_retransmit = 4;
    };
    
    explicit CoAPhandler(const Config& config);
    ~CoAPhandler() override;
    
    bool Initialize() override;
    void Shutdown() override;
    bool Connect(const std::string& address, int port,
                 const std::map<std::string, std::string>& credentials) override;
    void Disconnect() override;
    bool IsConnected() const override;
    bool Subscribe(const std::string& topic) override;
    bool Unsubscribe(const std::string& topic) override;
    bool Publish(const std::string& topic, const std::vector<uint8_t>& data) override;
    std::vector<SensorReading> PollDevice(const std::string& device_id) override;
    bool SendCommand(const std::string& device_id, const std::string& command,
                     const std::map<std::string, std::any>& params) override;
    IoTProtocol GetProtocol() const override { return IoTProtocol::COAP; }
    
private:
    Config config_;
    void* coap_session_;
    std::atomic<bool> connected_{false};
};

// ============================================================================
// Device Manager
// ============================================================================

class IoTDeviceManager {
public:
    struct Config {
        int max_devices = 1000;
        std::chrono::seconds device_timeout{300};
        bool auto_discovery = true;
        std::vector<IoTProtocol> discovery_protocols;
    };
    
    explicit IoTDeviceManager(const Config& config);
    ~IoTDeviceManager();
    
    bool Initialize();
    void Shutdown();
    
    // Device registration
    std::string RegisterDevice(const IoTDevice& device);
    bool UnregisterDevice(const std::string& device_id);
    bool UpdateDevice(const std::string& device_id, const IoTDevice& device);
    
    // Device queries
    IoTDevice GetDevice(const std::string& device_id) const;
    std::vector<IoTDevice> GetAllDevices() const;
    std::vector<IoTDevice> GetDevicesByClass(DeviceClass device_class) const;
    std::vector<IoTDevice> GetDevicesByProtocol(IoTProtocol protocol) const;
    std::vector<IoTDevice> GetOnlineDevices() const;
    std::vector<IoTDevice> GetDevicesByLocation(const std::string& location) const;
    
    // Device status
    bool UpdateDeviceStatus(const std::string& device_id, bool is_online);
    bool UpdateDeviceHeartbeat(const std::string& device_id);
    bool UpdateDeviceBattery(const std::string& device_id, float level);
    bool UpdateDeviceRSSI(const std::string& device_id, int rssi_dbm);
    
    // Discovery
    std::vector<IoTDevice> DiscoverDevices();
    bool StartDiscovery(IoTProtocol protocol);
    bool StopDiscovery();
    
    // Firmware
    bool UpdateFirmware(const std::string& device_id, const std::string& firmware_url);
    std::string GetFirmwareStatus(const std::string& device_id) const;
    
private:
    Config config_;
    std::map<std::string, IoTDevice> devices_;
    mutable std::mutex devices_mutex_;
    std::thread discovery_thread_;
    std::atomic<bool> discovering_{false};
    
    void DiscoveryLoop();
    void CleanupOfflineDevices();
};

// ============================================================================
// Data Ingestion
// ============================================================================

class DataIngestionService {
public:
    struct Config {
        int batch_size = 100;
        std::chrono::seconds flush_interval{5};
        bool enable_compression = true;
        bool enable_encryption = true;
        std::string storage_backend;  // kafka, mqtt, timeseries_db
    };
    
    struct IngestionStats {
        int total_readings = 0;
        int readings_per_second = 0;
        int devices_active = 0;
        int queue_depth = 0;
        double avg_latency_ms = 0.0;
    };
    
    explicit DataIngestionService(const Config& config);
    ~DataIngestionService();
    
    bool Initialize();
    void Shutdown();
    
    // Ingestion
    bool IngestReading(const SensorReading& reading);
    bool IngestReadings(const std::vector<SensorReading>& readings);
    
    // Processing
    bool ProcessBatch();
    bool TransformReading(SensorReading& reading);
    bool FilterReading(const SensorReading& reading);
    
    // Buffer management
    int GetQueueDepth() const;
    bool ClearQueue();
    IngestionStats GetStats() const;
    
    // Storage
    bool FlushToStorage();
    bool ArchiveOldData(const std::chrono::hours& age);
    
private:
    Config config_;
    std::queue<SensorReading> reading_queue_;
    mutable std::mutex queue_mutex_;
    std::thread ingestion_thread_;
    std::atomic<bool> running_{false};
    IngestionStats stats_;
    
    void IngestionLoop();
    bool StoreBatch(const std::vector<SensorReading>& batch);
};

// ============================================================================
// Edge Analytics
// ============================================================================

class EdgeAnalytics {
public:
    struct Config {
        bool enable_anomaly_detection = true;
        bool enable_aggregation = true;
        bool enable_ml_inference = true;
        std::string model_path;
        int window_size = 100;
        float anomaly_threshold = 3.0f;
    };
    
    struct AnalyticsResult {
        std::string device_id;
        DataType data_type;
        std::chrono::steady_clock::time_point timestamp;
        std::map<std::string, double> aggregates;
        bool is_anomaly;
        double anomaly_score;
        std::map<std::string, std::any> ml_predictions;
    };
    
    explicit EdgeAnalytics(const Config& config);
    ~EdgeAnalytics();
    
    bool Initialize();
    void Shutdown();
    
    // Real-time analytics
    AnalyticsResult ProcessReading(const SensorReading& reading);
    std::vector<AnalyticsResult> ProcessWindow(const std::string& device_id,
                                                DataType data_type,
                                                const std::chrono::seconds& window);
    
    // Aggregation
    std::map<std::string, double> ComputeAggregates(
        const std::vector<SensorReading>& readings);
    std::map<std::string, double> ComputeRollingStats(
        const std::string& device_id,
        DataType data_type,
        const std::chrono::minutes& window);
    
    // Anomaly detection
    bool DetectAnomaly(const SensorReading& reading);
    std::vector<SensorReading> GetAnomalies(const std::string& device_id,
                                            const std::chrono::hours& window);
    
    // ML inference
    bool LoadModel(const std::string& model_path);
    std::map<std::string, std::any> RunInference(const std::vector<SensorReading>& window);
    
private:
    Config config_;
    std::map<std::string, std::vector<SensorReading>> device_buffers_;
    mutable std::mutex buffers_mutex_;
    std::unique_ptr<void, std::function<void(void*)>> inference_engine_;
    
    double ComputeZScore(const SensorReading& reading, 
                         const std::vector<SensorReading>& history);
};

// ============================================================================
// IoT Gateway Runtime
// ============================================================================

class IoTGatewayRuntime {
public:
    struct Config {
        GatewayConfig gateway;
        IoTDeviceManager::Config device_manager;
        DataIngestionService::Config ingestion;
        EdgeAnalytics::Config analytics;
    };
    
    explicit IoTGatewayRuntime(const Config& config);
    ~IoTGatewayRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    IoTDeviceManager* GetDeviceManager();
    DataIngestionService* GetIngestionService();
    EdgeAnalytics* GetAnalytics();
    ProtocolHandler* GetProtocolHandler(IoTProtocol protocol);
    
    // Protocol management
    bool RegisterProtocolHandler(std::unique_ptr<ProtocolHandler> handler);
    bool EnableProtocol(IoTProtocol protocol);
    bool DisableProtocol(IoTProtocol protocol);
    
    // High-level API
    bool ConnectDevice(const IoTDevice& device);
    bool DisconnectDevice(const std::string& device_id);
    std::vector<SensorReading> ReadFromDevice(const std::string& device_id);
    bool SendToDevice(const std::string& device_id, const std::string& command);
    
    // Gateway status
    GatewayConfig GetGatewayConfig() const;
    int GetConnectedDeviceCount() const;
    DataIngestionService::IngestionStats GetIngestionStats() const;
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<IoTDeviceManager> device_manager_;
    std::unique_ptr<DataIngestionService> ingestion_service_;
    std::unique_ptr<EdgeAnalytics> analytics_;
    std::map<IoTProtocol, std::unique_ptr<ProtocolHandler>> protocol_handlers_;
    mutable std::mutex handlers_mutex_;
};

} // namespace Edge
} // namespace Sovereign
