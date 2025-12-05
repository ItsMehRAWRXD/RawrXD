#include "distributed_trainer.h"
#include <QDebug>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#include <QThread>
#include <QTimer>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <chrono>

/**
 * @brief DistributedTrainer::DistributedTrainer - Constructor
 */
DistributedTrainer::DistributedTrainer(QObject* parent)
    : QObject(parent), m_backend(Backend::NCCL), m_parallelismType(ParallelismType::DataParallel),
      m_isInitialized(false), m_isTraining(false), m_globalStep(0), m_worldRank(0), m_worldSize(1)
{
    qDebug() << "[DistributedTrainer] Initializing distributed trainer";
    initialize();
}

/**
 * @brief DistributedTrainer::~DistributedTrainer - Destructor
 */
DistributedTrainer::~DistributedTrainer()
{
    if (m_isTraining) {
        stopTraining();
    }
    
    // Clean up backend resources
    finalizeBackend();
    
    qDebug() << "[DistributedTrainer] Distributed trainer destroyed";
}

/**
 * @brief DistributedTrainer::initialize - Initialize distributed training
 */
bool DistributedTrainer::initialize()
{
    qDebug() << "[DistributedTrainer] Initializing";
    
    try {
        // Detect backend
        detectAvailableBackends();
        
        // Initialize process group
        if (!initializeProcessGroup()) {
            qWarning() << "[DistributedTrainer] Failed to initialize process group";
            return false;
        }
        
        // Set up communication
        m_isInitialized = true;
        
        qDebug() << "[DistributedTrainer] Initialized with backend:" << static_cast<int>(m_backend)
                 << ", Rank:" << m_worldRank << ", Size:" << m_worldSize;
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[DistributedTrainer] Initialization failed:" << e.what();
        return false;
    }
}

/**
 * @brief DistributedTrainer::detectAvailableBackends - Detect NCCL, Gloo, MPI
 */
void DistributedTrainer::detectAvailableBackends()
{
    qDebug() << "[DistributedTrainer] Detecting available backends";
    
    m_availableBackends.clear();
    
    // NCCL is available (assume for NVIDIA GPUs)
    m_availableBackends.push_back(Backend::NCCL);
    qDebug() << "[DistributedTrainer] NCCL backend available";
    
    // Gloo is available (CPU/GPU)
    m_availableBackends.push_back(Backend::Gloo);
    qDebug() << "[DistributedTrainer] Gloo backend available";
    
    // MPI check (may not be installed)
    #ifdef HAVE_MPI
    m_availableBackends.push_back(Backend::MPI);
    qDebug() << "[DistributedTrainer] MPI backend available";
    #endif
    
    // Default to NCCL
    m_backend = Backend::NCCL;
}

/**
 * @brief DistributedTrainer::initializeProcessGroup - Initialize process group
 */
bool DistributedTrainer::initializeProcessGroup()
{
    qDebug() << "[DistributedTrainer] Initializing process group";
    
    try {
        // Get rank and world size from environment
        m_worldRank = getEnvironmentInt("RANK", 0);
        m_worldSize = getEnvironmentInt("WORLD_SIZE", 1);
        
        if (m_worldRank >= m_worldSize) {
            qWarning() << "[DistributedTrainer] Invalid rank/size:" << m_worldRank << "/" << m_worldSize;
            return false;
        }
        
        qDebug() << "[DistributedTrainer] Process group initialized: Rank" << m_worldRank
                 << "of" << m_worldSize;
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[DistributedTrainer] Failed to initialize process group:" << e.what();
        return false;
    }
}

/**
 * @brief DistributedTrainer::startTraining - Begin distributed training
 */
bool DistributedTrainer::startTraining()
{
    if (m_isTraining) {
        qWarning() << "[DistributedTrainer] Training already running";
        return false;
    }
    
    if (!m_isInitialized) {
        qWarning() << "[DistributedTrainer] Not initialized";
        return false;
    }
    
    qDebug() << "[DistributedTrainer] Starting training";
    
    try {
        m_isTraining = true;
        m_globalStep = 0;
        m_trainingStartTime = std::chrono::high_resolution_clock::now();
        
        emit trainingStarted();
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[DistributedTrainer] Failed to start training:" << e.what();
        m_isTraining = false;
        return false;
    }
}

/**
 * @brief DistributedTrainer::stopTraining - Stop distributed training
 */
bool DistributedTrainer::stopTraining()
{
    if (!m_isTraining) {
        return true;
    }
    
    qDebug() << "[DistributedTrainer] Stopping training";
    
    try {
        m_isTraining = false;
        
        // Synchronize all ranks
        allReduce(0.0);
        
        // Calculate training duration
        auto duration = std::chrono::high_resolution_clock::now() - m_trainingStartTime;
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
        
        qDebug() << "[DistributedTrainer] Training stopped after" << seconds << "seconds";
        
        emit trainingStopped();
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[DistributedTrainer] Failed to stop training:" << e.what();
        return false;
    }
}

/**
 * @brief DistributedTrainer::recordGradient - Record gradient for all-reduce
 */
void DistributedTrainer::recordGradient(const QString& paramName, float gradNorm)
{
    m_gradientBuffer[paramName] = gradNorm;
}

/**
 * @brief DistributedTrainer::synchronizeGradients - All-reduce gradients across ranks
 */
bool DistributedTrainer::synchronizeGradients()
{
    if (!m_isTraining) {
        return false;
    }
    
    try {
        auto startTime = std::chrono::high_resolution_clock::now();
        
        // Simulate all-reduce (in real implementation, use NCCL/Gloo)
        double totalGradNorm = 0.0;
        for (const auto& pair : m_gradientBuffer) {
            totalGradNorm += pair.second;
        }
        
        // All-reduce
        totalGradNorm = allReduce(totalGradNorm);
        
        // Average across ranks
        totalGradNorm /= m_worldSize;
        
        auto duration = std::chrono::high_resolution_clock::now() - startTime;
        auto latency = std::chrono::duration<double, std::milli>(duration).count();
        
        m_communicationLatencies.push_back(latency);
        
        // Emit signal
        emit gradientssynchronized(totalGradNorm);
        
        return true;
    }
    catch (const std::exception& e) {
        qCritical() << "[DistributedTrainer] Failed to synchronize gradients:" << e.what();
        return false;
    }
}

/**
 * @brief DistributedTrainer::applyGradientCompression - Compress gradients before communication
 */
std::vector<float> DistributedTrainer::applyGradientCompression(
    const std::vector<float>& gradients, GradientCompression method, float compressionRatio)
{
    std::vector<float> compressed = gradients;
    
    switch (method) {
        case GradientCompression::TopK: {
            // Keep only top K gradients by magnitude
            int k = static_cast<int>(gradients.size() * compressionRatio);
            std::vector<std::pair<float, size_t>> indexed;
            for (size_t i = 0; i < gradients.size(); ++i) {
                indexed.push_back({std::abs(gradients[i]), i});
            }
            std::partial_sort(indexed.begin(), indexed.begin() + k, indexed.end(),
                            [](const auto& a, const auto& b) {
                                return a.first > b.first;
                            });
            
            std::fill(compressed.begin(), compressed.end(), 0.0f);
            for (int i = 0; i < k; ++i) {
                compressed[indexed[i].second] = gradients[indexed[i].second];
            }
            break;
        }
        
        case GradientCompression::Threshold: {
            // Zero out gradients below threshold
            float threshold = 1e-4f;
            for (auto& g : compressed) {
                if (std::abs(g) < threshold) {
                    g = 0.0f;
                }
            }
            break;
        }
        
        case GradientCompression::Quantization: {
            // Quantize to 8-bit
            float maxVal = *std::max_element(compressed.begin(), compressed.end(),
                                            [](float a, float b) {
                                                return std::abs(a) < std::abs(b);
                                            });
            
            for (auto& g : compressed) {
                g = (g / maxVal) * 127.0f;  // Quantize to [-127, 127]
            }
            break;
        }
        
        case GradientCompression::Delta: {
            // Only communicate gradient deltas
            if (!m_lastGradients.empty()) {
                for (size_t i = 0; i < compressed.size(); ++i) {
                    compressed[i] = compressed[i] - m_lastGradients[i];
                }
            }
            m_lastGradients = gradients;
            break;
        }
        
        case GradientCompression::None:
        default:
            break;
    }
    
    return compressed;
}

/**
 * @brief DistributedTrainer::recordStep - Record training step metrics
 */
void DistributedTrainer::recordStep(int step, float loss, float accuracy, float batchTime)
{
    TrainingMetrics metrics;
    metrics.step = step;
    metrics.loss = loss;
    metrics.accuracy = accuracy;
    metrics.batchTime = batchTime;
    metrics.timestamp = QDateTime::currentDateTime().toString(Qt::ISODate);
    
    m_metrics.push_back(metrics);
    m_globalStep = step;
    
    emit stepRecorded(metrics.step, metrics.loss, metrics.accuracy);
}

/**
 * @brief DistributedTrainer::loadBalance - Suggest load balancing
 */
QJsonObject DistributedTrainer::loadBalance()
{
    QJsonObject result;
    
    try {
        // Calculate average metrics per rank
        QJsonArray rankMetrics;
        
        for (int i = 0; i < m_worldSize; ++i) {
            QJsonObject rankObj;
            rankObj["rank"] = i;
            rankObj["gpuUtilization"] = 75.0 + (i * 5);  // Mock data
            rankObj["memoryUsage"] = 60.0 + (i * 8);     // Mock data
            rankObj["batchesProcessed"] = 1000 + (i * 50);
            rankMetrics.append(rankObj);
        }
        
        result["rankMetrics"] = rankMetrics;
        result["recommendation"] = "Consider migrating data from rank 3 to rank 0";
        
        emit loadBalanceComputed(result);
        
        return result;
    }
    catch (const std::exception& e) {
        qCritical() << "[DistributedTrainer] Load balance failed:" << e.what();
        return QJsonObject();
    }
}

/**
 * @brief DistributedTrainer::exportMetrics - Export training metrics as JSON
 */
QJsonObject DistributedTrainer::exportMetrics()
{
    QJsonObject result;
    
    try {
        QJsonArray metricsArray;
        
        for (const auto& metric : m_metrics) {
            QJsonObject obj;
            obj["step"] = metric.step;
            obj["loss"] = metric.loss;
            obj["accuracy"] = metric.accuracy;
            obj["batchTime"] = metric.batchTime;
            obj["timestamp"] = metric.timestamp;
            metricsArray.append(obj);
        }
        
        result["metrics"] = metricsArray;
        result["worldSize"] = m_worldSize;
        result["globalStep"] = m_globalStep;
        result["backend"] = static_cast<int>(m_backend);
        
        // Communication stats
        if (!m_communicationLatencies.empty()) {
            double avgLatency = std::accumulate(m_communicationLatencies.begin(),
                                               m_communicationLatencies.end(), 0.0) /
                               m_communicationLatencies.size();
            result["avgCommunicationLatency"] = avgLatency;
        }
        
        return result;
    }
    catch (const std::exception& e) {
        qCritical() << "[DistributedTrainer] Export metrics failed:" << e.what();
        return QJsonObject();
    }
}

/**
 * @brief DistributedTrainer::allReduce - Simulate all-reduce operation
 */
double DistributedTrainer::allReduce(double value)
{
    // In real implementation, use NCCL/Gloo
    // For now, return simulated result
    return value * m_worldSize;
}

/**
 * @brief DistributedTrainer::finalizeBackend - Clean up backend resources
 */
void DistributedTrainer::finalizeBackend()
{
    qDebug() << "[DistributedTrainer] Finalizing backend";
    
    // In real implementation, destroy NCCL/Gloo process group
    // For now, just log
}

/**
 * @brief DistributedTrainer::getEnvironmentInt - Get environment variable as int
 */
int DistributedTrainer::getEnvironmentInt(const QString& var, int defaultValue)
{
    QString value = qgetenv(var.toStdString().c_str());
    if (value.isEmpty()) {
        return defaultValue;
    }
    
    bool ok;
    int result = value.toInt(&ok);
    return ok ? result : defaultValue;
}
