#include "interpretability_panel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <QLabel>
#include <QSlider>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QChartView>
#include <QChart>
#include <QLineSeries>
#include <QBarSeries>
#include <QBarSet>
#include <QBarCategoryAxis>
#include <QValueAxis>
#include <QDebug>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonArray>
#include <algorithm>
#include <cmath>

/**
 * @brief InterpretabilityPanel::InterpretabilityPanel - Constructor
 */
InterpretabilityPanel::InterpretabilityPanel(QWidget* parent)
    : QWidget(parent), m_currentVisualization(VisualizationType::AttentionHeatmap),
      m_currentLayer(0), m_maxLayers(12), m_isUpdating(false)
{
    qDebug() << "[InterpretabilityPanel] Initializing interpretability panel";
    setupUI();
    initializeVisualizations();
}

/**
 * @brief InterpretabilityPanel::~InterpretabilityPanel - Destructor
 */
InterpretabilityPanel::~InterpretabilityPanel()
{
    qDebug() << "[InterpretabilityPanel] Interpretability panel destroyed";
}

/**
 * @brief InterpretabilityPanel::setupUI - Create UI components
 */
void InterpretabilityPanel::setupUI()
{
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    
    // Control panel
    QHBoxLayout* controlLayout = new QHBoxLayout();
    
    // Visualization type selector
    QLabel* vizLabel = new QLabel("Visualization:");
    QComboBox* vizCombo = new QComboBox();
    vizCombo->addItem("Attention Heatmap", static_cast<int>(VisualizationType::AttentionHeatmap));
    vizCombo->addItem("Feature Importance", static_cast<int>(VisualizationType::FeatureImportance));
    vizCombo->addItem("Gradient Flow", static_cast<int>(VisualizationType::GradientFlow));
    vizCombo->addItem("Activation Distribution", static_cast<int>(VisualizationType::ActivationDistribution));
    vizCombo->addItem("Attention Head Comparison", static_cast<int>(VisualizationType::AttentionHeadComparison));
    vizCombo->addItem("GradCAM", static_cast<int>(VisualizationType::GradCAM));
    vizCombo->addItem("Layer Contribution", static_cast<int>(VisualizationType::LayerContribution));
    vizCombo->addItem("Embedding Space", static_cast<int>(VisualizationType::EmbeddingSpace));
    vizCombo->addItem("Integrated Gradients", static_cast<int>(VisualizationType::IntegratedGradients));
    vizCombo->addItem("Saliency Map", static_cast<int>(VisualizationType::SaliencyMap));
    
    connect(vizCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &InterpretabilityPanel::onVisualizationTypeChanged);
    
    controlLayout->addWidget(vizLabel);
    controlLayout->addWidget(vizCombo);
    
    // Layer selector
    QLabel* layerLabel = new QLabel("Layer:");
    QSlider* layerSlider = new QSlider(Qt::Horizontal);
    layerSlider->setRange(0, m_maxLayers - 1);
    layerSlider->setValue(0);
    
    connect(layerSlider, &QSlider::valueChanged,
            this, &InterpretabilityPanel::onLayerChanged);
    
    controlLayout->addWidget(layerLabel);
    controlLayout->addWidget(layerSlider);
    
    // Head selector (for attention visualization)
    QLabel* headLabel = new QLabel("Attention Head:");
    QSpinBox* headSpinBox = new QSpinBox();
    headSpinBox->setRange(0, 15);
    headSpinBox->setValue(0);
    
    connect(headSpinBox, QOverload<int>::of(&QSpinBox::valueChanged),
            this, &InterpretabilityPanel::onAttentionHeadChanged);
    
    controlLayout->addWidget(headLabel);
    controlLayout->addWidget(headSpinBox);
    
    // Export button
    QPushButton* exportBtn = new QPushButton("Export");
    connect(exportBtn, &QPushButton::clicked, this, &InterpretabilityPanel::exportVisualization);
    controlLayout->addWidget(exportBtn);
    
    controlLayout->addStretch();
    mainLayout->addLayout(controlLayout);
    
    // Tab widget for different visualizations
    QTabWidget* tabWidget = new QTabWidget();
    
    // Attention heatmap chart
    QChart* attentionChart = new QChart();
    attentionChart->setTitle("Attention Weights Heatmap");
    QChartView* attentionView = new QChartView(attentionChart);
    attentionView->setRenderHint(QPainter::Antialiasing);
    m_visualizations[VisualizationType::AttentionHeatmap] = attentionView;
    tabWidget->addTab(attentionView, "Attention");
    
    // Feature importance chart
    QChart* featureChart = new QChart();
    featureChart->setTitle("Feature Importance");
    QChartView* featureView = new QChartView(featureChart);
    featureView->setRenderHint(QPainter::Antialiasing);
    m_visualizations[VisualizationType::FeatureImportance] = featureView;
    tabWidget->addTab(featureView, "Features");
    
    // Gradient flow chart
    QChart* gradientChart = new QChart();
    gradientChart->setTitle("Gradient Flow");
    QChartView* gradientView = new QChartView(gradientChart);
    gradientView->setRenderHint(QPainter::Antialiasing);
    m_visualizations[VisualizationType::GradientFlow] = gradientView;
    tabWidget->addTab(gradientView, "Gradients");
    
    // Activation distribution chart
    QChart* activationChart = new QChart();
    activationChart->setTitle("Activation Distribution");
    QChartView* activationView = new QChartView(activationChart);
    activationView->setRenderHint(QPainter::Antialiasing);
    m_visualizations[VisualizationType::ActivationDistribution] = activationView;
    tabWidget->addTab(activationView, "Activations");
    
    mainLayout->addWidget(tabWidget);
    
    // Statistics panel
    QHBoxLayout* statsLayout = new QHBoxLayout();
    
    m_statsLabel = new QLabel("Statistics: ");
    statsLayout->addWidget(m_statsLabel);
    statsLayout->addStretch();
    
    mainLayout->addLayout(statsLayout);
    
    setLayout(mainLayout);
}

/**
 * @brief InterpretabilityPanel::initializeVisualizations - Initialize visualization data
 */
void InterpretabilityPanel::initializeVisualizations()
{
    qDebug() << "[InterpretabilityPanel] Initializing visualizations";
    
    // Create mock data for each visualization type
    m_attentionWeights.resize(m_maxLayers);
    m_featureImportance.resize(m_maxLayers);
    m_gradientFlow.resize(m_maxLayers);
    m_activationStats.resize(m_maxLayers);
    
    for (int layer = 0; layer < m_maxLayers; ++layer) {
        // Attention weights: 12 heads x 768 tokens
        std::vector<std::vector<float>> layerAttention(12);
        for (int h = 0; h < 12; ++h) {
            layerAttention[h].resize(768);
            for (int t = 0; t < 768; ++t) {
                layerAttention[h][t] = static_cast<float>(rand()) / RAND_MAX;
            }
        }
        m_attentionWeights[layer] = layerAttention;
        
        // Feature importance: top 50 features
        std::vector<float> layerImportance(50);
        for (int i = 0; i < 50; ++i) {
            layerImportance[i] = static_cast<float>(rand()) / RAND_MAX;
        }
        std::sort(layerImportance.rbegin(), layerImportance.rend());
        m_featureImportance[layer] = layerImportance;
        
        // Gradient flow: mean gradient per layer
        m_gradientFlow[layer] = static_cast<float>(rand()) / RAND_MAX;
        
        // Activation stats: mean, std, min, max
        ActivationStats stats;
        stats.mean = 0.5f;
        stats.stddev = 0.2f;
        stats.min = 0.0f;
        stats.max = 1.0f;
        m_activationStats[layer] = stats;
    }
}

/**
 * @brief InterpretabilityPanel::updateAttentionVisualization - Update attention heatmap
 */
void InterpretabilityPanel::updateAttentionVisualization(int layer, int head)
{
    qDebug() << "[InterpretabilityPanel] Updating attention visualization for layer" << layer << "head" << head;
    
    try {
        if (layer < 0 || layer >= m_maxLayers) {
            return;
        }
        
        if (head < 0 || head >= 12) {
            return;
        }
        
        // Get attention weights for this head
        const auto& attentionWeights = m_attentionWeights[layer][head];
        
        // Create bar series
        auto barSet = new QBarSet("Attention");
        for (size_t i = 0; i < std::min(attentionWeights.size(), size_t(32)); ++i) {
            *barSet << attentionWeights[i];
        }
        
        auto series = new QBarSeries();
        series->append(barSet);
        
        // Update chart
        if (m_visualizations.find(VisualizationType::AttentionHeatmap) != m_visualizations.end()) {
            auto chartView = qobject_cast<QChartView*>(m_visualizations[VisualizationType::AttentionHeatmap]);
            if (chartView) {
                auto chart = chartView->chart();
                chart->removeAllSeries();
                chart->addSeries(series);
                chart->createDefaultAxes();
            }
        }
        
        // Update stats
        updateStatistics(layer);
    }
    catch (const std::exception& e) {
        qCritical() << "[InterpretabilityPanel] Failed to update attention visualization:" << e.what();
    }
}

/**
 * @brief InterpretabilityPanel::updateFeatureImportance - Update feature importance ranking
 */
void InterpretabilityPanel::updateFeatureImportance(int layer)
{
    qDebug() << "[InterpretabilityPanel] Updating feature importance for layer" << layer;
    
    try {
        if (layer < 0 || layer >= m_maxLayers) {
            return;
        }
        
        const auto& importance = m_featureImportance[layer];
        
        // Create bar series
        auto barSet = new QBarSet("Importance");
        for (size_t i = 0; i < std::min(importance.size(), size_t(20)); ++i) {
            *barSet << importance[i];
        }
        
        auto series = new QBarSeries();
        series->append(barSet);
        
        // Update chart
        if (m_visualizations.find(VisualizationType::FeatureImportance) != m_visualizations.end()) {
            auto chartView = qobject_cast<QChartView*>(m_visualizations[VisualizationType::FeatureImportance]);
            if (chartView) {
                auto chart = chartView->chart();
                chart->removeAllSeries();
                chart->addSeries(series);
                chart->createDefaultAxes();
            }
        }
    }
    catch (const std::exception& e) {
        qCritical() << "[InterpretabilityPanel] Failed to update feature importance:" << e.what();
    }
}

/**
 * @brief InterpretabilityPanel::updateGradientFlow - Update gradient flow visualization
 */
void InterpretabilityPanel::updateGradientFlow()
{
    qDebug() << "[InterpretabilityPanel] Updating gradient flow";
    
    try {
        // Create line series with gradient magnitudes
        auto series = new QLineSeries();
        
        for (int layer = 0; layer < m_maxLayers; ++layer) {
            series->append(layer, m_gradientFlow[layer]);
        }
        
        // Update chart
        if (m_visualizations.find(VisualizationType::GradientFlow) != m_visualizations.end()) {
            auto chartView = qobject_cast<QChartView*>(m_visualizations[VisualizationType::GradientFlow]);
            if (chartView) {
                auto chart = chartView->chart();
                chart->removeAllSeries();
                chart->addSeries(series);
                chart->createDefaultAxes();
            }
        }
    }
    catch (const std::exception& e) {
        qCritical() << "[InterpretabilityPanel] Failed to update gradient flow:" << e.what();
    }
}

/**
 * @brief InterpretabilityPanel::updateActivationDistribution - Update activation stats
 */
void InterpretabilityPanel::updateActivationDistribution(int layer)
{
    qDebug() << "[InterpretabilityPanel] Updating activation distribution for layer" << layer;
    
    try {
        if (layer < 0 || layer >= m_maxLayers) {
            return;
        }
        
        const auto& stats = m_activationStats[layer];
        
        // Create bar series
        auto barSet = new QBarSet("Activation Stats");
        barSet->append(stats.mean);
        barSet->append(stats.stddev);
        barSet->append(stats.min);
        barSet->append(stats.max);
        
        auto series = new QBarSeries();
        series->append(barSet);
        
        // Update chart
        if (m_visualizations.find(VisualizationType::ActivationDistribution) != m_visualizations.end()) {
            auto chartView = qobject_cast<QChartView*>(m_visualizations[VisualizationType::ActivationDistribution]);
            if (chartView) {
                auto chart = chartView->chart();
                chart->removeAllSeries();
                chart->addSeries(series);
                chart->createDefaultAxes();
            }
        }
    }
    catch (const std::exception& e) {
        qCritical() << "[InterpretabilityPanel] Failed to update activation distribution:" << e.what();
    }
}

/**
 * @brief InterpretabilityPanel::updateStatistics - Update statistics label
 */
void InterpretabilityPanel::updateStatistics(int layer)
{
    if (layer < 0 || layer >= m_maxLayers) {
        return;
    }
    
    const auto& stats = m_activationStats[layer];
    
    QString statsText = QString("Layer %1 | Mean: %.4f | Std: %.4f | Min: %.4f | Max: %.4f | Updated: %2")
        .arg(layer)
        .arg(stats.mean)
        .arg(stats.stddev)
        .arg(stats.min)
        .arg(stats.max)
        .arg(QDateTime::currentDateTime().toString("hh:mm:ss"));
    
    if (m_statsLabel) {
        m_statsLabel->setText(statsText);
    }
}

/**
 * @brief InterpretabilityPanel::computeLayerAttribution - Compute layer-wise attribution
 */
std::vector<float> InterpretabilityPanel::computeLayerAttribution(
    const std::vector<std::vector<float>>& layerOutputs,
    const std::vector<std::vector<float>>& layerGradients)
{
    std::vector<float> attribution;
    
    if (layerOutputs.size() != layerGradients.size()) {
        return attribution;
    }
    
    for (size_t i = 0; i < layerOutputs.size(); ++i) {
        float score = 0.0f;
        
        for (size_t j = 0; j < layerOutputs[i].size(); ++j) {
            score += layerOutputs[i][j] * layerGradients[i][j];
        }
        
        attribution.push_back(score);
    }
    
    return attribution;
}

/**
 * @brief InterpretabilityPanel::computeIntegratedGradients - Compute integrated gradients
 */
std::vector<float> InterpretabilityPanel::computeIntegratedGradients(
    const std::vector<float>& baseline,
    const std::vector<float>& input,
    int steps)
{
    std::vector<float> integratedGradients(input.size(), 0.0f);
    
    for (int step = 0; step < steps; ++step) {
        // Interpolate between baseline and input
        float alpha = static_cast<float>(step) / steps;
        std::vector<float> interpolated(input.size());
        
        for (size_t i = 0; i < input.size(); ++i) {
            interpolated[i] = baseline[i] + alpha * (input[i] - baseline[i]);
        }
        
        // Compute gradients at interpolated point (mock)
        for (size_t i = 0; i < interpolated.size(); ++i) {
            integratedGradients[i] += interpolated[i] * 0.01f;  // Mock gradient
        }
    }
    
    // Riemann sum approximation
    for (auto& g : integratedGradients) {
        g = g * (input[0] - baseline[0]) / steps;
    }
    
    return integratedGradients;
}

/**
 * @brief InterpretabilityPanel::onVisualizationTypeChanged - Handle visualization type change
 */
void InterpretabilityPanel::onVisualizationTypeChanged(int index)
{
    m_currentVisualization = static_cast<VisualizationType>(index);
    qDebug() << "[InterpretabilityPanel] Visualization type changed to" << index;
}

/**
 * @brief InterpretabilityPanel::onLayerChanged - Handle layer selection change
 */
void InterpretabilityPanel::onLayerChanged(int layer)
{
    m_currentLayer = layer;
    
    switch (m_currentVisualization) {
        case VisualizationType::AttentionHeatmap:
            updateAttentionVisualization(layer, 0);
            break;
        case VisualizationType::FeatureImportance:
            updateFeatureImportance(layer);
            break;
        case VisualizationType::GradientFlow:
            updateGradientFlow();
            break;
        case VisualizationType::ActivationDistribution:
            updateActivationDistribution(layer);
            break;
        default:
            break;
    }
}

/**
 * @brief InterpretabilityPanel::onAttentionHeadChanged - Handle attention head selection
 */
void InterpretabilityPanel::onAttentionHeadChanged(int head)
{
    updateAttentionVisualization(m_currentLayer, head);
}

/**
 * @brief InterpretabilityPanel::exportVisualization - Export current visualization
 */
void InterpretabilityPanel::exportVisualization()
{
    qDebug() << "[InterpretabilityPanel] Exporting visualization";
    
    QJsonObject exportData;
    exportData["visualizationType"] = static_cast<int>(m_currentVisualization);
    exportData["layer"] = m_currentLayer;
    exportData["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    
    emit visualizationExported(exportData);
}
