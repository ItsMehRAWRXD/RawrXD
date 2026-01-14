/**
 * @file profiler_widget.h
 * @brief Full Performance Profiler widget for RawrXD IDE
 * @author RawrXD Team
 * 
 * This widget provides comprehensive profiling functionality including:
 * - CPU profiling with sampling and instrumentation
 * - Memory profiling with allocation tracking
 * - GPU profiling for graphics applications
 * - Flame graph visualization
 * - Call tree analysis
 * - Hot path identification
 * - perf/VTune/Instruments integration
 */

#pragma once

#include <QWidget>
#include <QDockWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QChartView>
#include <QLineSeries>
#include <QAreaSeries>
#include <QBarSeries>
#include <QTimer>
#include <QProcess>
#include <QElapsedTimer>
#include <QThread>
#include <QMutex>
#include <QSettings>
#include <QMap>
#include <QtCharts/QtCharts>

// No namespace wrapping - all classes use global scope
#include <memory>
#include <functional>

// using namespace QtCharts;

/**
 * @brief Sample data from profiler
 */
struct ProfileSample {
    quint64 timestamp = 0;      // nanoseconds
    quint64 address = 0;
    QString function;
    QString module;
    QString file;
    int line = 0;
    int threadId = 0;
    quint64 selfTime = 0;       // nanoseconds
    quint64 totalTime = 0;
    quint64 callCount = 0;
};

/**
 * @brief Memory allocation record
 */
struct MemoryAllocation {
    quint64 address = 0;
    quint64 size = 0;
    quint64 timestamp = 0;
    QString allocator;          // malloc, new, etc.
    QVector<QString> stackTrace;
    bool freed = false;
    quint64 freeTimestamp = 0;
};

/**
 * @brief Call tree node for hierarchical profiling
 */
struct CallTreeNode {
    QString function;
    QString module;
    quint64 selfTime = 0;
    quint64 totalTime = 0;
    quint64 callCount = 0;
    double selfPercent = 0.0;
    double totalPercent = 0.0;
    QVector<std::shared_ptr<CallTreeNode>> children;
    CallTreeNode* parent = nullptr;
};

/**
 * @brief Flame graph frame
 */
struct FlameFrame {
    QString name;
    quint64 value = 0;
    double x = 0.0;
    double width = 0.0;
    int depth = 0;
    QColor color;
    QVector<FlameFrame> children;
};

/**
 * @brief Profiling session configuration
 */
struct ProfileConfig {
    QString name;
    QString program;
    QStringList args;
    QString cwd;
    QString profilerType;       // "sampling", "instrumented", "memory", "gpu"
    int samplingRate = 1000;    // samples per second
    bool trackAllocations = true;
    bool trackFrees = true;
    bool collectStackTraces = true;
    int stackDepth = 64;
    QStringList symbolPaths;
    
    QJsonObject toJson() const;
    static ProfileConfig fromJson(const QJsonObject& obj);
};

/**
 * @enum ProfilerState
 * @brief Current state of the profiler
 */
enum class ProfilerState {
    Idle,
    Starting,
    Running,
    Stopping,
    Analyzing
};

/**
 * @class FlameGraphView
 * @brief Custom graphics view for flame graph visualization
 */
class FlameGraphView : public QGraphicsView {
    Q_OBJECT

public:
    explicit FlameGraphView(QWidget* parent = nullptr);
    
    void setData(const QVector<FlameFrame>& frames);
    void setRootFrame(const FlameFrame& root);
    void clear();
    
signals:
    void frameClicked(const QString& function);
    void frameHovered(const QString& function, quint64 value, double percent);

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    void rebuild();
    void addFrameRect(const FlameFrame& frame, int depth, double x, double totalWidth);
    QColor colorForFunction(const QString& function);
    
    QGraphicsScene* m_scene = nullptr;
    FlameFrame m_rootFrame;
    double m_scale = 1.0;
    QMap<QGraphicsItem*, FlameFrame> m_itemToFrame;
};

/**
 * @class ProfilerWidget
 * @brief Full-featured performance profiler widget
 */
class ProfilerWidget : public QWidget {
    Q_OBJECT

public:
    explicit ProfilerWidget(QWidget* parent = nullptr);
    ~ProfilerWidget() override;

    // Profiler control
    void startProfiling(const ProfileConfig& config);
    void stopProfiling();
    void pauseProfiling();
    void resumeProfiling();
    void clearData();
    
    // Data access
    QVector<ProfileSample> getSamples() const;
    QVector<MemoryAllocation> getAllocations() const;
    std::shared_ptr<CallTreeNode> getCallTree() const;
    
    // Analysis
    void analyzeHotSpots();
    void analyzeMemoryLeaks();
    void generateFlameGraph();
    void exportReport(const QString& path, const QString& format);
    
    // Configuration
    void setWorkingDirectory(const QString& dir);
    void addSymbolPath(const QString& path);
    QVector<ProfileConfig> getConfigs() const;
    void addConfig(const ProfileConfig& config);
    
    // State
    ProfilerState state() const { return m_state; }
    bool isRunning() const { return m_state == ProfilerState::Running; }

signals:
    void profilingStarted();
    void profilingStopped();
    void profilingPaused();
    void profilingResumed();
    void stateChanged(ProfilerState state);
    
    void sampleCollected(const ProfileSample& sample);
    void allocationTracked(const MemoryAllocation& alloc);
    void analysisComplete();
    void errorOccurred(const QString& error);
    
    void navigateToSource(const QString& file, int line);

public slots:
    void onConfigChanged(int index);
    void onFunctionDoubleClicked(QTreeWidgetItem* item, int column);
    void onFlameFrameClicked(const QString& function);
    void refreshViews();
    void toggleLiveUpdate(bool enabled);

private slots:
    void processProfilerOutput();
    void processProfilerError();
    void onProfilerFinished(int exitCode, QProcess::ExitStatus status);
    void updateLiveData();
    void parsePerfOutput(const QString& output);

private:
    void setupUI();
    void setupToolbar();
    void setupHotSpotsView();
    void setupCallTreeView();
    void setupFlameGraphView();
    void setupMemoryView();
    void setupTimelineView();
    void setupStatsPanel();
    
    // Profiler backends
    void startPerfProfiler(const ProfileConfig& config);
    void startSamplingProfiler(const ProfileConfig& config);
    void startInstrumentedProfiler(const ProfileConfig& config);
    void startMemoryProfiler(const ProfileConfig& config);
    
    // Data processing
    void processSample(const ProfileSample& sample);
    void buildCallTree();
    void buildFlameGraph();
    void calculateStatistics();
    
    // UI updates
    void updateHotSpotsView();
    void updateCallTreeView();
    void updateMemoryView();
    void updateTimelineChart();
    void updateStatsPanel();
    void setState(ProfilerState newState);
    
    // Symbol resolution
    QString resolveSymbol(quint64 address);
    void loadSymbols(const QString& path);

private:
    // UI Components
    QToolBar* m_toolbar = nullptr;
    QComboBox* m_configSelector = nullptr;
    QTabWidget* m_tabWidget = nullptr;
    QSplitter* m_mainSplitter = nullptr;
    
    // Views
    QTreeWidget* m_hotSpotsTree = nullptr;
    QTreeWidget* m_callTreeView = nullptr;
    FlameGraphView* m_flameGraphView = nullptr;
    QTreeWidget* m_memoryTree = nullptr;
    QChartView* m_timelineChart = nullptr;
    QTableWidget* m_statsTable = nullptr;
    
    // Charts
    QChart* m_cpuChart = nullptr;
    QLineSeries* m_cpuSeries = nullptr;
    QChart* m_memoryChart = nullptr;
    QAreaSeries* m_memorySeries = nullptr;
    
    // Action buttons
    QPushButton* m_startBtn = nullptr;
    QPushButton* m_stopBtn = nullptr;
    QPushButton* m_pauseBtn = nullptr;
    QPushButton* m_clearBtn = nullptr;
    QPushButton* m_exportBtn = nullptr;
    QCheckBox* m_liveUpdateCheck = nullptr;
    
    // Profiler process
    QProcess* m_profilerProcess = nullptr;
    QTimer* m_liveUpdateTimer = nullptr;
    QString m_outputBuffer;
    
    // Data
    QVector<ProfileConfig> m_configs;
    QVector<ProfileSample> m_samples;
    QVector<MemoryAllocation> m_allocations;
    std::shared_ptr<CallTreeNode> m_callTreeRoot;
    FlameFrame m_flameRoot;
    QMap<quint64, QString> m_symbolCache;
    
    // Statistics
    quint64 m_totalSamples = 0;
    quint64 m_totalTime = 0;
    quint64 m_peakMemory = 0;
    quint64 m_currentMemory = 0;
    quint64 m_totalAllocations = 0;
    quint64 m_totalFrees = 0;
    
    // State
    ProfilerState m_state = ProfilerState::Idle;
    ProfileConfig m_activeConfig;
    QString m_workingDirectory;
    QStringList m_symbolPaths;
    QElapsedTimer m_sessionTimer;
    bool m_liveUpdate = true;
    
    // Thread safety
    QMutex m_dataMutex;
    
    // Settings
    QSettings* m_settings = nullptr;
};

