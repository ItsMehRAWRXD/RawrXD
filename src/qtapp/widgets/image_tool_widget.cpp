/**
 * @file image_tool_widget.cpp
 * @brief Implementation of ImageToolWidget - image viewer and editor
 */

#include "image_tool_widget.h"
#include <QApplication>
#include <QClipboard>
#include <QInputDialog>
#include <QColorDialog>
#include <QTextStream>
#include <QStandardPaths>
#include <QDirIterator>
#include <QImageReader>
#include <QImageWriter>
#include <QBuffer>
#include <QMouseEvent>
#include <QDebug>
#include <cmath>
#include <algorithm>

// ============================================================================
// ImageGraphicsView Implementation
// ============================================================================

ImageGraphicsView::ImageGraphicsView(QWidget* parent)
    : QGraphicsView(parent)
    , m_scene(new QGraphicsScene(this))
    , m_pixmapItem(nullptr)
    , m_selectionRect(nullptr)
    , m_zoomFactor(1.0)
    , m_selectionMode(false)
    , m_selecting(false)
{
    setScene(m_scene);
    setRenderHint(QPainter::Antialiasing);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setBackgroundBrush(QBrush(QColor(64, 64, 64)));
    setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    
    // Create selection rectangle
    m_selectionRect = new QGraphicsRectItem();
    m_selectionRect->setPen(QPen(Qt::red, 1, Qt::DashLine));
    m_selectionRect->setBrush(QBrush(QColor(255, 0, 0, 50)));
    m_selectionRect->setVisible(false);
    m_scene->addItem(m_selectionRect);
}

void ImageGraphicsView::setImage(const QImage& image)
{
    if (m_pixmapItem) {
        m_scene->removeItem(m_pixmapItem);
        delete m_pixmapItem;
    }
    
    m_pixmapItem = new QGraphicsPixmapItem(QPixmap::fromImage(image));
    m_scene->addItem(m_pixmapItem);
    m_scene->setSceneRect(m_pixmapItem->boundingRect());
    
    // Reset zoom and center
    resetZoom();
    centerOn(m_pixmapItem);
}

QImage ImageGraphicsView::getImage() const
{
    return m_pixmapItem ? m_pixmapItem->pixmap().toImage() : QImage();
}

void ImageGraphicsView::zoomIn()
{
    setZoom(m_zoomFactor * (1.0 + ZOOM_STEP));
}

void ImageGraphicsView::zoomOut()
{
    setZoom(m_zoomFactor * (1.0 - ZOOM_STEP));
}

void ImageGraphicsView::zoomToFit()
{
    if (!m_pixmapItem) return;
    
    QRectF viewRect = viewport()->rect();
    QRectF imageRect = m_pixmapItem->boundingRect();
    
    qreal scaleX = viewRect.width() / imageRect.width();
    qreal scaleY = viewRect.height() / imageRect.height();
    qreal scale = qMin(scaleX, scaleY) * 0.95; // Leave some margin
    
    setZoom(scale);
    centerOn(m_pixmapItem);
}

void ImageGraphicsView::resetZoom()
{
    setZoom(1.0);
}

void ImageGraphicsView::setZoom(qreal factor)
{
    m_zoomFactor = qBound(MIN_ZOOM, factor, MAX_ZOOM);
    
    QTransform transform;
    transform.scale(m_zoomFactor, m_zoomFactor);
    setTransform(transform);
    
    emit zoomChanged(m_zoomFactor);
}

qreal ImageGraphicsView::getZoom() const
{
    return m_zoomFactor;
}

void ImageGraphicsView::setSelectionRect(const QRectF& rect)
{
    if (rect.isValid()) {
        m_selectionRect->setRect(rect);
        m_selectionRect->setVisible(true);
    } else {
        m_selectionRect->setVisible(false);
    }
}

QRectF ImageGraphicsView::getSelectionRect() const
{
    return m_selectionRect->isVisible() ? m_selectionRect->rect() : QRectF();
}

void ImageGraphicsView::clearSelection()
{
    m_selectionRect->setVisible(false);
}

void ImageGraphicsView::setSelectionMode(bool enabled)
{
    m_selectionMode = enabled;
    setDragMode(enabled ? QGraphicsView::NoDrag : QGraphicsView::ScrollHandDrag);
    if (!enabled) {
        clearSelection();
    }
}

bool ImageGraphicsView::isSelectionMode() const
{
    return m_selectionMode;
}

void ImageGraphicsView::wheelEvent(QWheelEvent* event)
{
    if (event->modifiers() & Qt::ControlModifier) {
        if (event->angleDelta().y() > 0) {
            zoomIn();
        } else {
            zoomOut();
        }
        event->accept();
    } else {
        QGraphicsView::wheelEvent(event);
    }
}

void ImageGraphicsView::mousePressEvent(QMouseEvent* event)
{
    if (m_selectionMode && event->button() == Qt::LeftButton) {
        m_selecting = true;
        m_selectionStart = mapToScene(event->pos());
        clearSelection();
        event->accept();
    } else if (event->button() == Qt::LeftButton) {
        emit imageClicked(mapToScene(event->pos()));
        QGraphicsView::mousePressEvent(event);
    } else {
        QGraphicsView::mousePressEvent(event);
    }
}

void ImageGraphicsView::mouseMoveEvent(QMouseEvent* event)
{
    if (m_selecting) {
        QPointF currentPos = mapToScene(event->pos());
        QRectF selectionRect(m_selectionStart, currentPos);
        setSelectionRect(selectionRect.normalized());
        event->accept();
    } else {
        QGraphicsView::mouseMoveEvent(event);
    }
}

void ImageGraphicsView::mouseReleaseEvent(QMouseEvent* event)
{
    if (m_selecting && event->button() == Qt::LeftButton) {
        m_selecting = false;
        QRectF selection = getSelectionRect();
        if (selection.isValid() && selection.width() > 1 && selection.height() > 1) {
            emit selectionChanged(selection);
        }
        event->accept();
    } else {
        QGraphicsView::mouseReleaseEvent(event);
    }
}

void ImageGraphicsView::resizeEvent(QResizeEvent* event)
{
    QGraphicsView::resizeEvent(event);
    // Could implement auto-fit on resize here
}

// ============================================================================
// ImageProcessor Implementation
// ============================================================================

ImageProcessor::ImageProcessor(QObject* parent)
    : QObject(parent)
    , m_cancelled(false)
{
}

void ImageProcessor::processImage(const QImage& input, const QList<ImageOperation>& operations, const QVariantMap& params)
{
    QMutexLocker locker(&m_mutex);
    m_cancelled = false;
    locker.unlock();
    
    QImage result = input;
    
    for (ImageOperation op : operations) {
        if (m_cancelled) {
            emit error("Processing cancelled");
            return;
        }
        
        result = applyOperation(result, op, params);
    }
    
    emit processingFinished(result);
}

void ImageProcessor::processBatch(const QList<ImageTask>& tasks)
{
    QMutexLocker locker(&m_mutex);
    m_cancelled = false;
    locker.unlock();
    
    for (int i = 0; i < tasks.size(); ++i) {
        if (m_cancelled) {
            emit error("Batch processing cancelled");
            return;
        }
        
        const ImageTask& task = tasks[i];
        emit batchProgress(i, tasks.size(), task.inputPath);
        
        QImage input(task.inputPath);
        if (input.isNull()) {
            emit error(QString("Failed to load image: %1").arg(task.inputPath));
            continue;
        }
        
        QImage result = input;
        for (ImageOperation op : task.operations) {
            result = applyOperation(result, op, task.parameters);
        }
        
        if (!result.save(task.outputPath)) {
            emit error(QString("Failed to save image: %1").arg(task.outputPath));
        }
    }
    
    emit batchFinished();
}

void ImageProcessor::cancel()
{
    QMutexLocker locker(&m_mutex);
    m_cancelled = true;
}

QImage ImageProcessor::applyOperation(const QImage& image, ImageOperation op, const QVariantMap& params)
{
    switch (op) {
        case ImageOperation::Crop:
            return cropImage(image, params.value("rect").toRect());
        case ImageOperation::Resize:
            return resizeImage(image, params.value("size").toSize(), params.value("keepAspect", true).toBool());
        case ImageOperation::Rotate:
            return rotateImage(image, params.value("angle", 0.0).toDouble());
        case ImageOperation::FlipHorizontal:
            return flipImage(image, true);
        case ImageOperation::FlipVertical:
            return flipImage(image, false);
        case ImageOperation::BrightnessContrast:
            return adjustBrightnessContrast(image, 
                                          params.value("brightness", 0).toInt(),
                                          params.value("contrast", 0).toInt());
        case ImageOperation::HueSaturation:
            return adjustHueSaturation(image,
                                     params.value("hue", 0).toInt(),
                                     params.value("saturation", 0).toInt());
        case ImageOperation::Sharpen:
            return sharpenImage(image, params.value("factor", 1.0).toDouble());
        case ImageOperation::Blur:
            return blurImage(image, params.value("radius", 1.0).toDouble());
        default:
            return image;
    }
}

QImage ImageProcessor::cropImage(const QImage& image, const QRect& rect)
{
    if (!rect.isValid() || rect.isEmpty()) {
        return image;
    }
    
    return image.copy(rect);
}

QImage ImageProcessor::resizeImage(const QImage& image, const QSize& size, bool keepAspect)
{
    if (size.isEmpty()) {
        return image;
    }
    
    Qt::AspectRatioMode mode = keepAspect ? Qt::KeepAspectRatio : Qt::IgnoreAspectRatio;
    return image.scaled(size, mode, Qt::SmoothTransformation);
}

QImage ImageProcessor::rotateImage(const QImage& image, qreal angle)
{
    if (qFuzzyCompare(angle, 0.0)) {
        return image;
    }
    
    QTransform transform;
    transform.rotate(angle);
    
    return image.transformed(transform, Qt::SmoothTransformation);
}

QImage ImageProcessor::flipImage(const QImage& image, bool horizontal)
{
    return image.mirrored(horizontal, !horizontal);
}

QImage ImageProcessor::adjustBrightnessContrast(const QImage& image, int brightness, int contrast)
{
    if (brightness == 0 && contrast == 0) {
        return image;
    }
    
    QImage result = image;
    
    // Apply brightness and contrast adjustment
    for (int y = 0; y < result.height(); ++y) {
        for (int x = 0; x < result.width(); ++x) {
            QColor color = result.pixelColor(x, y);
            
            // Adjust brightness
            int r = qBound(0, color.red() + brightness, 255);
            int g = qBound(0, color.green() + brightness, 255);
            int b = qBound(0, color.blue() + brightness, 255);
            
            // Adjust contrast
            if (contrast != 0) {
                float factor = (259.0f * (contrast + 255.0f)) / (255.0f * (259.0f - contrast));
                r = qBound(0, static_cast<int>(factor * (r - 128) + 128), 255);
                g = qBound(0, static_cast<int>(factor * (g - 128) + 128), 255);
                b = qBound(0, static_cast<int>(factor * (b - 128) + 128), 255);
            }
            
            result.setPixelColor(x, y, QColor(r, g, b));
        }
    }
    
    return result;
}

QImage ImageProcessor::adjustHueSaturation(const QImage& image, int hue, int saturation)
{
    if (hue == 0 && saturation == 0) {
        return image;
    }
    
    QImage result = image;
    
    for (int y = 0; y < result.height(); ++y) {
        for (int x = 0; x < result.width(); ++x) {
            QColor color = result.pixelColor(x, y);
            
            // Convert to HSV
            int h, s, v;
            color.getHsv(&h, &s, &v);
            
            // Adjust hue and saturation
            h = (h + hue) % 360;
            s = qBound(0, s + saturation, 255);
            
            color.setHsv(h, s, v);
            result.setPixelColor(x, y, color);
        }
    }
    
    return result;
}

QImage ImageProcessor::sharpenImage(const QImage& image, qreal factor)
{
    if (qFuzzyCompare(factor, 0.0)) {
        return image;
    }
    
    QImage result = image;
    
    // Simple sharpening using unsharp mask
    QImage blurred = blurImage(image, 1.0);
    
    for (int y = 0; y < result.height(); ++y) {
        for (int x = 0; x < result.width(); ++x) {
            QColor original = image.pixelColor(x, y);
            QColor blurredColor = blurred.pixelColor(x, y);
            
            int r = qBound(0, original.red() + static_cast<int>(factor * (original.red() - blurredColor.red())), 255);
            int g = qBound(0, original.green() + static_cast<int>(factor * (original.green() - blurredColor.green())), 255);
            int b = qBound(0, original.blue() + static_cast<int>(factor * (original.blue() - blurredColor.blue())), 255);
            
            result.setPixelColor(x, y, QColor(r, g, b));
        }
    }
    
    return result;
}

QImage ImageProcessor::blurImage(const QImage& image, qreal radius)
{
    if (qFuzzyCompare(radius, 0.0)) {
        return image;
    }
    
    // Simple box blur implementation
    QImage result = image;
    int kernelSize = static_cast<int>(radius * 2) + 1;
    
    for (int y = 0; y < result.height(); ++y) {
        for (int x = 0; x < result.width(); ++x) {
            int r = 0, g = 0, b = 0, count = 0;
            
            for (int ky = -kernelSize/2; ky <= kernelSize/2; ++ky) {
                for (int kx = -kernelSize/2; kx <= kernelSize/2; ++kx) {
                    int px = qBound(0, x + kx, result.width() - 1);
                    int py = qBound(0, y + ky, result.height() - 1);
                    
                    QColor color = result.pixelColor(px, py);
                    r += color.red();
                    g += color.green();
                    b += color.blue();
                    count++;
                }
            }
            
            result.setPixelColor(x, y, QColor(r/count, g/count, b/count));
        }
    }
    
    return result;
}

// ============================================================================
// ImageToolWidget Implementation
// ============================================================================

ImageToolWidget::ImageToolWidget(QWidget* parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_toolbar(nullptr)
    , m_splitter(nullptr)
    , m_openAction(nullptr)
    , m_saveAction(nullptr)
    , m_exportAction(nullptr)
    , m_batchAction(nullptr)
    , m_undoAction(nullptr)
    , m_redoAction(nullptr)
    , m_zoomInAction(nullptr)
    , m_zoomOutAction(nullptr)
    , m_zoomFitAction(nullptr)
    , m_cropAction(nullptr)
    , m_resizeAction(nullptr)
    , m_rotateAction(nullptr)
    , m_flipHAction(nullptr)
    , m_flipVAction(nullptr)
    , m_brightnessAction(nullptr)
    , m_metadataAction(nullptr)
    , m_histogramAction(nullptr)
    , m_operationCombo(nullptr)
    , m_zoomSlider(nullptr)
    , m_zoomLabel(nullptr)
    , m_sizeLabel(nullptr)
    , m_formatLabel(nullptr)
    , m_sidebarTabs(nullptr)
    , m_metadataTree(nullptr)
    , m_histogramWidget(nullptr)
    , m_historyList(nullptr)
    , m_imageView(nullptr)
    , m_historyIndex(-1)
    , m_processor(std::make_unique<ImageProcessor>())
    , m_processorThread(nullptr)
    , m_modified(false)
    , m_currentOperation(ImageOperation::None)
{
    setupUI();
    setupConnections();
    
    updateWindowTitle();
    
    qDebug() << "ImageToolWidget initialized";
}

ImageToolWidget::~ImageToolWidget()
{
    if (m_processorThread) {
        m_processor->cancel();
        m_processorThread->quit();
        m_processorThread->wait();
    }
}

void ImageToolWidget::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setContentsMargins(0, 0, 0, 0);
    m_mainLayout->setSpacing(0);
    
    setupToolbar();
    
    m_splitter = new QSplitter(Qt::Horizontal, this);
    m_mainLayout->addWidget(m_splitter);
    
    setupSidebar();
    setupImageView();
    
    // Status bar area
    QWidget* statusWidget = new QWidget(this);
    QHBoxLayout* statusLayout = new QHBoxLayout(statusWidget);
    statusLayout->setContentsMargins(4, 2, 4, 2);
    
    m_sizeLabel = new QLabel("No image loaded", statusWidget);
    m_formatLabel = new QLabel("", statusWidget);
    
    statusLayout->addWidget(m_sizeLabel);
    statusLayout->addStretch();
    statusLayout->addWidget(m_formatLabel);
    
    m_mainLayout->addWidget(statusWidget);
    
    // Set initial splitter sizes
    m_splitter->setSizes({200, 600});
}

void ImageToolWidget::setupToolbar()
{
    m_toolbar = new QToolBar(tr("Image"), this);
    m_toolbar->setIconSize(QSize(18, 18));
    m_mainLayout->addWidget(m_toolbar);
    
    // File actions
    m_openAction = m_toolbar->addAction(QIcon::fromTheme("document-open", QIcon(":/icons/open.png")), tr("Open"));
    m_saveAction = m_toolbar->addAction(QIcon::fromTheme("document-save", QIcon(":/icons/save.png")), tr("Save"));
    m_exportAction = m_toolbar->addAction(QIcon::fromTheme("document-export", QIcon(":/icons/export.png")), tr("Export"));
    m_batchAction = m_toolbar->addAction(QIcon::fromTheme("system-run", QIcon(":/icons/batch.png")), tr("Batch Process"));
    
    m_toolbar->addSeparator();
    
    // Edit actions
    m_undoAction = m_toolbar->addAction(QIcon::fromTheme("edit-undo", QIcon(":/icons/undo.png")), tr("Undo"));
    m_undoAction->setShortcut(QKeySequence::Undo);
    m_undoAction->setEnabled(false);
    
    m_redoAction = m_toolbar->addAction(QIcon::fromTheme("edit-redo", QIcon(":/icons/redo.png")), tr("Redo"));
    m_redoAction->setShortcut(QKeySequence::Redo);
    m_redoAction->setEnabled(false);
    
    m_toolbar->addSeparator();
    
    // View actions
    m_zoomOutAction = m_toolbar->addAction(QIcon::fromTheme("zoom-out", QIcon(":/icons/zoom-out.png")), tr("Zoom Out"));
    m_zoomSlider = new QSlider(Qt::Horizontal, this);
    m_zoomSlider->setRange(10, 500);
    m_zoomSlider->setValue(100);
    m_zoomSlider->setMaximumWidth(100);
    m_toolbar->addWidget(m_zoomSlider);
    
    m_zoomInAction = m_toolbar->addAction(QIcon::fromTheme("zoom-in", QIcon(":/icons/zoom-in.png")), tr("Zoom In"));
    m_zoomFitAction = m_toolbar->addAction(QIcon::fromTheme("zoom-fit-best", QIcon(":/icons/zoom-fit.png")), tr("Zoom to Fit"));
    
    m_zoomLabel = new QLabel("100%", this);
    m_zoomLabel->setMinimumWidth(40);
    m_toolbar->addWidget(m_zoomLabel);
    
    m_toolbar->addSeparator();
    
    // Operation combo
    m_operationCombo = new QComboBox(this);
    m_operationCombo->addItem(tr("Select Operation"), static_cast<int>(ImageOperation::None));
    m_operationCombo->addItem(tr("Crop"), static_cast<int>(ImageOperation::Crop));
    m_operationCombo->addItem(tr("Resize"), static_cast<int>(ImageOperation::Resize));
    m_operationCombo->addItem(tr("Rotate"), static_cast<int>(ImageOperation::Rotate));
    m_operationCombo->addItem(tr("Flip Horizontal"), static_cast<int>(ImageOperation::FlipHorizontal));
    m_operationCombo->addItem(tr("Flip Vertical"), static_cast<int>(ImageOperation::FlipVertical));
    m_operationCombo->addItem(tr("Brightness/Contrast"), static_cast<int>(ImageOperation::BrightnessContrast));
    m_operationCombo->addItem(tr("Hue/Saturation"), static_cast<int>(ImageOperation::HueSaturation));
    m_operationCombo->addItem(tr("Sharpen"), static_cast<int>(ImageOperation::Sharpen));
    m_operationCombo->addItem(tr("Blur"), static_cast<int>(ImageOperation::Blur));
    m_toolbar->addWidget(m_operationCombo);
    
    m_toolbar->addSeparator();
    
    // Tool actions
    m_cropAction = m_toolbar->addAction(QIcon::fromTheme("transform-crop", QIcon(":/icons/crop.png")), tr("Crop"));
    m_resizeAction = m_toolbar->addAction(QIcon::fromTheme("transform-scale", QIcon(":/icons/resize.png")), tr("Resize"));
    m_rotateAction = m_toolbar->addAction(QIcon::fromTheme("transform-rotate", QIcon(":/icons/rotate.png")), tr("Rotate"));
    m_flipHAction = m_toolbar->addAction(QIcon::fromTheme("object-flip-horizontal", QIcon(":/icons/flip-h.png")), tr("Flip H"));
    m_flipVAction = m_toolbar->addAction(QIcon::fromTheme("object-flip-vertical", QIcon(":/icons/flip-v.png")), tr("Flip V"));
    m_brightnessAction = m_toolbar->addAction(QIcon::fromTheme("color-management", QIcon(":/icons/brightness.png")), tr("Adjust"));
    
    m_toolbar->addSeparator();
    
    // Info actions
    m_metadataAction = m_toolbar->addAction(QIcon::fromTheme("document-properties", QIcon(":/icons/metadata.png")), tr("Metadata"));
    m_histogramAction = m_toolbar->addAction(QIcon::fromTheme("view-object-histogram", QIcon(":/icons/histogram.png")), tr("Histogram"));
}

void ImageToolWidget::setupSidebar()
{
    m_sidebarTabs = new QTabWidget(this);
    m_splitter->addWidget(m_sidebarTabs);
    
    // Metadata tree
    m_metadataTree = new QTreeWidget(this);
    m_metadataTree->setHeaderLabel(tr("Metadata"));
    m_metadataTree->setRootIsDecorated(false);
    m_sidebarTabs->addTab(m_metadataTree, tr("Metadata"));
    
    // Histogram widget
    m_histogramWidget = new QWidget(this);
    QVBoxLayout* histogramLayout = new QVBoxLayout(m_histogramWidget);
    histogramLayout->addWidget(new QLabel(tr("Histogram not implemented yet")));
    m_sidebarTabs->addTab(m_histogramWidget, tr("Histogram"));
    
    // History list
    m_historyList = new QListWidget(this);
    m_historyList->setAlternatingRowColors(true);
    m_sidebarTabs->addTab(m_historyList, tr("History"));
}

void ImageToolWidget::setupImageView()
{
    m_imageView = new ImageGraphicsView(this);
    m_splitter->addWidget(m_imageView);
}

void ImageToolWidget::setupConnections()
{
    // File actions
    connect(m_openAction, &QAction::triggered, this, &ImageToolWidget::onOpenAction);
    connect(m_saveAction, &QAction::triggered, this, &ImageToolWidget::onSaveAction);
    connect(m_exportAction, &QAction::triggered, this, &ImageToolWidget::onExportAction);
    connect(m_batchAction, &QAction::triggered, this, &ImageToolWidget::onBatchProcessAction);
    
    // Edit actions
    connect(m_undoAction, &QAction::triggered, this, &ImageToolWidget::undo);
    connect(m_redoAction, &QAction::triggered, this, &ImageToolWidget::redo);
    
    // View actions
    connect(m_zoomInAction, &QAction::triggered, this, &ImageToolWidget::zoomIn);
    connect(m_zoomOutAction, &QAction::triggered, this, &ImageToolWidget::zoomOut);
    connect(m_zoomFitAction, &QAction::triggered, this, &ImageToolWidget::zoomToFit);
    connect(m_zoomSlider, &QSlider::valueChanged, this, [this](int value) {
        setZoom(value / 100.0);
    });
    
    // Operation actions
    connect(m_cropAction, &QAction::triggered, this, &ImageToolWidget::cropToSelection);
    connect(m_resizeAction, &QAction::triggered, this, [this]() {
        bool ok;
        QString sizeStr = QInputDialog::getText(this, tr("Resize Image"), 
                                             tr("Enter new size (width x height):"), 
                                             QLineEdit::Normal, 
                                             QString("%1x%2").arg(m_currentImage.width()).arg(m_currentImage.height()), 
                                             &ok);
        QStringList sizeParts = sizeStr.split('x');
        if (ok && sizeParts.size() >= 2) {
            QVariantMap params;
            params["size"] = QSize(sizeParts[0].toInt(), sizeParts[1].toInt());
            applyOperation(ImageOperation::Resize, params);
        }
    });
    
    connect(m_rotateAction, &QAction::triggered, this, [this]() {
        QStringList angles = {"90", "180", "270", "-90"};
        bool ok;
        QString angleStr = QInputDialog::getItem(this, tr("Rotate Image"), 
                                                tr("Rotation angle:"), angles, 0, false, &ok);
        if (ok) {
            QVariantMap params;
            params["angle"] = angleStr.toDouble();
            applyOperation(ImageOperation::Rotate, params);
        }
    });
    
    connect(m_flipHAction, &QAction::triggered, this, [this]() {
        applyOperation(ImageOperation::FlipHorizontal);
    });
    
    connect(m_flipVAction, &QAction::triggered, this, [this]() {
        applyOperation(ImageOperation::FlipVertical);
    });
    
    connect(m_brightnessAction, &QAction::triggered, this, [this]() {
        // Simple brightness/contrast dialog
        bool ok;
        int brightness = QInputDialog::getInt(this, tr("Adjust Brightness"), 
                                            tr("Brightness (-255 to 255):"), 0, -255, 255, 1, &ok);
        if (ok) {
            int contrast = QInputDialog::getInt(this, tr("Adjust Contrast"), 
                                               tr("Contrast (-255 to 255):"), 0, -255, 255, 1, &ok);
            if (ok) {
                QVariantMap params;
                params["brightness"] = brightness;
                params["contrast"] = contrast;
                applyOperation(ImageOperation::BrightnessContrast, params);
            }
        }
    });
    
    // Info actions
    connect(m_metadataAction, &QAction::triggered, this, &ImageToolWidget::showMetadata);
    connect(m_histogramAction, &QAction::triggered, this, &ImageToolWidget::showHistogram);
    
    // Operation combo
    connect(m_operationCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        ImageOperation op = static_cast<ImageOperation>(m_operationCombo->itemData(index).toInt());
        m_currentOperation = op;
        
        // Enable/disable selection mode based on operation
        setSelectionMode(op == ImageOperation::Crop);
    });
    
    // Image view connections
    connect(m_imageView, &ImageGraphicsView::zoomChanged, this, &ImageToolWidget::onZoomChanged);
    connect(m_imageView, &ImageGraphicsView::selectionChanged, this, &ImageToolWidget::onSelectionChanged);
    connect(m_imageView, &ImageGraphicsView::imageClicked, this, &ImageToolWidget::onImageClicked);
    
    // Processor connections
    connect(m_processor.get(), &ImageProcessor::processingFinished, this, &ImageToolWidget::onProcessingFinished);
    connect(m_processor.get(), &ImageProcessor::batchProgress, this, &ImageToolWidget::onBatchProgress);
    connect(m_processor.get(), &ImageProcessor::batchFinished, this, &ImageToolWidget::onBatchFinished);
    connect(m_processor.get(), &ImageProcessor::error, this, &ImageToolWidget::onError);
    
    // Context menu
    m_imageView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_imageView, &QWidget::customContextMenuRequested, this, &ImageToolWidget::showContextMenu);
}

bool ImageToolWidget::openImage(const QString& filePath)
{
    QImage image(filePath);
    if (image.isNull()) {
        emit error(tr("Failed to load image: %1").arg(filePath));
        return false;
    }
    
    m_currentImage = image;
    m_originalImage = image;
    m_currentFilePath = filePath;
    m_modified = false;
    
    m_imageView->setImage(m_currentImage);
    m_metadata = extractMetadata(filePath);
    updateMetadataPanel();
    updateWindowTitle();
    
    // Clear history and add original
    m_history.clear();
    m_historyIndex = -1;
    pushToHistory(m_currentImage);
    
    m_sizeLabel->setText(QString("%1 x %2").arg(image.width()).arg(image.height()));
    m_formatLabel->setText(QFileInfo(filePath).suffix().toUpper());
    
    emit imageLoaded(filePath);
    return true;
}

bool ImageToolWidget::saveImage(const QString& filePath)
{
    if (m_currentImage.isNull()) {
        return false;
    }
    
    if (!m_currentImage.save(filePath)) {
        emit error(tr("Failed to save image: %1").arg(filePath));
        return false;
    }
    
    m_currentFilePath = filePath;
    m_modified = false;
    updateWindowTitle();
    
    emit imageSaved(filePath);
    return true;
}

void ImageToolWidget::exportImage(const QString& filePath, ImageFormat format)
{
    if (m_currentImage.isNull()) {
        return;
    }
    
    // For now, just save with the requested format
    // In production, would handle format-specific options
    QString extension;
    switch (format) {
        case ImageFormat::PNG: extension = "png"; break;
        case ImageFormat::JPEG: extension = "jpg"; break;
        case ImageFormat::BMP: extension = "bmp"; break;
        case ImageFormat::TIFF: extension = "tiff"; break;
        case ImageFormat::GIF: extension = "gif"; break;
        case ImageFormat::WebP: extension = "webp"; break;
        case ImageFormat::ICO: extension = "ico"; break;
    }
    
    QString fullPath = filePath;
    if (!fullPath.endsWith("." + extension)) {
        fullPath += "." + extension;
    }
    
    if (!m_currentImage.save(fullPath)) {
        emit error(tr("Failed to export image: %1").arg(fullPath));
    }
}

void ImageToolWidget::applyOperation(ImageOperation operation, const QVariantMap& params)
{
    if (m_currentImage.isNull()) {
        return;
    }
    
    // Move processor to thread if not already
    if (!m_processorThread) {
        m_processorThread = new QThread(this);
        m_processor->moveToThread(m_processorThread);
        m_processorThread->start();
    }
    
    // Apply operation asynchronously
    QMetaObject::invokeMethod(m_processor.get(), "processImage", 
                            Qt::QueuedConnection,
                            Q_ARG(QImage, m_currentImage),
                            Q_ARG(QList<ImageOperation>, QList<ImageOperation>() << operation),
                            Q_ARG(QVariantMap, params));
    
    m_modified = true;
    updateWindowTitle();
}

void ImageToolWidget::undo()
{
    if (!canUndo()) return;
    
    m_historyIndex--;
    m_currentImage = m_history[m_historyIndex];
    m_imageView->setImage(m_currentImage);
    updateUndoRedoActions();
    m_modified = true;
    updateWindowTitle();
}

void ImageToolWidget::redo()
{
    if (!canRedo()) return;
    
    m_historyIndex++;
    m_currentImage = m_history[m_historyIndex];
    m_imageView->setImage(m_currentImage);
    updateUndoRedoActions();
    m_modified = true;
    updateWindowTitle();
}

bool ImageToolWidget::canUndo() const
{
    return m_historyIndex > 0;
}

bool ImageToolWidget::canRedo() const
{
    return m_historyIndex < m_history.size() - 1;
}

void ImageToolWidget::zoomIn()
{
    m_imageView->zoomIn();
}

void ImageToolWidget::zoomOut()
{
    m_imageView->zoomOut();
}

void ImageToolWidget::zoomToFit()
{
    m_imageView->zoomToFit();
}

void ImageToolWidget::resetZoom()
{
    m_imageView->resetZoom();
}

void ImageToolWidget::setZoom(qreal factor)
{
    m_imageView->setZoom(factor);
}

qreal ImageToolWidget::getZoom() const
{
    return m_imageView->getZoom();
}

void ImageToolWidget::setSelectionMode(bool enabled)
{
    m_imageView->setSelectionMode(enabled);
}

void ImageToolWidget::cropToSelection()
{
    QRectF selection = m_imageView->getSelectionRect();
    if (selection.isValid()) {
        QVariantMap params;
        params["rect"] = selection.toRect();
        applyOperation(ImageOperation::Crop, params);
        m_imageView->clearSelection();
    }
}

void ImageToolWidget::clearSelection()
{
    m_imageView->clearSelection();
}

void ImageToolWidget::processBatch(const QList<ImageTask>& tasks)
{
    if (!m_processorThread) {
        m_processorThread = new QThread(this);
        m_processor->moveToThread(m_processorThread);
        m_processorThread->start();
    }
    
    QMetaObject::invokeMethod(m_processor.get(), "processBatch", 
                            Qt::QueuedConnection,
                            Q_ARG(QList<ImageTask>, tasks));
}

void ImageToolWidget::cancelBatch()
{
    if (m_processor) {
        m_processor->cancel();
    }
}

QList<ImageMetadata> ImageToolWidget::getMetadata() const
{
    return m_metadata;
}

void ImageToolWidget::setMetadata(const QList<ImageMetadata>& metadata)
{
    m_metadata = metadata;
    updateMetadataPanel();
}

void ImageToolWidget::saveState(QSettings& settings)
{
    settings.beginGroup("ImageToolWidget");
    settings.setValue("splitterSizes", m_splitter->saveState());
    settings.setValue("zoomFactor", getZoom());
    settings.setValue("sidebarTab", m_sidebarTabs->currentIndex());
    settings.setValue("currentOperation", static_cast<int>(m_currentOperation));
    settings.endGroup();
}

void ImageToolWidget::restoreState(QSettings& settings)
{
    settings.beginGroup("ImageToolWidget");
    
    if (settings.contains("splitterSizes")) {
        m_splitter->restoreState(settings.value("splitterSizes").toByteArray());
    }
    
    qreal zoomFactor = settings.value("zoomFactor", 1.0).toDouble();
    setZoom(zoomFactor);
    
    m_sidebarTabs->setCurrentIndex(settings.value("sidebarTab", 0).toInt());
    
    m_currentOperation = static_cast<ImageOperation>(settings.value("currentOperation", static_cast<int>(ImageOperation::None)).toInt());
    m_operationCombo->setCurrentIndex(static_cast<int>(m_currentOperation));
    
    settings.endGroup();
}

void ImageToolWidget::refresh()
{
    if (!m_currentFilePath.isEmpty()) {
        openImage(m_currentFilePath);
    }
}

void ImageToolWidget::showMetadata()
{
    m_sidebarTabs->setCurrentWidget(m_metadataTree);
}

void ImageToolWidget::showHistogram()
{
    m_sidebarTabs->setCurrentWidget(m_histogramWidget);
}

void ImageToolWidget::onOpenAction()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open Image"), 
                                                  QString(), 
                                                  tr("Images (*.png *.jpg *.jpeg *.bmp *.tiff *.gif *.webp);;All files (*)"));
    if (!fileName.isEmpty()) {
        openImage(fileName);
    }
}

void ImageToolWidget::onSaveAction()
{
    if (m_currentFilePath.isEmpty()) {
        onExportAction();
        return;
    }
    
    saveImage(m_currentFilePath);
}

void ImageToolWidget::onExportAction()
{
    if (m_currentImage.isNull()) return;
    
    QString fileName = QFileDialog::getSaveFileName(this, tr("Export Image"), 
                                                  QString(), 
                                                  tr("PNG files (*.png);;JPEG files (*.jpg);;BMP files (*.bmp);;TIFF files (*.tiff);;GIF files (*.gif);;WebP files (*.webp);;ICO files (*.ico);;All files (*)"));
    if (!fileName.isEmpty()) {
        QString extension = QFileInfo(fileName).suffix().toLower();
        ImageFormat format = ImageFormat::PNG; // default
        
        if (extension == "jpg" || extension == "jpeg") format = ImageFormat::JPEG;
        else if (extension == "bmp") format = ImageFormat::BMP;
        else if (extension == "tiff") format = ImageFormat::TIFF;
        else if (extension == "gif") format = ImageFormat::GIF;
        else if (extension == "webp") format = ImageFormat::WebP;
        else if (extension == "ico") format = ImageFormat::ICO;
        
        exportImage(fileName, format);
    }
}

void ImageToolWidget::onBatchProcessAction()
{
    // Simple batch processing dialog
    QMessageBox::information(this, tr("Batch Processing"), 
                           tr("Batch processing dialog not implemented yet"));
}

void ImageToolWidget::onZoomChanged(qreal factor)
{
    m_zoomSlider->blockSignals(true);
    m_zoomSlider->setValue(qRound(factor * 100));
    m_zoomSlider->blockSignals(false);
    
    m_zoomLabel->setText(QString("%1%").arg(qRound(factor * 100)));
}

void ImageToolWidget::onSelectionChanged(const QRectF& rect)
{
    m_selectionRect = rect;
}

void ImageToolWidget::onImageClicked(const QPointF& pos)
{
    Q_UNUSED(pos)
    // Could implement pixel color picking here
}

void ImageToolWidget::onProcessingFinished(const QImage& result)
{
    m_currentImage = result;
    m_imageView->setImage(m_currentImage);
    pushToHistory(m_currentImage);
    
    m_sizeLabel->setText(QString("%1 x %2").arg(result.width()).arg(result.height()));
    
    emit operationApplied(m_currentOperation);
}

void ImageToolWidget::onBatchProgress(int current, int total, const QString& currentFile)
{
    emit batchProgress(current, total, currentFile);
}

void ImageToolWidget::onBatchFinished()
{
    emit batchFinished();
}

void ImageToolWidget::onError(const QString& error)
{
    emit this->error(error);
}

void ImageToolWidget::showContextMenu(const QPoint& pos)
{
    QMenu menu(this);
    
    menu.addAction(tr("Zoom In"), this, &ImageToolWidget::zoomIn);
    menu.addAction(tr("Zoom Out"), this, &ImageToolWidget::zoomOut);
    menu.addAction(tr("Zoom to Fit"), this, &ImageToolWidget::zoomToFit);
    menu.addAction(tr("Reset Zoom"), this, &ImageToolWidget::resetZoom);
    
    menu.addSeparator();
    
    if (m_imageView->isSelectionMode()) {
        menu.addAction(tr("Crop to Selection"), this, &ImageToolWidget::cropToSelection);
        menu.addAction(tr("Clear Selection"), this, &ImageToolWidget::clearSelection);
    }
    
    menu.addSeparator();
    
    menu.addAction(tr("Copy"), this, [this]() {
        if (!m_currentImage.isNull()) {
            QApplication::clipboard()->setImage(m_currentImage);
        }
    });
    
    if (!menu.isEmpty()) {
        menu.exec(m_imageView->mapToGlobal(pos));
    }
}

void ImageToolWidget::updateWindowTitle()
{
    QString title = tr("Image Tool");
    if (!m_currentFilePath.isEmpty()) {
        title += " - " + QFileInfo(m_currentFilePath).fileName();
        if (m_modified) {
            title += "*";
        }
    }
    // In a real application, this would set the window title
    // setWindowTitle(title);
}

void ImageToolWidget::updateMetadataPanel()
{
    m_metadataTree->clear();
    
    QMap<QString, QTreeWidgetItem*> categories;
    
    for (const ImageMetadata& metadata : m_metadata) {
        if (!categories.contains(metadata.category)) {
            categories[metadata.category] = new QTreeWidgetItem(m_metadataTree);
            categories[metadata.category]->setText(0, metadata.category);
            categories[metadata.category]->setExpanded(true);
        }
        
        QTreeWidgetItem* item = new QTreeWidgetItem(categories[metadata.category]);
        item->setText(0, QString("%1: %2").arg(metadata.key, metadata.value));
    }
}

void ImageToolWidget::updateHistogram()
{
    // Histogram implementation would go here
    // For now, just show a placeholder
}

void ImageToolWidget::updateUndoRedoActions()
{
    m_undoAction->setEnabled(canUndo());
    m_redoAction->setEnabled(canRedo());
    
    // Update history list
    m_historyList->clear();
    for (int i = 0; i < m_history.size(); ++i) {
        QListWidgetItem* item = new QListWidgetItem(m_historyList);
        item->setText(QString("Step %1").arg(i + 1));
        if (i == m_historyIndex) {
            item->setIcon(QIcon::fromTheme("go-jump"));
        }
    }
}

QList<ImageMetadata> ImageToolWidget::extractMetadata(const QString& filePath)
{
    QList<ImageMetadata> metadata;
    
    QFileInfo fileInfo(filePath);
    
    // Basic file metadata
    metadata.append({"File Name", fileInfo.fileName(), "File"});
    metadata.append({"File Size", QString::number(fileInfo.size()), "File"});
    metadata.append({"Created", fileInfo.birthTime().toString(), "File"});
    metadata.append({"Modified", fileInfo.lastModified().toString(), "File"});
    
    // Image metadata
    QImageReader reader(filePath);
    QSize size = reader.size();
    if (size.isValid()) {
        metadata.append({"Width", QString::number(size.width()), "Image"});
        metadata.append({"Height", QString::number(size.height()), "Image"});
    }
    
    metadata.append({"Format", reader.format().toUpper(), "Image"});
    metadata.append({"Color Count", QString::number(reader.imageCount()), "Image"});
    
    return metadata;
}

QString ImageToolWidget::formatToString(ImageFormat format) const
{
    switch (format) {
        case ImageFormat::PNG: return "PNG";
        case ImageFormat::JPEG: return "JPEG";
        case ImageFormat::BMP: return "BMP";
        case ImageFormat::TIFF: return "TIFF";
        case ImageFormat::GIF: return "GIF";
        case ImageFormat::WebP: return "WebP";
        case ImageFormat::ICO: return "ICO";
        default: return "Unknown";
    }
}

ImageFormat ImageToolWidget::stringToFormat(const QString& str) const
{
    QString upper = str.toUpper();
    if (upper == "PNG") return ImageFormat::PNG;
    if (upper == "JPEG" || upper == "JPG") return ImageFormat::JPEG;
    if (upper == "BMP") return ImageFormat::BMP;
    if (upper == "TIFF") return ImageFormat::TIFF;
    if (upper == "GIF") return ImageFormat::GIF;
    if (upper == "WEBP") return ImageFormat::WebP;
    if (upper == "ICO") return ImageFormat::ICO;
    return ImageFormat::PNG;
}

void ImageToolWidget::pushToHistory(const QImage& image)
{
    // Remove any redo history
    while (m_history.size() > m_historyIndex + 1) {
        m_history.removeLast();
    }
    
    m_history.append(image);
    m_historyIndex = m_history.size() - 1;
    
    // Limit history size
    while (m_history.size() > MAX_HISTORY_SIZE) {
        m_history.removeFirst();
        m_historyIndex--;
    }
    
    updateUndoRedoActions();
}

QImage ImageToolWidget::getCurrentImage() const
{
    return m_currentImage;
}
