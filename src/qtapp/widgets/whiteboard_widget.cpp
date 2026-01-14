/**
 * @file whiteboard_widget.cpp
 * @brief Implementation of WhiteboardWidget - Interactive drawing canvas
 */

#include "whiteboard_widget.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGraphicsView>
#include <QGraphicsPathItem>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsRectItem>
#include <QPainter>
#include <QPainterPath>
#include <QGraphicsSceneMouseEvent>
#include <QPushButton>
#include <QToolBar>
#include <QSpinBox>
#include <QLabel>
#include <QColorDialog>
#include <QFileDialog>
#include <QMessageBox>
#include <QSettings>
#include <QDebug>

// ============================================================================
// WhiteboardScene Implementation
// ============================================================================

WhiteboardScene::WhiteboardScene(QObject* parent)
    : QGraphicsScene(parent), mCurrentMode("pen"), mCurrentColor(Qt::black), 
      mPenWidth(2), mIsDrawing(false)
{
    setBackgroundBrush(QBrush(Qt::white));
    setSceneRect(0, 0, 800, 600);
}

void WhiteboardScene::setDrawingMode(const QString& mode)
{
    mCurrentMode = mode;
    emit drawingModeChanged(mode);
}

void WhiteboardScene::setColor(const QColor& color)
{
    mCurrentColor = color;
}

void WhiteboardScene::setPenWidth(int width)
{
    mPenWidth = width;
}

void WhiteboardScene::clearBoard()
{
    clear();
    emit boardModified();
}

void WhiteboardScene::saveBoardToImage(const QString& filename)
{
    QPixmap pixmap(800, 600);
    pixmap.fill(Qt::white);
    QPainter painter(&pixmap);
    render(&painter);
    pixmap.save(filename);
}

QPixmap WhiteboardScene::getCurrentImage() const
{
    QPixmap pixmap(800, 600);
    pixmap.fill(Qt::white);
    QPainter painter(&pixmap);
    const_cast<WhiteboardScene*>(this)->render(&painter);
    return pixmap;
}

void WhiteboardScene::mousePressEvent(QGraphicsSceneMouseEvent* event)
{
    mIsDrawing = true;
    mLastPoint = event->scenePos();
}

void WhiteboardScene::mouseMoveEvent(QGraphicsSceneMouseEvent* event)
{
    if (!mIsDrawing) return;
    
    if (mCurrentMode == "pen") {
        QPen pen(mCurrentColor);
        pen.setWidth(mPenWidth);
        pen.setCapStyle(Qt::RoundCap);
        pen.setJoinStyle(Qt::RoundJoin);
        addLine(mLastPoint.x(), mLastPoint.y(), event->scenePos().x(), event->scenePos().y(), pen);
        mLastPoint = event->scenePos();
    } else if (mCurrentMode == "eraser") {
        QPen pen(Qt::white);
        pen.setWidth(mPenWidth * 2);
        pen.setCapStyle(Qt::RoundCap);
        pen.setJoinStyle(Qt::RoundJoin);
        addLine(mLastPoint.x(), mLastPoint.y(), event->scenePos().x(), event->scenePos().y(), pen);
        mLastPoint = event->scenePos();
    }
    
    emit boardModified();
}

void WhiteboardScene::mouseReleaseEvent(QGraphicsSceneMouseEvent* event)
{
    if (!mIsDrawing) return;
    mIsDrawing = false;
    
    if (mCurrentMode == "rectangle") {
        QRectF rect(mLastPoint, event->scenePos());
        QPen pen(mCurrentColor);
        pen.setWidth(mPenWidth);
        addRect(rect, pen);
    } else if (mCurrentMode == "circle") {
        QRectF rect(mLastPoint, event->scenePos());
        QPen pen(mCurrentColor);
        pen.setWidth(mPenWidth);
        addEllipse(rect, pen);
    } else if (mCurrentMode == "line") {
        QPen pen(mCurrentColor);
        pen.setWidth(mPenWidth);
        addLine(mLastPoint.x(), mLastPoint.y(), event->scenePos().x(), event->scenePos().y(), pen);
    }
    
    emit boardModified();
}

// ============================================================================
// WhiteboardWidget Implementation
// ============================================================================

WhiteboardWidget::WhiteboardWidget(QWidget* parent)
    : QWidget(parent), mCurrentColor(Qt::black)
{
    setupUI();
    createToolbar();
    connectSignals();
    restoreState();
}

WhiteboardWidget::~WhiteboardWidget()
{
    saveState();
}

void WhiteboardWidget::setupUI()
{
    mMainLayout = new QVBoxLayout(this);
    mMainLayout->setContentsMargins(0, 0, 0, 0);
    
    // Toolbar
    mToolbarLayout = new QHBoxLayout();
    mMainLayout->addLayout(mToolbarLayout);
    
    // Graphics view and scene
    mScene = new WhiteboardScene(this);
    mGraphicsView = new QGraphicsView(mScene, this);
    mGraphicsView->setRenderHint(QPainter::Antialiasing);
    mGraphicsView->setRenderHint(QPainter::SmoothPixmapTransform);
    mMainLayout->addWidget(mGraphicsView);
}

void WhiteboardWidget::createToolbar()
{
    // Tool buttons
    mPenButton = new QPushButton("Pen", this);
    mPenButton->setCheckable(true);
    mPenButton->setChecked(true);
    mToolbarLayout->addWidget(mPenButton);
    
    mEraserButton = new QPushButton("Eraser", this);
    mEraserButton->setCheckable(true);
    mToolbarLayout->addWidget(mEraserButton);
    
    mRectButton = new QPushButton("Rectangle", this);
    mRectButton->setCheckable(true);
    mToolbarLayout->addWidget(mRectButton);
    
    mCircleButton = new QPushButton("Circle", this);
    mCircleButton->setCheckable(true);
    mToolbarLayout->addWidget(mCircleButton);
    
    mLineButton = new QPushButton("Line", this);
    mLineButton->setCheckable(true);
    mToolbarLayout->addWidget(mLineButton);
    
    // Add visual separator
    QFrame* separator = new QFrame(this);
    separator->setFrameShape(QFrame::VLine);
    separator->setFrameShadow(QFrame::Sunken);
    separator->setMaximumWidth(2);
    mToolbarLayout->addWidget(separator);
    
    // Color picker
    mColorButton = new QPushButton("Color", this);
    mColorButton->setStyleSheet(QString("background-color: %1").arg(mCurrentColor.name()));
    mToolbarLayout->addWidget(mColorButton);
    
    // Pen width
    mToolbarLayout->addWidget(new QLabel("Width:", this));
    mPenWidthSpinBox = new QSpinBox(this);
    mPenWidthSpinBox->setMinimum(1);
    mPenWidthSpinBox->setMaximum(20);
    mPenWidthSpinBox->setValue(2);
    mToolbarLayout->addWidget(mPenWidthSpinBox);
    
    mToolbarLayout->addStretch();
    
    // Action buttons
    mUndoButton = new QPushButton("Undo", this);
    mToolbarLayout->addWidget(mUndoButton);
    
    mRedoButton = new QPushButton("Redo", this);
    mToolbarLayout->addWidget(mRedoButton);
    
    mClearButton = new QPushButton("Clear", this);
    mToolbarLayout->addWidget(mClearButton);
    
    mLoadButton = new QPushButton("Load", this);
    mToolbarLayout->addWidget(mLoadButton);
    
    mSaveButton = new QPushButton("Save", this);
    mToolbarLayout->addWidget(mSaveButton);
}

void WhiteboardWidget::connectSignals()
{
    connect(mPenButton, &QPushButton::clicked, this, &WhiteboardWidget::onPenTool);
    connect(mEraserButton, &QPushButton::clicked, this, &WhiteboardWidget::onEraserTool);
    connect(mRectButton, &QPushButton::clicked, this, &WhiteboardWidget::onRectangleTool);
    connect(mCircleButton, &QPushButton::clicked, this, &WhiteboardWidget::onCircleTool);
    connect(mLineButton, &QPushButton::clicked, this, &WhiteboardWidget::onLineTool);
    connect(mColorButton, &QPushButton::clicked, this, &WhiteboardWidget::onColorSelection);
    connect(mPenWidthSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &WhiteboardWidget::onPenWidthChanged);
    connect(mClearButton, &QPushButton::clicked, this, &WhiteboardWidget::onClearBoard);
    connect(mSaveButton, &QPushButton::clicked, this, &WhiteboardWidget::onSaveBoard);
    connect(mLoadButton, &QPushButton::clicked, this, &WhiteboardWidget::onLoadBoard);
    connect(mScene, &WhiteboardScene::boardModified, this, [this]() {
        emit boardUpdated(mScene->getCurrentImage());
    });
}

void WhiteboardWidget::onPenTool()
{
    mPenButton->setChecked(true);
    mEraserButton->setChecked(false);
    mRectButton->setChecked(false);
    mCircleButton->setChecked(false);
    mLineButton->setChecked(false);
    mScene->setDrawingMode("pen");
    emit toolChanged("pen");
}

void WhiteboardWidget::onEraserTool()
{
    mPenButton->setChecked(false);
    mEraserButton->setChecked(true);
    mRectButton->setChecked(false);
    mCircleButton->setChecked(false);
    mLineButton->setChecked(false);
    mScene->setDrawingMode("eraser");
    emit toolChanged("eraser");
}

void WhiteboardWidget::onRectangleTool()
{
    mPenButton->setChecked(false);
    mEraserButton->setChecked(false);
    mRectButton->setChecked(true);
    mCircleButton->setChecked(false);
    mLineButton->setChecked(false);
    mScene->setDrawingMode("rectangle");
    emit toolChanged("rectangle");
}

void WhiteboardWidget::onCircleTool()
{
    mPenButton->setChecked(false);
    mEraserButton->setChecked(false);
    mRectButton->setChecked(false);
    mCircleButton->setChecked(true);
    mLineButton->setChecked(false);
    mScene->setDrawingMode("circle");
    emit toolChanged("circle");
}

void WhiteboardWidget::onLineTool()
{
    mPenButton->setChecked(false);
    mEraserButton->setChecked(false);
    mRectButton->setChecked(false);
    mCircleButton->setChecked(false);
    mLineButton->setChecked(true);
    mScene->setDrawingMode("line");
    emit toolChanged("line");
}

void WhiteboardWidget::onColorSelection()
{
    QColor color = QColorDialog::getColor(mCurrentColor, this, "Select Color");
    if (color.isValid()) {
        mCurrentColor = color;
        mScene->setColor(color);
        mColorButton->setStyleSheet(QString("background-color: %1").arg(color.name()));
    }
}

void WhiteboardWidget::onPenWidthChanged(int width)
{
    mScene->setPenWidth(width);
}

void WhiteboardWidget::onClearBoard()
{
    int ret = QMessageBox::question(this, "Clear Board", "Are you sure you want to clear the board?");
    if (ret == QMessageBox::Yes) {
        mScene->clearBoard();
    }
}

void WhiteboardWidget::onSaveBoard()
{
    QString filename = QFileDialog::getSaveFileName(this, "Save Board", "", "PNG Images (*.png);;JPEG Images (*.jpg)");
    if (!filename.isEmpty()) {
        mScene->saveBoardToImage(filename);
        QMessageBox::information(this, "Success", "Board saved successfully!");
    }
}

void WhiteboardWidget::onLoadBoard()
{
    QString filename = QFileDialog::getOpenFileName(this, "Load Board", "", "PNG Images (*.png);;JPEG Images (*.jpg)");
    if (!filename.isEmpty()) {
        QPixmap pixmap(filename);
        if (!pixmap.isNull()) {
            mScene->clear();
            mScene->addPixmap(pixmap);
        } else {
            QMessageBox::warning(this, "Error", "Failed to load image!");
        }
    }
}

void WhiteboardWidget::onUndo()
{
    // Implement undo functionality - restore previous board state
    if (!mScene) return;
    
    // Get the current image
    QPixmap currentImage = mScene->getCurrentImage();
    
    // Save current state to redo stack
    mRedoStack.push(currentImage);
    
    // Restore previous state from undo stack
    if (!mUndoStack.isEmpty()) {
        QPixmap previousImage = mUndoStack.pop();
        
        // Render the previous pixmap to the scene
        mScene->clear();
        QGraphicsPixmapItem* item = new QGraphicsPixmapItem(previousImage);
        mScene->addItem(item);
        
        emit boardUpdated(previousImage);
    }
}

void WhiteboardWidget::onRedo()
{
    // Implement redo functionality - restore next board state
    if (!mScene) return;
    
    // Get the current image
    QPixmap currentImage = mScene->getCurrentImage();
    
    // Save current state to undo stack
    mUndoStack.push(currentImage);
    
    // Restore next state from redo stack
    if (!mRedoStack.isEmpty()) {
        QPixmap nextImage = mRedoStack.pop();
        
        // Render the next pixmap to the scene
        mScene->clear();
        QGraphicsPixmapItem* item = new QGraphicsPixmapItem(nextImage);
        mScene->addItem(item);
        
        emit boardUpdated(nextImage);
    }
}

void WhiteboardWidget::restoreState()
{
    QSettings settings("RawrXD", "IDE");
    mCurrentColor = settings.value("whiteboard/color", QColor(Qt::black)).value<QColor>();
    int width = settings.value("whiteboard/penWidth", 2).toInt();
    mPenWidthSpinBox->setValue(width);
}

void WhiteboardWidget::saveState()
{
    QSettings settings("RawrXD", "IDE");
    settings.setValue("whiteboard/color", mCurrentColor);
    settings.setValue("whiteboard/penWidth", mPenWidthSpinBox->value());
}
