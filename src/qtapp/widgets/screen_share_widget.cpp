/**
 * @file screen_share_widget.cpp
 * @brief Implementation of ScreenShareWidget - Screen capture and sharing
 */

#include "screen_share_widget.h"
#include <QApplication>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QCheckBox>
#include <QSpinBox>
#include <QScreen>
#include <QGuiApplication>
#include <QMessageBox>
#include <QSettings>
#include <QDebug>

ScreenShareWidget::ScreenShareWidget(QWidget* parent)
    : QWidget(parent), mSharingActive(false)
{
    setupUI();
    populateScreens();
    populateResolutions();
    initializeScreens();
    connectSignals();
    restoreState();
    
    setWindowTitle("Screen Share");
}

ScreenShareWidget::~ScreenShareWidget()
{
    saveState();
    if (mSharingActive) {
        onStopSharing();
    }
}

void ScreenShareWidget::setupUI()
{
    mMainLayout = new QVBoxLayout(this);
    
    // Status display
    mStatusLabel = new QLabel("Ready to share", this);
    mStatusLabel->setStyleSheet("font-weight: bold; font-size: 14px;");
    mMainLayout->addWidget(mStatusLabel);
    
    // Screen selection
    mScreenLayout = new QHBoxLayout();
    mScreenLabel = new QLabel("Screen:", this);
    mScreenLayout->addWidget(mScreenLabel);
    
    mScreenCombo = new QComboBox(this);
    mScreenLayout->addWidget(mScreenCombo);
    
    mScreenInfoLabel = new QLabel("", this);
    mScreenLayout->addWidget(mScreenInfoLabel);
    mScreenLayout->addStretch();
    
    mMainLayout->addLayout(mScreenLayout);
    
    // Resolution settings
    mResolutionLayout = new QHBoxLayout();
    mResolutionLabel = new QLabel("Resolution:", this);
    mResolutionLayout->addWidget(mResolutionLabel);
    
    mResolutionCombo = new QComboBox(this);
    mResolutionLayout->addWidget(mResolutionCombo);
    mResolutionLayout->addStretch();
    
    mMainLayout->addLayout(mResolutionLayout);
    
    // Frame rate
    mFpsLayout = new QHBoxLayout();
    mFpsLabel = new QLabel("Frame Rate (FPS):", this);
    mFpsLayout->addWidget(mFpsLabel);
    
    mFpsSpinBox = new QSpinBox(this);
    mFpsSpinBox->setRange(5, 60);
    mFpsSpinBox->setValue(30);
    mFpsLayout->addWidget(mFpsSpinBox);
    mFpsLayout->addStretch();
    
    mMainLayout->addLayout(mFpsLayout);
    
    // Options
    mOptionsLayout = new QHBoxLayout();
    
    mAudioCheckbox = new QCheckBox("Share Audio", this);
    mAudioCheckbox->setChecked(true);
    mOptionsLayout->addWidget(mAudioCheckbox);
    
    mCursorCheckbox = new QCheckBox("Show Cursor", this);
    mCursorCheckbox->setChecked(true);
    mOptionsLayout->addWidget(mCursorCheckbox);
    
    mOptionsLayout->addStretch();
    
    mMainLayout->addLayout(mOptionsLayout);
    
    mMainLayout->addSpacing(15);
    
    // Control buttons
    mControlsLayout = new QHBoxLayout();
    
    mStartButton = new QPushButton("Start Sharing", this);
    mStartButton->setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; font-weight: bold;");
    mControlsLayout->addWidget(mStartButton);
    
    mStopButton = new QPushButton("Stop Sharing", this);
    mStopButton->setStyleSheet("background-color: #f44336; color: white; padding: 10px; font-weight: bold;");
    mStopButton->setEnabled(false);
    mControlsLayout->addWidget(mStopButton);
    
    mRegionButton = new QPushButton("Select Region", this);
    mControlsLayout->addWidget(mRegionButton);
    
    mCaptureButton = new QPushButton("Capture Now", this);
    mControlsLayout->addWidget(mCaptureButton);
    
    mSettingsButton = new QPushButton("Settings", this);
    mControlsLayout->addWidget(mSettingsButton);
    
    mMainLayout->addLayout(mControlsLayout);
    
    // Bitrate display
    mBitrateLabel = new QLabel("Bitrate: 0 Mbps", this);
    mMainLayout->addWidget(mBitrateLabel);
    
    mMainLayout->addStretch();
}

void ScreenShareWidget::populateScreens()
{
    mAvailableScreens = QGuiApplication::screens();
    for (int i = 0; i < mAvailableScreens.size(); ++i) {
        QScreen* screen = mAvailableScreens.at(i);
        mScreenCombo->addItem(QString("Screen %1 (%2x%3)").arg(i + 1)
            .arg(screen->geometry().width())
            .arg(screen->geometry().height()), i);
    }
}

void ScreenShareWidget::populateResolutions()
{
    mResolutionCombo->addItem("Full Resolution");
    mResolutionCombo->addItem("1920x1080");
    mResolutionCombo->addItem("1280x720");
    mResolutionCombo->addItem("1024x768");
    mResolutionCombo->addItem("800x600");
    mResolutionCombo->setCurrentIndex(1);
}

void ScreenShareWidget::connectSignals()
{
    connect(mStartButton, &QPushButton::clicked, this, &ScreenShareWidget::onStartSharing);
    connect(mStopButton, &QPushButton::clicked, this, &ScreenShareWidget::onStopSharing);
    connect(mScreenCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &ScreenShareWidget::onScreenSelected);
    connect(mResolutionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &ScreenShareWidget::onResolutionChanged);
    connect(mFpsSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &ScreenShareWidget::onFrameRateChanged);
    connect(mAudioCheckbox, &QCheckBox::toggled, this, &ScreenShareWidget::onToggleAudio);
    connect(mCursorCheckbox, &QCheckBox::toggled, this, &ScreenShareWidget::onToggleCursor);
    connect(mRegionButton, &QPushButton::clicked, this, &ScreenShareWidget::onSelectRegion);
    connect(mCaptureButton, &QPushButton::clicked, this, &ScreenShareWidget::onCaptureScreen);
    connect(mSettingsButton, &QPushButton::clicked, this, &ScreenShareWidget::onSettingsClicked);
}

void ScreenShareWidget::onStartSharing()
{
    mSharingActive = true;
    mStatusLabel->setText("Sharing screen...");
    mStatusLabel->setStyleSheet("font-weight: bold; font-size: 14px; color: green;");
    mStartButton->setEnabled(false);
    mStopButton->setEnabled(true);
    mScreenCombo->setEnabled(false);
    mResolutionCombo->setEnabled(false);
    
    QString screenName = mScreenCombo->currentText();
    emit sharingStarted(screenName);
}

void ScreenShareWidget::onStopSharing()
{
    mSharingActive = false;
    mStatusLabel->setText("Screen sharing stopped");
    mStatusLabel->setStyleSheet("font-weight: bold; font-size: 14px; color: red;");
    mStartButton->setEnabled(true);
    mStopButton->setEnabled(false);
    mScreenCombo->setEnabled(true);
    mResolutionCombo->setEnabled(true);
    
    emit sharingStopped();
}

void ScreenShareWidget::onScreenSelected(int index)
{
    updateScreenInfo();
}

void ScreenShareWidget::onResolutionChanged(int index)
{
    QString resolution = mResolutionCombo->itemText(index);
    qDebug() << "Resolution changed to:" << resolution;
    emit settingsChanged();
}

void ScreenShareWidget::onFrameRateChanged(int fps)
{
    qDebug() << "Frame rate changed to:" << fps << "FPS";
    emit settingsChanged();
}

void ScreenShareWidget::onToggleAudio()
{
    qDebug() << "Audio sharing:" << mAudioCheckbox->isChecked();
    emit settingsChanged();
}

void ScreenShareWidget::onToggleCursor()
{
    qDebug() << "Cursor visibility:" << mCursorCheckbox->isChecked();
    emit settingsChanged();
}

void ScreenShareWidget::onSelectRegion()
{
    QMessageBox::information(this, "Select Region", 
        "Click and drag on your screen to select a region to share.\n"
        "This feature is not yet fully implemented.");
}

void ScreenShareWidget::onSettingsClicked()
{
    QString info = QString(
        "Current Settings:\n\n"
        "Screen: %1\n"
        "Resolution: %2\n"
        "Frame Rate: %3 FPS\n"
        "Share Audio: %4\n"
        "Show Cursor: %5")
        .arg(mScreenCombo->currentText())
        .arg(mResolutionCombo->currentText())
        .arg(mFpsSpinBox->value())
        .arg(mAudioCheckbox->isChecked() ? "Yes" : "No")
        .arg(mCursorCheckbox->isChecked() ? "Yes" : "No");
    
    QMessageBox::information(this, "Screen Share Settings", info);
}

void ScreenShareWidget::onCaptureScreen()
{
    int screenIndex = mScreenCombo->currentData().toInt();
    if (screenIndex >= 0 && screenIndex < mAvailableScreens.size()) {
        QScreen* screen = mAvailableScreens.at(screenIndex);
        QPixmap pixmap = screen->grabWindow(0);
        
        mStatusLabel->setText("Screen captured!");
        mStatusLabel->setStyleSheet("font-weight: bold; font-size: 14px; color: blue;");
        
        emit screenCaptured(pixmap);
    }
}

void ScreenShareWidget::updateScreenInfo()
{
    int screenIndex = mScreenCombo->currentData().toInt();
    if (screenIndex >= 0 && screenIndex < mAvailableScreens.size()) {
        QScreen* screen = mAvailableScreens.at(screenIndex);
        QString info = QString("%1x%2 @ %3 DPI")
            .arg(screen->geometry().width())
            .arg(screen->geometry().height())
            .arg(screen->logicalDotsPerInch(), 0, 'f', 1);
        mScreenInfoLabel->setText(info);
    }
}

void ScreenShareWidget::restoreState()
{
    QSettings settings("RawrXD", "IDE");
    int screenIndex = settings.value("screenShare/screenIndex", 0).toInt();
    if (screenIndex >= 0 && screenIndex < mScreenCombo->count()) {
        mScreenCombo->setCurrentIndex(screenIndex);
    }
    
    QString resolution = settings.value("screenShare/resolution", "1920x1080").toString();
    int resIndex = mResolutionCombo->findText(resolution);
    if (resIndex >= 0) mResolutionCombo->setCurrentIndex(resIndex);
    
    int fps = settings.value("screenShare/fps", 30).toInt();
    mFpsSpinBox->setValue(fps);
    
    bool audio = settings.value("screenShare/audio", true).toBool();
    mAudioCheckbox->setChecked(audio);
    
    bool cursor = settings.value("screenShare/cursor", true).toBool();
    mCursorCheckbox->setChecked(cursor);
}

void ScreenShareWidget::saveState()
{
    QSettings settings("RawrXD", "IDE");
    settings.setValue("screenShare/screenIndex", mScreenCombo->currentIndex());
    settings.setValue("screenShare/resolution", mResolutionCombo->currentText());
    settings.setValue("screenShare/fps", mFpsSpinBox->value());
    settings.setValue("screenShare/audio", mAudioCheckbox->isChecked());
    settings.setValue("screenShare/cursor", mCursorCheckbox->isChecked());
}

void ScreenShareWidget::initializeScreens()
{
    updateScreenInfo();
}
