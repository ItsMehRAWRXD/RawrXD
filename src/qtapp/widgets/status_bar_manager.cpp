/**
 * @file status_bar_manager.cpp
 * @brief Implementation of StatusBarManager - Status bar management
 */

#include "status_bar_manager.h"
#include <QStatusBar>
#include <QLabel>
#include <QProgressBar>
#include <QVBoxLayout>

StatusBarManager::StatusBarManager(QWidget* parent)
    : QWidget(parent)
{
    setupUI();
    setWindowTitle("Status Bar Manager");
}

StatusBarManager::~StatusBarManager() = default;

void StatusBarManager::setupUI()
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    
    mStatusBar = new QStatusBar(this);
    layout->addWidget(mStatusBar);
    
    mStatusLabel = new QLabel("Ready", this);
    mStatusBar->addWidget(mStatusLabel, 1);
    
    mPositionLabel = new QLabel("Line: 1, Column: 1", this);
    mStatusBar->addPermanentWidget(mPositionLabel);
    
    mEncodingLabel = new QLabel("UTF-8", this);
    mStatusBar->addPermanentWidget(mEncodingLabel);
    
    mProgressBar = new QProgressBar(this);
    mProgressBar->setMaximumWidth(200);
    mProgressBar->setMaximumHeight(20);
    mProgressBar->setVisible(false);
    mStatusBar->addPermanentWidget(mProgressBar);
}

void StatusBarManager::setStatus(const QString& message)
{
    mStatusLabel->setText(message);
}

void StatusBarManager::setProgress(int value)
{
    mProgressBar->setVisible(true);
    mProgressBar->setValue(value);
    if (value >= 100) mProgressBar->setVisible(false);
}

void StatusBarManager::clearStatus()
{
    mStatusLabel->setText("Ready");
    mProgressBar->setVisible(false);
}
