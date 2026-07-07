#include "training_progress_dock.h"
#include <iostream>

TrainingProgressDock::TrainingProgressDock(void* parent)
    : m_parent(parent)
    , m_progress(0.0f)
{
}

void TrainingProgressDock::initialize() {
    std::cout << "TrainingProgressDock initialized" << std::endl;
}

void TrainingProgressDock::setProgress(float progress) {
    m_progress = progress;
}

float TrainingProgressDock::getProgress() const {
    return m_progress;
}
