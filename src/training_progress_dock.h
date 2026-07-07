#ifndef TRAINING_PROGRESS_DOCK_H
#define TRAINING_PROGRESS_DOCK_H

class TrainingProgressDock {

public:
    explicit TrainingProgressDock(void* parent = nullptr);
    void initialize();
    void setProgress(float progress);
    float getProgress() const;

private:
    void* m_parent;
    float m_progress;
};

#endif
