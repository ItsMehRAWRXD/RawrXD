#ifndef TODO_DOCK_H
#define TODO_DOCK_H

#include <string>
#include <vector>

class TodoDock {

public:
    explicit TodoDock(void* parent = nullptr);
    void initialize();
    void addTask(const std::string& task);
    std::vector<std::string> getTasks() const;

private:
    void* m_parent;
    std::vector<std::string> m_tasks;
};

#endif
