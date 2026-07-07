#include "todo_dock.h"
#include <iostream>

TodoDock::TodoDock(void* parent)
    : m_parent(parent)
{
}

void TodoDock::initialize() {
    std::cout << "TodoDock initialized" << std::endl;
}

void TodoDock::addTask(const std::string& task) {
    m_tasks.push_back(task);
}

std::vector<std::string> TodoDock::getTasks() const {
    return m_tasks;
}
