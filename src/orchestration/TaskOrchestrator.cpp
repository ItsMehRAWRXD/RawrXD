// Task Orchestrator - Qt-free implementation
#include <iostream>
#include <string>
#include <vector>

class TaskOrchestrator {
public:
    TaskOrchestrator() = default;
    
    void submitTask(const std::string& task) {
        m_tasks.push_back(task);
        std::cout << "Task submitted: " << task << std::endl;
    }
    
    std::vector<std::string> getTasks() const {
        return m_tasks;
    }
    
private:
    std::vector<std::string> m_tasks;
};

int main() {
    TaskOrchestrator orchestrator;
    orchestrator.submitTask("test");
    return 0;
}
