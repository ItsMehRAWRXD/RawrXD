#pragma once
#include <QString>
#include <QJsonArray>
#include "planner.hpp"
#include "../ai_implementation.h"

class AgenticBridge {
private:
    std::shared_ptr<AIImplementation> m_ai;
    Planner m_planner;

public:
    AgenticBridge(std::shared_ptr<AIImplementation> ai) : m_ai(ai) {}
    
    // Convert plan to AI request and execute
    CompletionResponse executePlan(const QString& humanWish);
    
    // Stream execution with real-time feedback
    void streamExecutePlan(const QString& humanWish, 
                          std::function<void(const std::string&)> callback);
};