#include "agentic_bridge.hpp"
#include <QJsonDocument>
#include <QJsonObject>

CompletionResponse AgenticBridge::executePlan(const QString& humanWish) {
    // Generate structured plan using existing planner
    QJsonArray tasks = m_planner.plan(humanWish);
    
    // Convert plan to AI prompt
    QString planJson = QJsonDocument(tasks).toJson(QJsonDocument::Compact);
    
    CompletionRequest request;
    request.prompt = QString("Execute this plan: %1").arg(planJson).toStdString();
    request.useToolCalling = true;
    
    // Make real AI call using existing infrastructure
    return m_ai->complete(request);
}

void AgenticBridge::streamExecutePlan(const QString& humanWish, 
                                     std::function<void(const std::string&)> callback) {
    QJsonArray tasks = m_planner.plan(humanWish);
    QString planJson = QJsonDocument(tasks).toJson(QJsonDocument::Compact);
    
    CompletionRequest request;
    request.prompt = QString("Execute: %1").arg(planJson).toStdString();
    
    // Stream through existing 8,259 TPS pipeline
    m_ai->streamComplete(request, [callback](const ParsedCompletion& chunk) {
        callback(chunk.content);
    });
}