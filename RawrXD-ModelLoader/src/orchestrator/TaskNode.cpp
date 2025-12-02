#include "TaskNode.h"

namespace beacon {

TaskNode::TaskNode(const QString& description, const QList<QString>& deps)
    : id(QUuid::createUuid().toString(QUuid::Id128)),
      description(description),
      status(TaskStatus::PENDING),
      dependencies(deps)
{
    id.remove(QChar('{')).remove(QChar('}'));
}

QJsonObject TaskNode::toJson() const
{
    QJsonObject json;
    json["id"] = id;
    json["description"] = description;
    json["status"] = statusToString();
    json["log"] = log;

    QJsonArray depsArray;
    for (const QString& dep : dependencies) {
        depsArray.append(dep);
    }
    json["dependencies"] = depsArray;

    QJsonArray outputsArray;
    for (const QString& output : outputs) {
        outputsArray.append(output);
    }
    json["outputs"] = outputsArray;

    return json;
}

TaskNode TaskNode::fromJson(const QJsonObject& json)
{
    TaskNode node;
    node.id = json["id"].toString();
    node.description = json["description"].toString();
    node.status = stringToStatus(json["status"].toString());
    node.log = json["log"].toString();

    QJsonArray depsArray = json["dependencies"].toArray();
    for (const QJsonValue& value : depsArray) {
        node.dependencies.append(value.toString());
    }

    QJsonArray outputsArray = json["outputs"].toArray();
    for (const QJsonValue& value : outputsArray) {
        node.outputs.append(value.toString());
    }

    return node;
}

QString TaskNode::statusToString() const
{
    return statusToString(status);
}

QString TaskNode::statusToString(TaskStatus status)
{
    switch (status) {
    case TaskStatus::PENDING: return QStringLiteral("PENDING");
    case TaskStatus::IN_PROGRESS: return QStringLiteral("IN_PROGRESS");
    case TaskStatus::COMPLETED: return QStringLiteral("COMPLETED");
    case TaskStatus::FAILED: return QStringLiteral("FAILED");
    case TaskStatus::SKIPPED: return QStringLiteral("SKIPPED");
    }
    return QStringLiteral("UNKNOWN");
}

TaskStatus TaskNode::stringToStatus(const QString& statusStr)
{
    if (statusStr == QLatin1String("IN_PROGRESS")) return TaskStatus::IN_PROGRESS;
    if (statusStr == QLatin1String("COMPLETED")) return TaskStatus::COMPLETED;
    if (statusStr == QLatin1String("FAILED")) return TaskStatus::FAILED;
    if (statusStr == QLatin1String("SKIPPED")) return TaskStatus::SKIPPED;
    return TaskStatus::PENDING;
}

} // namespace beacon
