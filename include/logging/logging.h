#pragma once

#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(rawrxd_api)
Q_DECLARE_LOGGING_CATEGORY(rawrxd_config)

#define LOG_API_INFO(...)   qCInfo(rawrxd_api, __VA_ARGS__)
#define LOG_API_WARN(...)   qCWarning(rawrxd_api, __VA_ARGS__)
#define LOG_API_ERROR(...)  qCCritical(rawrxd_api, __VA_ARGS__)
#define LOG_CFG_INFO(...)   qCInfo(rawrxd_config, __VA_ARGS__)
#define LOG_CFG_WARN(...)   qCWarning(rawrxd_config, __VA_ARGS__)
#define LOG_CFG_ERROR(...)  qCCritical(rawrxd_config, __VA_ARGS__)
