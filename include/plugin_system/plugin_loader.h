<<<<<<< HEAD
#ifndef PLUGIN_LOADER_H
#define PLUGIN_LOADER_H

// C++20, no Qt. Hot-load .dll/.so via platform API (no QLibrary).

#include <string>
#include <map>
#include "plugin_api.h"

struct PluginInstance {
    void* library = nullptr;  // HMODULE or dlopen handle
    PluginInfo* (*plugin_init)(PluginContext*) = nullptr;
    void (*plugin_onFileSave)(const char*) = nullptr;
    void (*plugin_onChatMessage)(const char*) = nullptr;
    void (*plugin_onCommand)(const char*) = nullptr;
    void (*plugin_onModelLoad)(const char*) = nullptr;
    void (*plugin_cleanup)() = nullptr;
    PluginInfo* info = nullptr;
    int refCount = 0;
};

class PluginLoader
{
public:
    PluginLoader() = default;
    ~PluginLoader();

    bool loadPlugin(const std::string& pluginPath);
    void unloadPlugin(const std::string& pluginName);
    void unloadAllPlugins();

    void onFileSave(const std::string& filePath);
    void onChatMessage(const std::string& message);
    void onCommand(const std::string& command);
    void onModelLoad(const std::string& modelPath);

private:
    std::map<std::string, PluginInstance> m_plugins;
    PluginContext m_context;
};

#endif // PLUGIN_LOADER_H
=======
#ifndef PLUGIN_LOADER_H
#define PLUGIN_LOADER_H

#include <QObject>
#include <QString>
#include <QLibrary>
#include <QMap>
#include <QVector>
#include "plugin_api.h"

class PluginLoader : public QObject
{
    Q_OBJECT

public:
    explicit PluginLoader(QObject *parent = nullptr);
    ~PluginLoader();

    // Hot-load .dll / .so via QLibrary
    // Manifest-driven: name, version, permissions (["file_ops", "terminal"])
    // Sand-boxed: plugins must call rawrxd::requestFileOperation() → goes through your AgenticFileOperations → Keep/Undo dialog.
    // Hooks: onFileSave, onChatMessage, onCommand, onModelLoad
    // Unload-safe (RAII shared-lib handle, refcount).
    bool loadPlugin(const QString &pluginPath);
    void unloadPlugin(const QString &pluginName);
    void unloadAllPlugins();

    // Call plugin hooks
    void onFileSave(const QString &filePath);
    void onChatMessage(const QString &message);
    void onCommand(const QString &command);
    void onModelLoad(const QString &modelPath);

private:
    struct PluginInstance {
        QLibrary *library;
        PluginInfo* (*plugin_init)(PluginContext*);
        void (*plugin_onFileSave)(const char*);
        void (*plugin_onChatMessage)(const char*);
        void (*plugin_onCommand)(const char*);
        void (*plugin_onModelLoad)(const char*);
        void (*plugin_cleanup)();
        PluginInfo *info;
        int refCount;
    };

    QMap<QString, PluginInstance> m_plugins;
    PluginContext m_context;
};

#endif // PLUGIN_LOADER_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
