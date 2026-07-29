<<<<<<< HEAD
#ifndef SANDBOX_H
#define SANDBOX_H

// C++20 / Win32. Command sandbox: allow-list; Win32 Job Objects, no Qt.

#include <string>
#include <vector>

class Sandbox
{
public:
    Sandbox() = default;
    ~Sandbox() = default;

    void setAllowList(const std::vector<std::string>& allowList);

    /** Execute command in sandbox. Returns true on success. */
    bool executeCommand(const std::string& command, const std::vector<std::string>& arguments = {});

    std::string getOutput() const { return m_output; }

private:
    bool executeCommandWindows(const std::string& command, const std::vector<std::string>& arguments);
    bool executeCommandLinux(const std::string& command, const std::vector<std::string>& arguments);

    std::vector<std::string> m_allowList;
    std::string m_output;
};

#endif // SANDBOX_H
=======
#ifndef SANDBOX_H
#define SANDBOX_H

#include <QObject>
#include <QString>
#include <QProcess>

// Command sandbox: allow-list + chroot on Linux, Job Objects on Win32.
class Sandbox : public QObject
{
    Q_OBJECT

public:
    explicit Sandbox(QObject *parent = nullptr);
    ~Sandbox();

    // Set allow-list of commands
    void setAllowList(const QStringList &allowList);

    // Execute a command in the sandbox
    bool executeCommand(const QString &command, const QStringList &arguments = QStringList());

    // Get the output of the last executed command
    QString getOutput() const;

private:
    QStringList m_allowList;
    QString m_output;
    
    // Execute command on Windows using Job Objects
    bool executeCommandWindows(const QString &command, const QStringList &arguments);
    
    // Execute command on Linux using chroot
    bool executeCommandLinux(const QString &command, const QStringList &arguments);
};

#endif // SANDBOX_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
