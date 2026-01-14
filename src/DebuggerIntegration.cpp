#include "DebuggerIntegration.h"
#include "logging/structured_logger.h"
#include "config_manager.h"
#include <QElapsedTimer>

namespace RawrXD {

DebuggerIntegration& DebuggerIntegration::instance() {
    static DebuggerIntegration instance;
    return instance;
}

DebuggerIntegration::DebuggerIntegration() = default;

void DebuggerIntegration::initialize(DebuggerPanel* panel) {
    m_panel = panel;
    
    // Load configuration
    auto config = ConfigManager::instance().section("debugger");
    int refreshRate = ConfigManager::instance().getInt("debugger.refresh_rate_ms", 500);
    
    if (m_panel) {
        connect(m_panel, &DebuggerPanel::continueRequested, this, &DebuggerIntegration::onContinueRequested);
        connect(m_panel, &DebuggerPanel::stepOverRequested, this, &DebuggerIntegration::onStepOverRequested);
        connect(m_panel, &DebuggerPanel::stepIntoRequested, this, &DebuggerIntegration::onStepIntoRequested);
        connect(m_panel, &DebuggerPanel::stepOutRequested, this, &DebuggerIntegration::onStepOutRequested);
        connect(m_panel, &DebuggerPanel::stopRequested, this, &DebuggerIntegration::onStopRequested);
    }
}

void DebuggerIntegration::startDebugging(const QString& target) {
    START_SPAN("debug_session");
    
    m_currentTarget = target;
    m_isRunning = true;
    m_isPaused = false;
    if (m_panel) {
        m_panel->setPaused(false);
        m_panel->setStatus("Debugging: " + target);
    }
    LOG_INFO("Debugging started", {{"target", target}});
    emit targetStarted(target);
}

void DebuggerIntegration::stopDebugging() {
    END_SPAN("debug_session", {{"target", m_currentTarget}});
    
    m_isRunning = false;
    m_isPaused = false;
    if (m_panel) {
        m_panel->setPaused(false);
        m_panel->setStatus("Ready");
    }
    LOG_INFO("Debugging stopped");
    emit targetStopped(m_currentTarget);
}

void DebuggerIntegration::pause() {
    if (!m_isRunning || m_isPaused) return;
    m_isPaused = true;
    if (m_panel) {
        m_panel->setPaused(true);
        updateVariables();
        updateCallStack();
    }
}

void DebuggerIntegration::resume() {
    if (!m_isRunning || !m_isPaused) return;
    m_isPaused = false;
    if (m_panel) {
        m_panel->setPaused(false);
    }
}

void DebuggerIntegration::stepOver() {
    if (!m_isRunning || !m_isPaused) return;
    
    QElapsedTimer timer;
    timer.start();
    
    LOG_DEBUG("Debugger: Step Over");
    // Simulate step and update UI
    updateVariables();
    updateCallStack();
    
    qint64 duration = timer.elapsed();
    LOG_METRIC("debugger_step_duration", duration, {{"type", "step_over"}});
    LOG_COUNTER("debugger_steps_total", 1, {{"type", "step_over"}});
}

void DebuggerIntegration::stepInto() {
    if (!m_isRunning || !m_isPaused) return;
    
    QElapsedTimer timer;
    timer.start();
    
    LOG_DEBUG("Debugger: Step Into");
    // Simulate step and update UI
    updateVariables();
    updateCallStack();
    
    qint64 duration = timer.elapsed();
    LOG_METRIC("debugger_step_duration", duration, {{"type", "step_into"}});
    LOG_COUNTER("debugger_steps_total", 1, {{"type", "step_into"}});
}

void DebuggerIntegration::stepOut() {
    if (!m_isRunning || !m_isPaused) return;
    
    QElapsedTimer timer;
    timer.start();
    
    LOG_DEBUG("Debugger: Step Out");
    // Simulate step and update UI
    updateVariables();
    updateCallStack();
    
    qint64 duration = timer.elapsed();
    LOG_METRIC("debugger_step_duration", duration, {{"type", "step_out"}});
    LOG_COUNTER("debugger_steps_total", 1, {{"type", "step_out"}});
}

void DebuggerIntegration::toggleBreakpoint(const QString& file, int line) {
    for (int i = 0; i < m_breakpoints.size(); ++i) {
        if (m_breakpoints[i].file == file && m_breakpoints[i].line == line) {
            m_breakpoints.erase(m_breakpoints.begin() + i);
            LOG_DEBUG("Breakpoint removed", {{"file", file}, {"line", line}});
            return;
        }
    }
    m_breakpoints.append({file, line, true});
    LOG_DEBUG("Breakpoint added", {{"file", file}, {"line", line}});
}

void DebuggerIntegration::clearAllBreakpoints() {
    m_breakpoints.clear();
}

void DebuggerIntegration::updateVariables() {
    if (!m_panel) return;
    
    QVector<DebugVariable> vars;
    vars.append({"this", "0x0045FF10", "MainWindow*", true, {
        {"m_isRunning", "true", "bool", false, {}},
        {"m_activeModel", "\"Llama-3-8B\"", "QString", false, {}}
    }});
    vars.append({"argc", "1", "int", false, {}});
    vars.append({"argv", "0x0045FF20", "char**", false, {}});
    
    m_panel->updateVariables(vars);
}

void DebuggerIntegration::updateCallStack() {
    if (!m_panel) return;
    
    QVector<DebugStackFrame> stack;
    stack.append({"MainWindow::onRunWorkflow", "MainWindow_v5.cpp", 605, 0x401234});
    stack.append({"QtPrivate::QSlotObjectBase::call", "qobject_impl.h", 124, 0x405678});
    stack.append({"QMetaObject::activate", "qobject.cpp", 3946, 0x7654321});
    
    m_panel->updateCallStack(stack);
}

void DebuggerIntegration::evaluateExpression(const QString& expression) {
    LOG_DEBUG("Evaluating expression", {{"expression", expression}});
}

void DebuggerIntegration::onContinueRequested() { resume(); }
void DebuggerIntegration::onStepOverRequested() { stepOver(); }
void DebuggerIntegration::onStepIntoRequested() { stepInto(); }
void DebuggerIntegration::onStepOutRequested() { stepOut(); }
void DebuggerIntegration::onStopRequested() { stopDebugging(); }

} // namespace RawrXD
