// Win32IDE_AnnotationOverlay.cpp — Annotation Overlay (Batch 6 C02)
// Code comments and inline discussions
#include "Win32IDE.h"
#include "AnnotationOverlay.h"

namespace RawrXD {
namespace UI {

} // namespace UI
} // namespace RawrXD

void Win32IDE::initAnnotationOverlay() {
    if (m_annotationOverlay) return;
    m_annotationOverlay = std::make_unique<RawrXD::UI::AnnotationOverlay>(this);
    if (m_hwndEditor && m_annotationOverlay) {
        m_annotationOverlay->Initialize(m_hwndEditor);
    }
    appendToOutput("[AnnotationOverlay] Diagnostic overlay initialized.\n", "Output", Win32IDE::OutputSeverity::Info);
}

void Win32IDE::showAnnotationOverlay() {
    if (m_annotationOverlay) {
        m_annotationOverlay->SetVisible(true);
    }
}

void Win32IDE::hideAnnotationOverlay() {
    if (m_annotationOverlay) {
        m_annotationOverlay->SetVisible(false);
    }
}

bool Win32IDE::isAnnotationOverlayVisible() const {
    return m_annotationOverlay && m_annotationOverlay->IsVisible();
}

void Win32IDE::addAnnotationOverlayItem(int line, const std::string& message, OutputSeverity severity) {
    if (!m_annotationOverlay) return;
    RawrXD::UI::AnnotationItem item;
    item.line = line;
    item.startColumn = 0;
    item.endColumn = 0;
    item.severity = RawrXD::UI::DiagnosticSeverity::Error;
    item.message = message;
    item.isActive = true;
    m_annotationOverlay->AddAnnotation(item);
}
