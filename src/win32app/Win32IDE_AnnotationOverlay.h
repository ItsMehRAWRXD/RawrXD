// Win32IDE_AnnotationOverlay.h — Annotation Overlay Declarations (Batch 6 C02)
#pragma once

class Win32IDE;

void Win32IDE_initAnnotationOverlay();
void Win32IDE_showAnnotationOverlay();
void Win32IDE_hideAnnotationOverlay();
bool Win32IDE_isAnnotationOverlayVisible();
void Win32IDE_addAnnotationOverlayItem(int line, const std::string& message, int severity);
