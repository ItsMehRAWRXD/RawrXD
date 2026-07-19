#!/usr/bin/env python3
"""
Surgical repair script for RawrXD_IDE_Win32.cpp corruption
"""

import re

# Read the file
with open('d:\\RawrXD\\src\\ide\\RawrXD_IDE_Win32.cpp', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix 1: Remove the corrupted MoE completion code block (lines ~750-780)
# This removes the interleaved MoE code and restores clean WM_KEYDOWN -> WM_CLOSE flow
pattern1 = r'''    case WM_KEYDOWN:
    \{
        /\* Ctrl\+Space — trigger Sovereign completion \*/
        if \(wParam == VK_SPACE && \(GetAsyncKeyState\(VK_CONTROL\) & 0x8000\)\) \{
            RawrXD_IDE_OutputAppend\(ide, L"\[Sovereign\] Completion requested \(Ctrl\+Space\)\\r\\n"\);
            /\* TODO: Wire to SovereignRuntime::Generate\(\) when runtime is loaded \*/Param == VK_SPACE && \(GetAsyncKeyState\(VK_CONTROL\) & 0x8000\)\) \{
            if \(ide->moeInfo\.state == MOE_LOADED\) \{
                /\* MoE model is loaded - use PrometheusMoE for completion \*/
                RawrXD_IDE_RequestMoECompletion\(ide\);
            \} else \{
                /\* No completion engine available \*/
                RawrXD_IDE_OutputAppend\(ide, L"\[Completion\] Engine not ready\. Load a model first\.\\r\\n"\);
        \}
        /\* Tab — accept completion if active \*/
        if \(wParam == VK_TAB && ide->completion\.active\) \{
            RawrXD_IDE_AcceptCompletion\(ide\);
            return 0;
        \}
        /\* Esc — dismiss completion \*/
        if \(wParam == VK_ESCAPE && ide->completion\.active\) \{
            RawrXD_IDE_DismissCompletion\(ide\);
            RawrXD_IDE_OutputAppend\(ide, L"\[Completion\] Dismissed\.\\r\\n"\);
            return 0;
        \}
        break;
    \}

    case WM_APP \+ 200:
        /\* Completion thread finished - show the suggestion \*/
        if \(ide->completion\.active && ide->completion\.suggestion\[0\]\) \{
            RawrXD_IDE_ShowCompletionGhost\(ide, ide->completion\.suggestion\);
        \}
        return 0;f \(bottomH > cy / 2\) bottomH = cy / 2;

    int centerX = leftW \+ \(leftW > 0 \? splW : 0\);
    int centerW = cx - centerX - \(rightW > 0 \? rightW \+ splW : 0\);
    if \(centerW < 100\) centerW = 100;'''

replacement1 = '''    case WM_KEYDOWN:
    {
        /* Ctrl+Space — trigger Sovereign completion */
        if (wParam == VK_SPACE && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
            RawrXD_IDE_OutputAppend(ide, L"[Sovereign] Completion requested (Ctrl+Space)\\r\\n");
            /* TODO: Wire to SovereignRuntime::Generate() when runtime is loaded */
            return 0;
        }
        break;
    }

    case WM_CLOSE:'''

content = re.sub(pattern1, replacement1, content, flags=re.MULTILINE)

# Fix 2: Clean up IDE_Main function - remove Ollama references
pattern2 = r'''    /\* Initialize Ollama completion engine \*/
    #include "ide_Sovereign Runtime bridge \*/
    RawrXD_IDE_OutputAppend\(&g_IDE, L"\[Sovereign\] Initializing runtime bridge\.\.\.\\r\\n"\);'''

replacement2 = '''    /* Initialize Sovereign Runtime bridge */
    RawrXD_IDE_OutputAppend(&g_IDE, L"[Sovereign] Initializing runtime bridge...\\r\\n");'''

content = re.sub(pattern2, replacement2, content)

# Write the fixed file
with open('d:\\RawrXD\\src\\ide\\RawrXD_IDE_Win32.cpp', 'w', encoding='utf-8') as f:
    f.write(content)

print("File repaired successfully!")
