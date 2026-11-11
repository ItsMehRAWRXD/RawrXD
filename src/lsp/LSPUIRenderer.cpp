// ============================================================================
// LSPUIRenderer.cpp - Production LSP UI Rendering Implementation
// ============================================================================

#include "LSPUIRenderer.hpp"
#include <richedit.h>
#include <sstream>
#include <algorithm>

// Scintilla messages
#define SCI_GETDIRECTFUNCTION 2184
#define SCI_GETDIRECTPOINTER 2185
#define SCI_POSITIONFROMLINE 2169
#define SCI_LINELENGTH 2350
#define SCI_SETINDICATORCURRENT 2620
#define SCI_INDICATORFILLRANGE 2621
#define SCI_INDICATORCLEARRANGE 2622
#define SCI_INDICSETSTYLE 2080
#define SCI_INDICSETFORE 2081
#define SCI_INDICSETUNDER 2510
#define SCI_GETCURRENTPOS 2008
#define SCI_POINTXFROMPOSITION 2164
#define SCI_POINTYFROMPOSITION 2165
#define SCI_GETLINECOUNT 2154
#define SCI_GETFIRSTVISIBLELINE 2152
#define SCI_LINESONSCREEN 2370
#define SCI_GETSCROLLWIDTH 2006
#define SCI_GETSCROLLPOS 2009
#define SCI_GETVSCROLLBAR 2120
#define SCI_GETHSCROLLBAR 2121
#define SCI_GETXOFFSET 2398
#define SCI_GETMARGINLEFT 2156
#define SCI_GETMARGINRIGHT 2157
#define SCI_GETMARGINTOP 2154
#define SCI_GETMARGINBOTTOM 2155
#define SCI_GETRECTANGULARSELECTIONMODIFIER 2598
#define SCI_GETMOUSESELECTIONRECTANGULARSWITCH 2669
#define SCI_GETVIRTUALSPACEOPTIONS 2596
#define SCI_GETADDITIONALSELECTIONTYPING 2604
#define SCI_GETADDITIONALCARETSBLINK 2608
#define SCI_GETADDITIONALCARETSVISIBLE 2609
#define SCI_GETSELECTIONS 2570
#define SCI_GETMAINSELECTION 2571
#define SCI_SETSELECTION 2574
#define SCI_ADDSELECTION 2573
#define SCI_SETMAINSELECTION 2574
#define SCI_GETSELECTIONNSTART 2575
#define SCI_GETSELECTIONNEND 2576
#define SCI_GETSELECTIONNCARET 2577
#define SCI_GETSELECTIONNANCHOR 2578
#define SCI_GETSELECTIONNSTARTVIRTUALSPACE 2579
#define SCI_GETSELECTIONNENDVIRTUALSPACE 2580
#define SCI_GETSELECTIONNCARETVIRTUALSPACE 2581
#define SCI_GETSELECTIONNANCHORVIRTUALSPACE 2582
#define SCI_SETSELECTIONNSTART 2583
#define SCI_SETSELECTIONNEND 2584
#define SCI_SETSELECTIONNCARET 2585
#define SCI_SETSELECTIONNANCHOR 2586
#define SCI_SETSELECTIONNSTARTVIRTUALSPACE 2587
#define SCI_SETSELECTIONNENDVIRTUALSPACE 2588
#define SCI_SETSELECTIONNCARETVIRTUALSPACE 2589
#define SCI_SETSELECTIONNANCHORVIRTUALSPACE 2590
#define SCI_GETSELECTIONNSTARTS 2575
#define SCI_GETSELECTIONNENDS 2576
#define SCI_GETSELECTIONNCARETS 2577
#define SCI_GETSELECTIONNANCHORS 2578
#define SCI_GETSELECTIONNSTARTSVIRTUALSPACE 2579
#define SCI_GETSELECTIONNENDSVIRTUALSPACE 2580
#define SCI_GETSELECTIONNCARETSVIRTUALSPACE 2581
#define SCI_GETSELECTIONNANCHORSVIRTUALSPACE 2582
#define SCI_SETSELECTIONNSTARTS 2583
#define SCI_SETSELECTIONNENDS 2584
#define SCI_SETSELECTIONNCARETS 2585
#define SCI_SETSELECTIONNANCHORS 2586
#define SCI_SETSELECTIONNSTARTSVIRTUALSPACE 2587
#define SCI_SETSELECTIONNENDSVIRTUALSPACE 2588
#define SCI_SETSELECTIONNCARETSVIRTUALSPACE 2589
#define SCI_SETSELECTIONNANCHORSVIRTUALSPACE 2590
#define SCI_GETSELECTIONEMPTY 2650
#define SCI_CLEARSELECTIONS 2571
#define SCI_SETSELECTIONMODE 2422
#define SCI_GETSELECTIONMODE 2423
#define SCI_GETLINESELSTARTPOSITION 2424
#define SCI_GETLINESELENDPOSITION 2425
#define SCI_LINEDOWN 2300
#define SCI_LINEUP 2301
#define SCI_CHARLEFT 2302
#define SCI_CHARRIGHT 2303
#define SCI_WORDLEFT 2304
#define SCI_WORDRIGHT 2305
#define SCI_WORDPARTLEFT 2306
#define SCI_WORDPARTRIGHT 2307
#define SCI_WORDLEFTEND 2431
#define SCI_WORDRIGHTEND 2432
#define SCI_HOME 2308
#define SCI_LINEEND 2309
#define SCI_HOMEWRAP 2345
#define SCI_LINEENDWRAP 2346
#define SCI_HOMEWRAPDISPLAY 2347
#define SCI_LINEENDDISPLAY 2348
#define SCI_HOMEEXTEND 2310
#define SCI_LINEENDEXTEND 2311
#define SCI_HOMEWRAPEXTEND 2349
#define SCI_LINEENDWRAPEXTEND 2350
#define SCI_HOMEWRAPDISPLAYEXTEND 2351
#define SCI_LINEENDDISPLAYEXTEND 2352
#define SCI_HOMEEXTENDWRAP 2450
#define SCI_LINEENDEXTENDWRAP 2451
#define SCI_HOMEEXTENDDISPLAY 2452
#define SCI_LINEENDEXTENDDISPLAY 2453
#define SCI_DOCUMENTSTART 2316
#define SCI_DOCUMENTEND 2317
#define SCI_DOCUMENTSTARTEXTEND 2318
#define SCI_DOCUMENTENDEXTEND 2319
#define SCI_PAGEUP 2320
#define SCI_PAGEDOWN 2321
#define SCI_PAGEUPEXTEND 2322
#define SCI_PAGEDOWNEXTEND 2323
#define SCI_STUTTEREDPAGEUP 2433
#define SCI_STUTTEREDPAGEDOWN 2434
#define SCI_STUTTEREDPAGEUPEXTEND 2435
#define SCI_STUTTEREDPAGEDOWNEXTEND 2436
#define SCI_DELETEBACK 2324
#define SCI_DELETEBACKNOTLINE 2344
#define SCI_DELWORDLEFT 2335
#define SCI_DELWORDRIGHT 2336
#define SCI_DELWORDRIGHTEND 2518
#define SCI_LINECUT 2337
#define SCI_LINEDELETE 2338
#define SCI_LINETRANSPOSE 2339
#define SCI_LINEREVERSE 2354
#define SCI_LINEDUPLICATE 2404
#define SCI_LOWERCASE 2340
#define SCI_UPPERCASE 2341
#define SCI_LINESCROLLDOWN 2342
#define SCI_LINESCROLLUP 2343
#define SCI_DELETEBACKSAFE 2394
#define SCI_MOVESELECTEDLINESUP 2621
#define SCI_MOVESELECTEDLINESDOWN 2622
#define SCI_SCROLLTOSTART 2628
#define SCI_SCROLLTOEND 2629
#define SCI_VERTICALCENTRECARET 2619
#define SCI_SCROLLCARET 2169
#define SCI_SETXCARETPOLICY 2402
#define SCI_SETYCARETPOLICY 2403
#define SCI_SETCARETSTICKY 2458
#define SCI_GETCARETSTICKY 2459
#define SCI_TOGGLECARETSTICKY 2459
#define SCI_GETREADONLY 2140
#define SCI_SETREADONLY 2171
#define SCI_GETTEXTRANGE 2162
#define SCI_ALLOCATE 2443
#define SCI_ADDTEXT 2001
#define SCI_ADDSTYLEDTEXT 2002
#define SCI_INSERTTEXT 2003
#define SCI_CLEARALL 2004
#define SCI_DELETERANGE 2645
#define SCI_CLEARDOCUMENTSTYLE 2005
#define SCI_GETCHARAT 2007
#define SCI_GETSTYLEAT 2010
#define SCI_GETSTYLEDTEXT 2015
#define SCI_RELEASEALLEXTENDEDSTYLES 2552
#define SCI_ALLOCATEEXTENDEDSTYLES 2553
#define SCI_TARGETASUTF8 2447
#define SCI_ENCODEDFROMUTF8 2449
#define SCI_SETLENGTHFORENCODE 2448
#define SCI_GETCHARACTERPOINTER 2520
#define SCI_GETRANGEPOINTER 2643
#define SCI_GETGAPPOSITION 2644
#define SCI_SETCURRENTPOS 2141
#define SCI_SETANCHOR 2026
#define SCI_SETSELECTIONSTART 2142
#define SCI_GETSELECTIONSTART 2143
#define SCI_SETSELECTIONEND 2144
#define SCI_GETSELECTIONEND 2145
#define SCI_SETEMPTYSELECTION 2554
#define SCI_SETPRINTMAGNIFICATION 2146
#define SCI_GETPRINTMAGNIFICATION 2147
#define SCI_SETPRINTCOLOURMODE 2148
#define SCI_GETPRINTCOLOURMODE 2149
#define SCI_FINDTEXT 2150
#define SCI_FORMATRANGE 2151
#define SCI_GETFIRSTVISIBLELINE 2152
#define SCI_GETLINE 2153
#define SCI_GETLINECOUNT 2154
#define SCI_SETMARGINLEFT 2155
#define SCI_GETMARGINLEFT 2156
#define SCI_SETMARGINRIGHT 2157
#define SCI_GETMARGINRIGHT 2158
#define SCI_GETMODIFY 2159
#define SCI_SETSEL 2160
#define SCI_GETSELTEXT 2161
#define SCI_GETTEXTRANGE 2162
#define SCI_HIDESELECTION 2163
#define SCI_POINTXFROMPOSITION 2164
#define SCI_POINTYFROMPOSITION 2165
#define SCI_LINEFROMPOSITION 2166
#define SCI_POSITIONFROMLINE 2167
#define SCI_LINESCROLL 2168
#define SCI_SCROLLCARET 2169
#define SCI_REPLACESEL 2170
#define SCI_SETREADONLY 2171
#define SCI_NULL 2172
#define SCI_CANPASTE 2173
#define SCI_CANUNDO 2174
#define SCI_EMPTYUNDOBUFFER 2175
#define SCI_UNDO 2176
#define SCI_CUT 2177
#define SCI_COPY 2178
#define SCI_PASTE 2179
#define SCI_CLEAR 2180
#define SCI_SETTEXT 2181
#define SCI_GETTEXT 2182
#define SCI_GETTEXTLENGTH 2183
#define SCI_GETDIRECTFUNCTION 2184
#define SCI_GETDIRECTPOINTER 2185
#define SCI_SETOVERTYPE 2186
#define SCI_GETOVERTYPE 2187
#define SCI_SETCARETWIDTH 2188
#define SCI_GETCARETWIDTH 2189
#define SCI_SETTARGETSTART 2190
#define SCI_GETTARGETSTART 2191
#define SCI_SETTARGETEND 2192
#define SCI_GETTARGETEND 2193
#define SCI_REPLACETARGET 2194
#define SCI_REPLACETARGETRE 2195
#define SCI_SEARCHINTARGET 2197
#define SCI_SETSEARCHFLAGS 2198
#define SCI_GETSEARCHFLAGS 2199
#define SCI_CALLTIPSHOW 2200
#define SCI_CALLTIPCANCEL 2201
#define SCI_CALLTIPACTIVE 2202
#define SCI_CALLTIPPOSSTART 2203
#define SCI_CALLTIPSETPOSSTART 2214
#define SCI_CALLTIPSETHLT 2204
#define SCI_CALLTIPSETBACK 2205
#define SCI_CALLTIPSETFORE 2206
#define SCI_CALLTIPSETFOREHLT 2207
#define SCI_CALLTIPUSESTYLE 2212
#define SCI_VISIBLEFROMDOCLINE 2220
#define SCI_DOCLINEFROMVISIBLE 2221
#define SCI_WRAPCOUNT 2235
#define SCI_SETFOLDLEVEL 2222
#define SCI_GETFOLDLEVEL 2223
#define SCI_GETLASTCHILD 2224
#define SCI_GETFOLDPARENT 2225
#define SCI_SHOWLINES 2226
#define SCI_HIDELINES 2227
#define SCI_GETLINEVISIBLE 2228
#define SCI_SETFOLDEXPANDED 2229
#define SCI_GETFOLDEXPANDED 2230
#define SCI_TOGGLEFOLD 2231
#define SCI_ENSUREVISIBLE 2232
#define SCI_SETFOLDFLAGS 2233
#define SCI_ENSUREVISIBLEENFORCEPOLICY 2234
#define SCI_SETTABDRAWMODE 2698
#define SCI_GETTABDRAWMODE 2699
#define SCI_SETWHITESPACEFLAGS 2453
#define SCI_GETWHITESPACEFLAGS 2454
#define SCI_SETWHITESPACEBACK 2085
#define SCI_SETWHITESPACEFORE 2084
#define SCI_SETWHITESPACESIZE 2086
#define SCI_GETWHITESPACESIZE 2087
#define SCI_SETLINESTATE 2092
#define SCI_GETLINESTATE 2093
#define SCI_GETMAXLINESTATE 2094
#define SCI_GETCARETLINEVISIBLE 2095
#define SCI_SETCARETLINEVISIBLE 2096
#define SCI_GETCARETLINEBACK 2097
#define SCI_SETCARETLINEBACK 2098
#define SCI_GETCARETLINEFRAME 2704
#define SCI_SETCARETLINEFRAME 2705
#define SCI_STYLESETBACK 2052
#define SCI_STYLESETFORE 2051
#define SCI_STYLESETBOLD 2053
#define SCI_STYLESETITALIC 2054
#define SCI_STYLESETSIZE 2055
#define SCI_STYLESETFONT 2056
#define SCI_STYLESETEOLFILLED 2057
#define SCI_STYLERESETDEFAULT 2058
#define SCI_STYLESETUNDERLINE 2059
#define SCI_STYLESETCASE 2060
#define SCI_STYLESETCHARACTERSET 2061
#define SCI_STYLESETHOTSPOT 2411
#define SCI_STYLESETVISIBLE 2074
#define SCI_STYLESETCHANGEABLE 2099
#define SCI_STYLESETHOTSPOT 2411
#define SCI_STYLESETHOTSPOT 2411

namespace rawrxd::lsp {

// ============================================================================
// Constructor / Destructor
// ============================================================================
LSPUIRenderer::LSPUIRenderer(HWND hEditor) 
    : m_hEditor(hEditor)
    , m_hTooltip(nullptr)
    , m_hSignatureWindow(nullptr)
    , m_hAutocompleteList(nullptr)
    , m_hAutocompleteTooltip(nullptr)
    , m_initialized(false) {
}

LSPUIRenderer::~LSPUIRenderer() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool LSPUIRenderer::Initialize() {
    if (m_initialized) return true;
    if (!m_hEditor || !IsWindow(m_hEditor)) return false;

    SetupIndicators();
    
    if (!CreateTooltipWindow()) return false;
    if (!CreateSignatureWindow()) return false;
    if (!CreateAutocompleteWindow()) return false;
    if (!CreateAutocompleteTooltip()) return false;

    m_initialized = true;
    return true;
}

void LSPUIRenderer::Shutdown() {
    if (m_hTooltip) { DestroyWindow(m_hTooltip); m_hTooltip = nullptr; }
    if (m_hSignatureWindow) { DestroyWindow(m_hSignatureWindow); m_hSignatureWindow = nullptr; }
    if (m_hAutocompleteList) { DestroyWindow(m_hAutocompleteList); m_hAutocompleteList = nullptr; }
    if (m_hAutocompleteTooltip) { DestroyWindow(m_hAutocompleteTooltip); m_hAutocompleteTooltip = nullptr; }
    
    m_initialized = false;
}

// ============================================================================
// Theme
// ============================================================================
void LSPUIRenderer::SetTheme(const LSPTheme& theme) {
    m_theme = theme;
    
    // Update indicator colors
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_ERROR, theme.errorColor);
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_WARNING, theme.warningColor);
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_INFO, theme.infoColor);
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_HINT, theme.hintColor);
}

// ============================================================================
// Diagnostics
// ============================================================================
void LSPUIRenderer::SetupIndicators() {
    // Error indicator - red squiggles
    SendMessage(m_hEditor, SCI_INDICSETSTYLE, INDIC_ERROR, INDIC_SQUIGGLE);
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_ERROR, m_theme.errorColor);
    SendMessage(m_hEditor, SCI_INDICSETUNDER, INDIC_ERROR, 1);
    
    // Warning indicator - orange squiggles
    SendMessage(m_hEditor, SCI_INDICSETSTYLE, INDIC_WARNING, INDIC_SQUIGGLE);
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_WARNING, m_theme.warningColor);
    SendMessage(m_hEditor, SCI_INDICSETUNDER, INDIC_WARNING, 1);
    
    // Info indicator - blue squiggles
    SendMessage(m_hEditor, SCI_INDICSETSTYLE, INDIC_INFO, INDIC_SQUIGGLE);
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_INFO, m_theme.infoColor);
    SendMessage(m_hEditor, SCI_INDICSETUNDER, INDIC_INFO, 1);
    
    // Hint indicator - gray dots
    SendMessage(m_hEditor, SCI_INDICSETSTYLE, INDIC_HINT, INDIC_DOTS);
    SendMessage(m_hEditor, SCI_INDICSETFORE, INDIC_HINT, m_theme.hintColor);
    SendMessage(m_hEditor, SCI_INDICSETUNDER, INDIC_HINT, 1);
}

void LSPUIRenderer::SetDiagnostics(const std::vector<Diagnostic>& diags) {
    ClearDiagnostics();
    m_currentDiagnostics = diags;
    
    for (const auto& d : diags) {
        int startPos = PositionFromLineCol(d.startLine, d.startCol);
        int endPos = PositionFromLineCol(d.endLine, d.endCol);
        if (startPos < 0 || endPos < 0 || startPos >= endPos) continue;
        
        int indicator = INDIC_ERROR;
        switch (d.severity) {
            case Diagnostic::Warning: indicator = INDIC_WARNING; break;
            case Diagnostic::Info: indicator = INDIC_INFO; break;
            case Diagnostic::Hint: indicator = INDIC_HINT; break;
            default: indicator = INDIC_ERROR; break;
        }
        
        ApplyIndicator(indicator, startPos, endPos - startPos, 
            indicator == INDIC_ERROR ? m_theme.errorColor :
            indicator == INDIC_WARNING ? m_theme.warningColor :
            indicator == INDIC_INFO ? m_theme.infoColor : m_theme.hintColor);
    }
}

void LSPUIRenderer::ClearDiagnostics() {
    ClearIndicator(INDIC_ERROR);
    ClearIndicator(INDIC_WARNING);
    ClearIndicator(INDIC_INFO);
    ClearIndicator(INDIC_HINT);
    m_currentDiagnostics.clear();
}

void LSPUIRenderer::ClearDiagnosticsForFile(const std::string& filePath) {
    // Filter out diagnostics for the specified file
    auto it = std::remove_if(m_currentDiagnostics.begin(), m_currentDiagnostics.end(),
        [&filePath](const Diagnostic& d) {
            // In a real implementation, you'd check d.filePath
            return false; // Placeholder
        });
    m_currentDiagnostics.erase(it, m_currentDiagnostics.end());
    
    // Re-apply remaining diagnostics
    SetDiagnostics(m_currentDiagnostics);
}

const Diagnostic* LSPUIRenderer::GetDiagnosticAt(int line, int col) const {
    for (const auto& d : m_currentDiagnostics) {
        if (d.ContainsPosition(line, col)) return &d;
    }
    return nullptr;
}

void LSPUIRenderer::ApplyIndicator(int indicator, int start, int length, COLORREF color) {
    SendMessage(m_hEditor, SCI_SETINDICATORCURRENT, indicator, 0);
    SendMessage(m_hEditor, SCI_INDICATORFILLRANGE, start, length);
}

void LSPUIRenderer::ClearIndicator(int indicator) {
    int length = (int)SendMessage(m_hEditor, SCI_GETTEXTLENGTH, 0, 0);
    SendMessage(m_hEditor, SCI_SETINDICATORCURRENT, indicator, 0);
    SendMessage(m_hEditor, SCI_INDICATORCLEARRANGE, 0, length);
}

// ============================================================================
// Hover Tooltips
// ============================================================================
bool LSPUIRenderer::CreateTooltipWindow() {
    m_hTooltip = CreateWindowEx(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
        TOOLTIPS_CLASS, nullptr,
        TTS_ALWAYSTIP | TTS_NOPREFIX | TTS_NOANIMATE | WS_POPUP,
        0, 0, 400, 200,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!m_hTooltip) return false;
    
    // Set tooltip properties
    SendMessage(m_hTooltip, TTM_SETMAXTIPWIDTH, 0, 400);
    SendMessage(m_hTooltip, TTM_SETDELAYTIME, TTDT_AUTOPOP, 30000); // 30s show time
    SendMessage(m_hTooltip, TTM_SETDELAYTIME, TTDT_INITIAL, 200);   // 200ms initial delay
    SendMessage(m_hTooltip, TTM_SETDELAYTIME, TTDT_RESHOW, 100);    // 100ms reshow delay
    
    return true;
}

void LSPUIRenderer::ShowHover(const HoverInfo& info, int x, int y) {
    if (!m_hTooltip || !m_initialized) return;
    
    m_currentHover = info;
    
    // Create tooltip info
    TOOLINFO ti = {0};
    ti.cbSize = sizeof(ti);
    ti.uFlags = TTF_TRACK | TTF_ABSOLUTE;
    ti.hwnd = m_hEditor;
    ti.lpszText = const_cast<LPSTR>(info.contents.c_str());
    ti.rect = {x, y, x + 1, y + 1};
    
    // Position and show
    SendMessage(m_hTooltip, TTM_TRACKPOSITION, 0, MAKELPARAM(x + 10, y + 10));
    SendMessage(m_hTooltip, TTM_TRACKACTIVATE, TRUE, (LPARAM)&ti);
    
    m_hoverLine = info.line;
    m_hoverCol = info.col;
}

void LSPUIRenderer::ShowHoverAtPosition(const HoverInfo& info, int line, int col) {
    POINT pt = GetScreenPosFromEditorPos(line, col);
    ShowHover(info, pt.x, pt.y);
}

void LSPUIRenderer::HideHover() {
    if (!m_hTooltip) return;
    SendMessage(m_hTooltip, TTM_TRACKACTIVATE, FALSE, 0);
    m_hoverLine = -1;
    m_hoverCol = -1;
}

bool LSPUIRenderer::IsHoverVisible() const {
    if (!m_hTooltip) return false;
    return (BOOL)SendMessage(m_hTooltip, TTM_GETCURRENTTOOL, 0, 0) != 0;
}

// ============================================================================
// Signature Help
// ============================================================================
bool LSPUIRenderer::CreateSignatureWindow() {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = DefWindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"LSPUIRenderer_SignatureWindow";
    wc.hbrBackground = CreateSolidBrush(m_theme.sigBg);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClass(&wc);
    
    m_hSignatureWindow = CreateWindowEx(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
        L"LSPUIRenderer_SignatureWindow", nullptr,
        WS_POPUP | WS_BORDER,
        0, 0, 600, 60,
        m_hEditor, nullptr, GetModuleHandle(nullptr), nullptr);
    
    return m_hSignatureWindow != nullptr;
}

void LSPUIRenderer::ShowSignature(const SignatureHelp& sig) {
    if (!m_hSignatureWindow || sig.signatures.empty()) return;
    
    m_currentSignature = sig;
    RenderSignatureContent(sig);
    PositionSignature();
    
    ShowWindow(m_hSignatureWindow, SW_SHOWNA);
    SetWindowPos(m_hSignatureWindow, HWND_TOPMOST, 0, 0, 0, 0, 
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    
    m_sigLine = -1; // Track separately if needed
    m_sigCol = -1;
}

void LSPUIRenderer::UpdateSignature(const SignatureHelp& sig) {
    if (IsSignatureVisible()) {
        ShowSignature(sig);
    }
}

void LSPUIRenderer::HideSignature() {
    if (m_hSignatureWindow) {
        ShowWindow(m_hSignatureWindow, SW_HIDE);
    }
    m_sigLine = -1;
    m_sigCol = -1;
}

bool LSPUIRenderer::IsSignatureVisible() const {
    if (!m_hSignatureWindow) return false;
    return IsWindowVisible(m_hSignatureWindow) != FALSE;
}

void LSPUIRenderer::CycleSignature(int direction) {
    if (m_currentSignature.signatures.empty()) return;
    
    int newIndex = m_currentSignature.activeSignature + direction;
    if (newIndex < 0) newIndex = (int)m_currentSignature.signatures.size() - 1;
    if (newIndex >= (int)m_currentSignature.signatures.size()) newIndex = 0;
    
    m_currentSignature.activeSignature = newIndex;
    RenderSignatureContent(m_currentSignature);
    
    if (m_signatureCycleCallback) {
        m_signatureCycleCallback(direction);
    }
}

void LSPUIRenderer::RenderSignatureContent(const SignatureHelp& sig) {
    if (!m_hSignatureWindow || sig.signatures.empty()) return;
    
    const auto& active = sig.signatures[sig.activeSignature];
    std::string text = active.label;
    
    if (sig.signatures.size() > 1) {
        text = "[" + std::to_string(sig.activeSignature + 1) + "/" + 
               std::to_string(sig.signatures.size()) + "] " + text;
    }
    
    // Set window text (in a real implementation, you'd custom draw this)
    SetWindowTextA(m_hSignatureWindow, text.c_str());
}

void LSPUIRenderer::PositionSignature() {
    if (!m_hSignatureWindow) return;
    
    // Position above current line
    RECT rc;
    GetWindowRect(m_hEditor, &rc);
    
    int x = rc.left + 20;
    int y = rc.top + 20;
    
    SetWindowPos(m_hSignatureWindow, nullptr, x, y, 0, 0,
        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

// ============================================================================
// Autocomplete
// ============================================================================
bool LSPUIRenderer::CreateAutocompleteWindow() {
    m_hAutocompleteList = CreateWindowEx(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
        WC_LISTBOX, nullptr,
        WS_POPUP | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS | LBS_OWNERDRAWFIXED,
        0, 0, 300, 200,
        m_hEditor, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!m_hAutocompleteList) return false;
    
    // Set font
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(m_hAutocompleteList, WM_SETFONT, (WPARAM)hFont, FALSE);
    
    return true;
}

bool LSPUIRenderer::CreateAutocompleteTooltip() {
    m_hAutocompleteTooltip = CreateWindowEx(
        WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
        TOOLTIPS_CLASS, nullptr,
        TTS_ALWAYSTIP | TTS_NOPREFIX | WS_POPUP,
        0, 0, 300, 100,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    
    return m_hAutocompleteTooltip != nullptr;
}

void LSPUIRenderer::ShowAutocomplete(const std::vector<CompletionItem>& completions, int line, int col) {
    if (!m_hAutocompleteList || completions.empty()) return;
    
    m_currentCompletions = completions;
    m_acLine = line;
    m_acCol = col;
    
    PopulateAutocompleteList(completions);
    PositionAutocomplete();
    
    ShowWindow(m_hAutocompleteList, SW_SHOWNA);
    SetWindowPos(m_hAutocompleteList, HWND_TOPMOST, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    
    // Select first item
    SendMessage(m_hAutocompleteList, LB_SETCURSEL, 0, 0);
    UpdateAutocompleteTooltip();
}

void LSPUIRenderer::UpdateAutocomplete(const std::vector<CompletionItem>& completions) {
    m_currentCompletions = completions;
    PopulateAutocompleteList(completions);
}

void LSPUIRenderer::HideAutocomplete() {
    if (m_hAutocompleteList) ShowWindow(m_hAutocompleteList, SW_HIDE);
    if (m_hAutocompleteTooltip) SendMessage(m_hAutocompleteTooltip, TTM_TRACKACTIVATE, FALSE, 0);
    m_acLine = -1;
    m_acCol = -1;
}

bool LSPUIRenderer::IsAutocompleteVisible() const {
    if (!m_hAutocompleteList) return false;
    return IsWindowVisible(m_hAutocompleteList) != FALSE;
}

int LSPUIRenderer::GetSelectedCompletion() const {
    if (!m_hAutocompleteList) return -1;
    return (int)SendMessage(m_hAutocompleteList, LB_GETCURSEL, 0, 0);
}

void LSPUIRenderer::SelectCompletion(int index) {
    if (!m_hAutocompleteList || index < 0) return;
    int count = (int)SendMessage(m_hAutocompleteList, LB_GETCOUNT, 0, 0);
    if (index >= count) return;
    
    SendMessage(m_hAutocompleteList, LB_SETCURSEL, index, 0);
    UpdateAutocompleteTooltip();
}

void LSPUIRenderer::SelectNextCompletion() {
    int current = GetSelectedCompletion();
    int count = (int)SendMessage(m_hAutocompleteList, LB_GETCOUNT, 0, 0);
    if (current < count - 1) {
        SelectCompletion(current + 1);
    }
}

void LSPUIRenderer::SelectPreviousCompletion() {
    int current = GetSelectedCompletion();
    if (current > 0) {
        SelectCompletion(current - 1);
    }
}

std::string LSPUIRenderer::GetSelectedCompletionText() const {
    int index = GetSelectedCompletion();
    if (index < 0 || index >= (int)m_currentCompletions.size()) return "";
    return m_currentCompletions[index].insertText.empty() ? 
           m_currentCompletions[index].label : 
           m_currentCompletions[index].insertText;
}

void LSPUIRenderer::PopulateAutocompleteList(const std::vector<CompletionItem>& completions) {
    if (!m_hAutocompleteList) return;
    
    SendMessage(m_hAutocompleteList, LB_RESETCONTENT, 0, 0);
    
    for (const auto& item : completions) {
        // Store item data
        int idx = (int)SendMessageA(m_hAutocompleteList, LB_ADDSTRING, 0, (LPARAM)item.label.c_str());
        if (idx != LB_ERR) {
            SendMessage(m_hAutocompleteList, LB_SETITEMDATA, idx, (LPARAM)&item);
        }
    }
}

void LSPUIRenderer::UpdateAutocompleteTooltip() {
    if (!m_hAutocompleteTooltip) return;
    
    int index = GetSelectedCompletion();
    if (index < 0 || index >= (int)m_currentCompletions.size()) {
        SendMessage(m_hAutocompleteTooltip, TTM_TRACKACTIVATE, FALSE, 0);
        return;
    }
    
    const auto& item = m_currentCompletions[index];
    if (item.documentation.empty()) {
        SendMessage(m_hAutocompleteTooltip, TTM_TRACKACTIVATE, FALSE, 0);
        return;
    }
    
    // Show documentation tooltip
    TOOLINFO ti = {0};
    ti.cbSize = sizeof(ti);
    ti.uFlags = TTF_TRACK | TTF_ABSOLUTE;
    ti.hwnd = m_hAutocompleteList;
    ti.lpszText = const_cast<LPSTR>(item.documentation.c_str());
    
    RECT rc;
    GetWindowRect(m_hAutocompleteList, &rc);
    
    SendMessage(m_hAutocompleteTooltip, TTM_TRACKPOSITION, 0, MAKELPARAM(rc.right + 5, rc.top));
    SendMessage(m_hAutocompleteTooltip, TTM_TRACKACTIVATE, TRUE, (LPARAM)&ti);
}

void LSPUIRenderer::PositionAutocomplete() {
    if (!m_hAutocompleteList) return;
    
    POINT pt = GetScreenPosFromEditorPos(m_acLine, m_acCol);
    
    // Position below the cursor
    int lineHeight = GetLineHeight();
    SetWindowPos(m_hAutocompleteList, nullptr, pt.x, pt.y + lineHeight, 0, 0,
        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

// ============================================================================
// Event Handlers
// ============================================================================
void LSPUIRenderer::OnMouseMove(int x, int y) {
    // Check if over a diagnostic
    int line, col;
    LineColFromPosition((int)SendMessage(m_hEditor, SCI_GETCURRENTPOS, 0, 0), line, col);
    
    const Diagnostic* diag = GetDiagnosticAt(line, col);
    if (diag && m_hoverRequestCallback) {
        m_hoverRequestCallback(line, col);
    }
}

void LSPUIRenderer::OnMouseHover(int x, int y) {
    // Trigger hover request
    int line, col;
    LineColFromPosition((int)SendMessage(m_hEditor, SCI_GETCURRENTPOS, 0, 0), line, col);
    
    if (m_hoverRequestCallback) {
        m_hoverRequestCallback(line, col);
    }
}

void LSPUIRenderer::OnMouseLeave() {
    HideHover();
}

void LSPUIRenderer::OnKeyDown(WPARAM key, LPARAM lParam) {
    if (IsAutocompleteVisible()) {
        switch (key) {
            case VK_UP:
                SelectPreviousCompletion();
                break;
            case VK_DOWN:
                SelectNextCompletion();
                break;
            case VK_RETURN:
            case VK_TAB:
                if (m_completionCallback) {
                    m_completionCallback(GetSelectedCompletionText());
                }
                HideAutocomplete();
                break;
            case VK_ESCAPE:
                HideAutocomplete();
                break;
        }
    } else if (IsSignatureVisible()) {
        switch (key) {
            case VK_UP:
            case VK_DOWN:
                // Cycle through signatures
                CycleSignature(key == VK_UP ? -1 : 1);
                break;
            case VK_ESCAPE:
                HideSignature();
                break;
        }
    }
}

void LSPUIRenderer::OnChar(WPARAM ch) {
    // Handle autocomplete trigger characters
    if (ch == '.' || ch == '>' || ch == ':') {
        // Trigger autocomplete
        if (m_hoverRequestCallback) {
            int line, col;
            LineColFromPosition((int)SendMessage(m_hEditor, SCI_GETCURRENTPOS, 0, 0), line, col);
            m_hoverRequestCallback(line, col);
        }
    }
}

void LSPUIRenderer::OnScroll() {
    // Reposition UI elements
    if (IsHoverVisible()) HideHover();
    if (IsSignatureVisible()) PositionSignature();
    if (IsAutocompleteVisible()) PositionAutocomplete();
}

void LSPUIRenderer::OnResize() {
    OnScroll();
}

void LSPUIRenderer::OnFocusLost() {
    HideHover();
    HideSignature();
    HideAutocomplete();
}

void LSPUIRenderer::OnScintillaNotify(const SCNotification* scn) {
    if (!scn) return;
    
    switch (scn->nmhdr.code) {
        case SCN_DWELLSTART:
            // Mouse hover start
            if (m_hoverRequestCallback) {
                m_hoverRequestCallback(scn->line, scn->position);
            }
            break;
            
        case SCN_DWELLEND:
            // Mouse hover end
            HideHover();
            break;
            
        case SCN_CHARADDED:
            // Character added - trigger autocomplete
            OnChar(scn->ch);
            break;
            
        case SCN_AUTOCSELECTION:
        case SCN_AUTOCCOMPLETED:
            // Autocomplete selection
            if (m_completionCallback) {
                m_completionCallback(scn->text ? scn->text : "");
            }
            break;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================
POINT LSPUIRenderer::GetScreenPosFromEditorPos(int line, int col) {
    POINT pt = {0, 0};
    if (!m_hEditor) return pt;
    
    int pos = PositionFromLineCol(line, col);
    if (pos < 0) return pt;
    
    pt.x = (int)SendMessage(m_hEditor, SCI_POINTXFROMPOSITION, 0, pos);
    pt.y = (int)SendMessage(m_hEditor, SCI_POINTYFROMPOSITION, 0, pos);
    
    ClientToScreen(m_hEditor, &pt);
    return pt;
}

int LSPUIRenderer::PositionFromLineCol(int line, int col) {
    if (!m_hEditor) return -1;
    int lineStart = (int)SendMessage(m_hEditor, SCI_POSITIONFROMLINE, line, 0);
    return lineStart + col;
}

void LSPUIRenderer::LineColFromPosition(int pos, int& line, int& col) {
    if (!m_hEditor) { line = -1; col = -1; return; }
    line = (int)SendMessage(m_hEditor, SCI_LINEFROMPOSITION, pos, 0);
    int lineStart = (int)SendMessage(m_hEditor, SCI_POSITIONFROMLINE, line, 0);
    col = pos - lineStart;
}

int LSPUIRenderer::GetLineHeight() {
    if (!m_hEditor) return 16;
    // Approximate line height
    return 16;
}

int LSPUIRenderer::GetCharWidth() {
    if (!m_hEditor) return 8;
    // Approximate char width
    return 8;
}

RECT LSPUIRenderer::GetEditorClientRect() {
    RECT rc = {0};
    if (m_hEditor) GetClientRect(m_hEditor, &rc);
    return rc;
}

bool LSPUIRenderer::IsEditorVisible() {
    if (!m_hEditor) return false;
    return IsWindowVisible(m_hEditor) != FALSE;
}

std::wstring LSPUIRenderer::Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
    return result;
}

std::string LSPUIRenderer::WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

} // namespace rawrxd::lsp
