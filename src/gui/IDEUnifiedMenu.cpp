//==============================================================================
// IDEUnifiedMenu.cpp - Sovereign IDE Unified Menu System Implementation
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#include "IDEUnifiedMenu.h"
#include "MoEPanel.h"
#include "MoEDiagnosticsPanel.h"
#include "MoEDebuggerPanel.h"
#include "MoEHeatmapPanel.h"
#include "MoESpecExplorerPanel.h"
#include "MASMEditorPanel.h"

// Static members
MenuCategory IDEUnifiedMenu::s_categories[IDEUnifiedMenu::MAX_CATEGORIES];
unsigned int IDEUnifiedMenu::s_categoryCount = 0;
bool IDEUnifiedMenu::s_initialized = false;

// Static storage for menu items (no dynamic allocation)
static MenuItem s_fileItems[IDEUnifiedMenu::MAX_ITEMS_PER_CATEGORY];
static MenuItem s_viewItems[IDEUnifiedMenu::MAX_ITEMS_PER_CATEGORY];
static MenuItem s_toolsItems[IDEUnifiedMenu::MAX_ITEMS_PER_CATEGORY];
static MenuItem s_moeItems[IDEUnifiedMenu::MAX_ITEMS_PER_CATEGORY];

static unsigned int s_fileItemCount = 0;
static unsigned int s_viewItemCount = 0;
static unsigned int s_toolsItemCount = 0;
static unsigned int s_moeItemCount = 0;

//==============================================================================
// Menu Callbacks
//==============================================================================

static void OnFileExit() {
    PostQuitMessage(0);
}

static void OnViewMoEOutput() {
    IDE_ShowPanel("MoE Output");
}

static void OnViewMoEDiagnostics() {
    IDE_ShowPanel("MoE Diagnostics");
}

static void OnViewMoEDebugger() {
    IDE_ShowPanel("MoE Debugger");
}

static void OnViewMoEHeatmap() {
    IDE_ShowPanel("MoE Heatmap");
}

static void OnViewMoESpecExplorer() {
    IDE_ShowPanel("MoE Spec Explorer");
}

static void OnToolsMASMEditor() {
    IDE_ShowPanel("MASM Expert Editor");
}

static void OnMoEGenerate() {
    // Trigger MoE generation
    MoEGenerateInput in = {};
    MoEGenerateOutput out = {};
    unsigned int logits[1] = {500};
    unsigned int kv[1] = {300};
    in.logits = logits;
    in.kv = kv;
    in.token = 'A';
    MoEBackend_Generate(&in, &out);
}

static void OnMoETrace() {
    // Refresh trace view
    IDE_ShowPanel("MoE Output");
}

static void OnMoESwarm() {
    // Trigger swarm mode
    MoEGenerateInput in = {};
    MoEGenerateOutput out = {};
    unsigned int logits[1] = {300}; // Low confidence triggers swarm
    unsigned int kv[1] = {700};     // High KV density
    in.logits = logits;
    in.kv = kv;
    in.token = 'A';
    MoEBackend_Generate(&in, &out);
}

static void OnMoEGhost() {
    // Trigger ghost mode
    MoEGenerateInput in = {};
    MoEGenerateOutput out = {};
    unsigned int logits[1] = {500};
    unsigned int kv[1] = {100}; // Low KV triggers ghost
    in.logits = logits;
    in.kv = kv;
    in.token = 'A';
    MoEBackend_Generate(&in, &out);
}

//==============================================================================
// Implementation
//==============================================================================

void IDEUnifiedMenu::Initialize() {
    if (s_initialized) return;
    
    // Initialize categories
    s_categoryCount = 0;
    
    // File menu
    s_categories[s_categoryCount].name = "File";
    s_categories[s_categoryCount].items = s_fileItems;
    s_categories[s_categoryCount].itemCount = 0;
    s_categoryCount++;
    
    // View menu
    s_categories[s_categoryCount].name = "View";
    s_categories[s_categoryCount].items = s_viewItems;
    s_categories[s_categoryCount].itemCount = 0;
    s_categoryCount++;
    
    // Tools menu
    s_categories[s_categoryCount].name = "Tools";
    s_categories[s_categoryCount].items = s_toolsItems;
    s_categories[s_categoryCount].itemCount = 0;
    s_categoryCount++;
    
    // MoE menu
    s_categories[s_categoryCount].name = "MoE";
    s_categories[s_categoryCount].items = s_moeItems;
    s_categories[s_categoryCount].itemCount = 0;
    s_categoryCount++;
    
    // Add standard items
    AddItem("File", "Exit", "Alt+F4", OnFileExit);
    
    s_initialized = true;
}

void IDEUnifiedMenu::Shutdown() {
    s_initialized = false;
    s_categoryCount = 0;
}

void IDEUnifiedMenu::AddCategory(const char* name) {
    if (s_categoryCount >= MAX_CATEGORIES) return;
    
    s_categories[s_categoryCount].name = name;
    s_categories[s_categoryCount].items = nullptr;
    s_categories[s_categoryCount].itemCount = 0;
    s_categoryCount++;
}

void IDEUnifiedMenu::AddItem(const char* category, const char* name, 
                              const char* shortcut, MenuCallback callback) {
    for (unsigned int i = 0; i < s_categoryCount; i++) {
        if (strcmp(s_categories[i].name, category) == 0) {
            MenuItem* items = nullptr;
            unsigned int* count = nullptr;
            
            if (strcmp(category, "File") == 0) {
                items = s_fileItems;
                count = &s_fileItemCount;
            } else if (strcmp(category, "View") == 0) {
                items = s_viewItems;
                count = &s_viewItemCount;
            } else if (strcmp(category, "Tools") == 0) {
                items = s_toolsItems;
                count = &s_toolsItemCount;
            } else if (strcmp(category, "MoE") == 0) {
                items = s_moeItems;
                count = &s_moeItemCount;
            }
            
            if (items && *count < MAX_ITEMS_PER_CATEGORY) {
                items[*count].name = name;
                items[*count].shortcut = shortcut;
                items[*count].callback = callback;
                items[*count].enabled = true;
                items[*count].checked = false;
                (*count)++;
                s_categories[i].itemCount = *count;
            }
            break;
        }
    }
}

void IDEUnifiedMenu::Draw() {
    if (!s_initialized) return;
    
    // Draw menu bar
    DrawText("[");
    for (unsigned int i = 0; i < s_categoryCount; i++) {
        DrawText(s_categories[i].name);
        if (i < s_categoryCount - 1) {
            DrawText(" | ");
        }
    }
    DrawText("]");
    
    // Draw separator
    DrawLine();
}

void IDEUnifiedMenu::HandleInput(WPARAM wParam) {
    // Handle keyboard shortcuts
    // This would be implemented based on your IDE's input system
}

void IDEUnifiedMenu::SetEnabled(const char* category, const char* item, bool enabled) {
    for (unsigned int i = 0; i < s_categoryCount; i++) {
        if (strcmp(s_categories[i].name, category) == 0) {
            for (unsigned int j = 0; j < s_categories[i].itemCount; j++) {
                if (strcmp(s_categories[i].items[j].name, item) == 0) {
                    s_categories[i].items[j].enabled = enabled;
                    return;
                }
            }
        }
    }
}

void IDEUnifiedMenu::SetChecked(const char* category, const char* item, bool checked) {
    for (unsigned int i = 0; i < s_categoryCount; i++) {
        if (strcmp(s_categories[i].name, category) == 0) {
            for (unsigned int j = 0; j < s_categories[i].itemCount; j++) {
                if (strcmp(s_categories[i].items[j].name, item) == 0) {
                    s_categories[i].items[j].checked = checked;
                    return;
                }
            }
        }
    }
}

//==============================================================================
// MoE Menu Registration
//==============================================================================

void IDEUnifiedMenu_RegisterMoE() {
    // View menu items
    IDEUnifiedMenu::AddItem("View", "MoE Output", "Ctrl+Shift+O", OnViewMoEOutput);
    IDEUnifiedMenu::AddItem("View", "MoE Diagnostics", "Ctrl+Shift+D", OnViewMoEDiagnostics);
    IDEUnifiedMenu::AddItem("View", "MoE Debugger", "Ctrl+Shift+G", OnViewMoEDebugger);
    IDEUnifiedMenu::AddItem("View", "MoE Heatmap", "Ctrl+Shift+H", OnViewMoEHeatmap);
    IDEUnifiedMenu::AddItem("View", "MoE Spec Explorer", "Ctrl+Shift+S", OnViewMoESpecExplorer);
    
    // Tools menu items
    IDEUnifiedMenu::AddItem("Tools", "MASM Expert Editor", "Ctrl+Shift+M", OnToolsMASMEditor);
    
    // MoE menu items
    IDEUnifiedMenu::AddItem("MoE", "Generate", "Ctrl+M G", OnMoEGenerate);
    IDEUnifiedMenu::AddItem("MoE", "View Trace", "Ctrl+M T", OnMoETrace);
    IDEUnifiedMenu::AddItem("MoE", "Swarm Mode", "Ctrl+M S", OnMoESwarm);
    IDEUnifiedMenu::AddItem("MoE", "Ghost Mode", "Ctrl+M H", OnMoEGhost);
}
