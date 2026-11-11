//==============================================================================
// IDEUnifiedMenu.h - Sovereign IDE Unified Menu System
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#ifndef IDE_UNIFIED_MENU_H
#define IDE_UNIFIED_MENU_H

#include <windows.h>

// Menu item callback type
typedef void (*MenuCallback)(void);

// Menu item structure
struct MenuItem {
    const char* name;
    const char* shortcut;
    MenuCallback callback;
    bool enabled;
    bool checked;
};

// Menu category
struct MenuCategory {
    const char* name;
    MenuItem* items;
    unsigned int itemCount;
};

// Unified menu system
class IDEUnifiedMenu {
public:
    static void Initialize();
    static void Shutdown();
    
    static void AddCategory(const char* name);
    static void AddItem(const char* category, const char* name, 
                        const char* shortcut, MenuCallback callback);
    
    static void Draw();
    static void HandleInput(WPARAM wParam);
    
    static void SetEnabled(const char* category, const char* item, bool enabled);
    static void SetChecked(const char* category, const char* item, bool checked);
    
private:
    static const unsigned int MAX_CATEGORIES = 16;
    static const unsigned int MAX_ITEMS_PER_CATEGORY = 32;
    
    static MenuCategory s_categories[MAX_CATEGORIES];
    static unsigned int s_categoryCount;
    static bool s_initialized;
};

// MoE-specific menu registration
void IDEUnifiedMenu_RegisterMoE();

#endif // IDE_UNIFIED_MENU_H
