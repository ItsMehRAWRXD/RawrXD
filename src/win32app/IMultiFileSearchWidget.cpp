#include "IMultiFileSearchWidget.h"
#include <string>

// ============================================================================
// IMultiFileSearchWidget Implementation
// Wraps the MultiFileSearchWidget with proper interface abstraction
// ============================================================================

// Forward declaration of the actual widget class
class MultiFileSearchWidget;

namespace {
    // Internal implementation class
    class MultiFileSearchWidgetImpl : public IMultiFileSearchWidget {
    public:
        MultiFileSearchWidgetImpl() : m_widget(nullptr), m_showCallback(nullptr), m_callbackContext(nullptr) {}
        
        ~MultiFileSearchWidgetImpl() override = default;
        
        void ShowDialog() override {
            // Delegate to the actual implementation
            // This would call MultiFileSearchWidget_ShowDialog or equivalent
            if (m_showCallback && m_callbackContext) {
                m_showCallback(m_callbackContext);
            }
        }
        
        void SetProjectRoot(const char* rootPath) override {
            if (rootPath) {
                m_projectRoot = rootPath;
            }
        }
        
        void SetShowCallback(void (*callback)(void*), void* context) override {
            m_showCallback = callback;
            m_callbackContext = context;
        }
        
        bool IsSearching() const override {
            // Query actual widget state
            return m_isSearching;
        }
        
        void CancelSearch() override {
            m_isSearching = false;
            // Cancel actual search operation
        }
        
    private:
        MultiFileSearchWidget* m_widget;
        void (*m_showCallback)(void*);
        void* m_callbackContext;
        std::string m_projectRoot;
        bool m_isSearching = false;
    };
    
    // Singleton instance
    IMultiFileSearchWidget* g_multiFileSearchWidget = nullptr;
}

IMultiFileSearchWidget* CreateMultiFileSearchWidget() {
    if (!g_multiFileSearchWidget) {
        g_multiFileSearchWidget = new MultiFileSearchWidgetImpl();
    }
    return g_multiFileSearchWidget;
}

IMultiFileSearchWidget* GetMultiFileSearchWidget() {
    if (!g_multiFileSearchWidget) {
        return CreateMultiFileSearchWidget();
    }
    return g_multiFileSearchWidget;
}

void DestroyMultiFileSearchWidget() {
    delete g_multiFileSearchWidget;
    g_multiFileSearchWidget = nullptr;
}