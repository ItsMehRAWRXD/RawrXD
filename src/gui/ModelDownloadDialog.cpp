//==============================================================================
// ModelDownloadDialog.cpp - Phase 15B: Download Dialog Implementation
//==============================================================================

#include "ModelDownloadDialog.h"
#include "../core/GGUFQuantizationDetector.h"
#include "../core/ModelRegistry.h"
#include "../core/ExecutionJournal.h"
#include <cstdio>
#include <cstring>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

//==============================================================================
// Internal State
//==============================================================================

static DownloadDialogState g_dlg_state = {0};
static HWND g_hDlg = NULL;

//==============================================================================
// Progress Callback
//==============================================================================

static void DownloadProgressCallbackImpl(const DownloadProgress* progress, void* user_data) {
    (void)user_data;
    g_dlg_state.last_progress = *progress;
    
    if (g_hDlg) {
        PostMessage(g_hDlg, WM_USER + 1, 0, 0);
    }
}

static void DownloadCompleteCallbackImpl(int download_id, int success, const char* error, void* user_data) {
    (void)download_id;
    (void)user_data;
    
    g_dlg_state.is_downloading = 0;
    g_dlg_state.is_completed = success;
    
    if (g_hDlg) {
        PostMessage(g_hDlg, WM_USER + 2, success, (LPARAM)error);
    }
}

//==============================================================================
// Dialog Functions
//==============================================================================

BOOL ModelDownloadDialog_Show(HWND hWndParent, HINSTANCE hInstance) {
    return ModelDownloadDialog_ShowWithURL(hWndParent, hInstance, NULL, NULL);
}

BOOL ModelDownloadDialog_ShowWithURL(HWND hWndParent, HINSTANCE hInstance,
                                        const char* url, const char* model_name) {
    // Initialize subsystem if needed
    if (!ModelDownload_IsReady()) {
        ModelDownload_Init(NULL);
    }
    
    // Reset state
    memset(&g_dlg_state, 0, sizeof(g_dlg_state));
    if (url) {
        strncpy(g_dlg_state.config.url, url, sizeof(g_dlg_state.config.url) - 1);
    }
    if (model_name) {
        strncpy(g_dlg_state.config.model_name, model_name, sizeof(g_dlg_state.config.model_name) - 1);
    }
    
    // Show dialog
    INT_PTR result = DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_DOWNLOAD_DIALOG),
                                     hWndParent, ModelDownloadDlgProc, (LPARAM)&g_dlg_state);
    
    return (result == IDOK);
}

//==============================================================================
// Dialog Procedure
//==============================================================================

INT_PTR CALLBACK ModelDownloadDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_INITDIALOG: {
            g_hDlg = hDlg;
            DownloadDlg_InitControls(hDlg, GetModuleHandle(NULL));
            
            // Set timer for progress updates
            SetTimer(hDlg, TIMER_DOWNLOAD_UPDATE, DOWNLOAD_UPDATE_MS, NULL);
            
            // Pre-fill if provided
            if (g_dlg_state.config.url[0]) {
                SetDlgItemText(hDlg, IDC_DLG_URL, g_dlg_state.config.url);
            }
            if (g_dlg_state.config.model_name[0]) {
                SetDlgItemText(hDlg, IDC_DLG_MODEL_NAME, g_dlg_state.config.model_name);
            }
            
            // Set default output directory
            SetDlgItemText(hDlg, IDC_DLG_OUTPUT_DIR, ModelDownload_GetDefaultDirectory());
            
            Journal_LogUserRequest("Download dialog opened", "GUI");
            return TRUE;
        }
        
        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            
            switch (wmId) {
                case IDC_DLG_START:
                    DownloadDlg_StartDownload(hDlg);
                    return TRUE;
                    
                case IDC_DLG_CANCEL:
                    if (g_dlg_state.is_downloading) {
                        DownloadDlg_CancelDownload(hDlg);
                    }
                    return TRUE;
                    
                case IDC_DLG_CLOSE:
                case IDCANCEL:
                    if (g_dlg_state.is_downloading) {
                        DownloadDlg_CancelDownload(hDlg);
                    }
                    EndDialog(hDlg, g_dlg_state.is_completed ? IDOK : IDCANCEL);
                    g_hDlg = NULL;
                    return TRUE;
                    
                case IDC_DLG_BROWSE:
                    DownloadDlg_BrowseDirectory(hDlg);
                    return TRUE;
                    
                case IDC_DLG_REFRESH_HF: {
                    char model_id[256];
                    GetDlgItemText(hDlg, IDC_DLG_URL, model_id, sizeof(model_id));
                    DownloadDlg_AutoFillFromHF(hDlg, model_id);
                    return TRUE;
                }
            }
            return FALSE;
        }
        
        case WM_TIMER: {
            if (wParam == TIMER_DOWNLOAD_UPDATE && g_dlg_state.is_downloading) {
                DownloadProgress progress;
                if (ModelDownload_GetProgress(g_dlg_state.download_id, &progress) == 0) {
                    DownloadDlg_UpdateProgress(hDlg, &progress);
                }
            }
            return TRUE;
        }
        
        case WM_USER + 1: {
            // Progress update from callback
            DownloadDlg_UpdateProgress(hDlg, &g_dlg_state.last_progress);
            return TRUE;
        }
        
        case WM_USER + 2: {
            // Completion from callback
            const char* error = (const char*)lParam;
            DownloadDlg_OnComplete(hDlg, (int)wParam, error);
            return TRUE;
        }
        
        case WM_DESTROY:
            KillTimer(hDlg, TIMER_DOWNLOAD_UPDATE);
            g_hDlg = NULL;
            return TRUE;
    }
    
    return FALSE;
}

//==============================================================================
// Helper Functions
//==============================================================================

void DownloadDlg_InitControls(HWND hDlg, HINSTANCE hInstance) {
    // Set dialog title
    SetWindowText(hDlg, "Download Model");
    
    // Initialize progress bar
    HWND hProgress = GetDlgItem(hDlg, IDC_DLG_PROGRESS);
    if (hProgress) {
        SendMessage(hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
    }
    
    // Set button states
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_START), TRUE);
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_CANCEL), FALSE);
    
    // Set status text
    SetDlgItemText(hDlg, IDC_DLG_STATUS, "Ready to download");
    SetDlgItemText(hDlg, IDC_DLG_SPEED, "");
    SetDlgItemText(hDlg, IDC_DLG_ETA, "");
    
    (void)hInstance;
}

void DownloadDlg_StartDownload(HWND hDlg) {
    // Get input values
    char url[MAX_DOWNLOAD_URL];
    char model_name[MAX_HF_MODEL_ID];
    char output_dir[MAX_DOWNLOAD_PATH];
    char sha256[65];
    
    GetDlgItemText(hDlg, IDC_DLG_URL, url, sizeof(url));
    GetDlgItemText(hDlg, IDC_DLG_MODEL_NAME, model_name, sizeof(model_name));
    GetDlgItemText(hDlg, IDC_DLG_OUTPUT_DIR, output_dir, sizeof(output_dir));
    GetDlgItemText(hDlg, IDC_DLG_SHA256, sha256, sizeof(sha256));
    
    if (url[0] == '\0') {
        MessageBox(hDlg, "Please enter a URL or HuggingFace model ID", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Build config
    DownloadConfig config = {0};
    
    // Check if it's a HuggingFace model ID
    if (strchr(url, '/') && !strstr(url, "://")) {
        // Looks like "org/model" format
        char resolved_url[MAX_DOWNLOAD_URL];
        if (ModelDownload_ResolveHFUrl(url, resolved_url, sizeof(resolved_url)) == 0) {
            strncpy(config.url, resolved_url, sizeof(config.url) - 1);
            config.use_hf_hub = 1;
        } else {
            strncpy(config.url, url, sizeof(config.url) - 1);
        }
    } else {
        strncpy(config.url, url, sizeof(config.url) - 1);
    }
    
    strncpy(config.model_name, model_name[0] ? model_name : "Downloaded Model", 
            sizeof(config.model_name) - 1);
    strncpy(config.expected_sha256, sha256, sizeof(config.expected_sha256) - 1);
    
    // Extract filename from URL
    const char* filename = strrchr(config.url, '/');
    if (filename) {
        filename++;
    } else {
        filename = "model.gguf";
    }
    
    // Remove query parameters
    char* qmark = strchr((char*)filename, '?');
    if (qmark) *qmark = '\0';
    
    snprintf(config.output_path, sizeof(config.output_path), "%s\\%s", output_dir, filename);
    
    config.auto_install = IsDlgButtonChecked(hDlg, IDC_DLG_AUTO_INSTALL) == BST_CHECKED;
    strncpy(config.backend_type, "native", sizeof(config.backend_type) - 1);
    
    // Start download
    g_dlg_state.download_id = ModelDownload_Start(&config);
    
    if (g_dlg_state.download_id < 0) {
        MessageBox(hDlg, "Failed to start download", "Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Set callbacks
    ModelDownload_SetProgressCallback(g_dlg_state.download_id, 
                                         DownloadProgressCallbackImpl, NULL);
    ModelDownload_SetCompleteCallback(g_dlg_state.download_id, 
                                       DownloadCompleteCallbackImpl, NULL);
    
    g_dlg_state.is_downloading = 1;
    
    // Update UI
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_START), FALSE);
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_CANCEL), TRUE);
    SetDlgItemText(hDlg, IDC_DLG_STATUS, "Starting download...");
    
    Journal_LogUserRequest("Download started from dialog", config.model_name);
}

void DownloadDlg_CancelDownload(HWND hDlg) {
    if (g_dlg_state.download_id > 0) {
        ModelDownload_Cancel(g_dlg_state.download_id);
    }
    
    g_dlg_state.is_downloading = 0;
    
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_START), TRUE);
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_CANCEL), FALSE);
    SetDlgItemText(hDlg, IDC_DLG_STATUS, "Cancelled");
    
    Journal_LogUserRequest("Download cancelled from dialog", "");
}

void DownloadDlg_UpdateProgress(HWND hDlg, const DownloadProgress* progress) {
    // Update progress bar
    HWND hProgress = GetDlgItem(hDlg, IDC_DLG_PROGRESS);
    if (hProgress) {
        SendMessage(hProgress, PBM_SETPOS, progress->percent_complete, 0);
    }
    
    // Update status
    SetDlgItemText(hDlg, IDC_DLG_STATUS, progress->status_message);
    
    // Update speed
    char speed_str[32];
    ModelDownload_FormatSpeed(progress->bytes_per_second, speed_str, sizeof(speed_str));
    SetDlgItemText(hDlg, IDC_DLG_SPEED, speed_str);
    
    // Update ETA
    char eta_str[32];
    if (progress->eta_ms > 0) {
        ModelDownload_FormatDuration(progress->eta_ms, eta_str, sizeof(eta_str));
        char eta_label[64];
        snprintf(eta_label, sizeof(eta_label), "ETA: %s", eta_str);
        SetDlgItemText(hDlg, IDC_DLG_ETA, eta_label);
    }
}

void DownloadDlg_OnComplete(HWND hDlg, int success, const char* error) {
    g_dlg_state.is_downloading = 0;
    
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_START), TRUE);
    EnableWindow(GetDlgItem(hDlg, IDC_DLG_CANCEL), FALSE);
    
    if (success) {
        SetDlgItemText(hDlg, IDC_DLG_STATUS, "Download complete!");
        
        // Show quantization info
        DownloadDlg_ShowQuantizationInfo(hDlg);
        
        // Ask to install
        if (!g_dlg_state.config.auto_install) {
            int result = MessageBox(hDlg, 
                "Download complete! Would you like to install this model to the registry?",
                "Install Model", MB_YESNO | MB_ICONQUESTION);
            
            if (result == IDYES) {
                DownloadDlg_InstallToRegistry(hDlg);
            }
        }
    } else {
        char msg[512];
        snprintf(msg, sizeof(msg), "Download failed: %s", error ? error : "Unknown error");
        SetDlgItemText(hDlg, IDC_DLG_STATUS, msg);
        MessageBox(hDlg, msg, "Error", MB_OK | MB_ICONERROR);
    }
}

void DownloadDlg_BrowseDirectory(HWND hDlg) {
    BROWSEINFO bi = {0};
    bi.hwndOwner = hDlg;
    bi.lpszTitle = "Select Output Directory";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    
    LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
    if (pidl) {
        char path[MAX_PATH];
        if (SHGetPathFromIDList(pidl, path)) {
            SetDlgItemText(hDlg, IDC_DLG_OUTPUT_DIR, path);
        }
        CoTaskMemFree(pidl);
    }
}

int DownloadDlg_ParseHFModelID(const char* input, char* out_url, char* out_name) {
    return ModelDownload_ResolveHFUrl(input, out_url, MAX_DOWNLOAD_URL);
}

void DownloadDlg_AutoFillFromHF(HWND hDlg, const char* model_id) {
    // Try to resolve HF URL
    char url[MAX_DOWNLOAD_URL];
    if (ModelDownload_ResolveHFUrl(model_id, url, sizeof(url)) == 0) {
        SetDlgItemText(hDlg, IDC_DLG_URL, url);
        
        // Extract model name from ID
        const char* slash = strchr(model_id, '/');
        if (slash) {
            SetDlgItemText(hDlg, IDC_DLG_MODEL_NAME, slash + 1);
        }
    }
}

void DownloadDlg_ShowQuantizationInfo(HWND hDlg) {
    // Detect quantization from downloaded file
    DetectedModelInfo info;
    if (GGUFDetector_AnalyzeFile(g_dlg_state.config.output_path, &info) == 0) {
        strncpy(g_dlg_state.detected_quantization, info.quantization, 
                sizeof(g_dlg_state.detected_quantization) - 1);
        g_dlg_state.detected_params = info.parameter_count;
        
        char msg[512];
        char params_str[32];
        if (info.parameter_count >= 1000000000) {
            snprintf(params_str, sizeof(params_str), "%.1fB", info.parameter_count / 1000000000.0);
        } else if (info.parameter_count >= 1000000) {
            snprintf(params_str, sizeof(params_str), "%.1fM", info.parameter_count / 1000000.0);
        } else {
            snprintf(params_str, sizeof(params_str), "%llu", info.parameter_count);
        }
        
        snprintf(msg, sizeof(msg),
                 "Detected: %s quantization, %s parameters\r\n"
                 "Architecture: %s\r\n"
                 "Context: %d tokens",
                 info.quantization, params_str,
                 info.architecture[0] ? info.architecture : "unknown",
                 info.context_length);
        
        SetDlgItemText(hDlg, IDC_DLG_STATUS, msg);
    }
}

void DownloadDlg_InstallToRegistry(HWND hDlg) {
    // Get model name
    char model_name[128];
    GetDlgItemText(hDlg, IDC_DLG_MODEL_NAME, model_name, sizeof(model_name));
    
    // Install
    if (ModelDownload_InstallToRegistry(g_dlg_state.config.output_path,
                                         model_name,
                                         g_dlg_state.config.backend_type,
                                         0) == 0) {
        MessageBox(hDlg, "Model installed successfully!", "Success", MB_OK | MB_ICONINFORMATION);
        Journal_LogUserRequest("Model installed from dialog", model_name);
    } else {
        MessageBox(hDlg, "Failed to install model to registry", "Error", MB_OK | MB_ICONERROR);
    }
}
