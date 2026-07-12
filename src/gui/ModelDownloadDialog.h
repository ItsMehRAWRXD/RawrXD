//==============================================================================
// ModelDownloadDialog.h - Phase 15B: GUI Download Dialog
//
// Win32 dialog for downloading models from HuggingFace or direct URLs
// Features:
// - URL input with HuggingFace model ID support
// - Real-time progress bar
// - Speed and ETA display
// - Auto-detect quantization after download
// - One-click registry installation
//==============================================================================

#ifndef MODEL_DOWNLOAD_DIALOG_H
#define MODEL_DOWNLOAD_DIALOG_H

#include <windows.h>
#include "../core/ModelDownloadSubsystem.h"

// Dialog dimensions
#define DOWNLOADDLG_WIDTH       500
#define DOWNLOADDLG_HEIGHT      400

// Control IDs
#define IDC_DLG_URL             2001
#define IDC_DLG_MODEL_NAME      2002
#define IDC_DLG_BACKEND         2003
#define IDC_DLG_OUTPUT_DIR      2004
#define IDC_DLG_BROWSE          2005
#define IDC_DLG_SHA256          2006
#define IDC_DLG_AUTO_INSTALL    2007
#define IDC_DLG_PROGRESS        2008
#define IDC_DLG_STATUS          2009
#define IDC_DLG_SPEED           2010
#define IDC_DLG_ETA             2011
#define IDC_DLG_START           2012
#define IDC_DLG_CANCEL          2013
#define IDC_DLG_CLOSE           2014
#define IDC_DLG_HF_LIST         2015
#define IDC_DLG_REFRESH_HF      2016

// Timer for progress updates
#define TIMER_DOWNLOAD_UPDATE   200
#define DOWNLOAD_UPDATE_MS      100

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Dialog Functions
//==============================================================================

// Show the download dialog (modal)
// Returns: TRUE if download completed successfully, FALSE otherwise
BOOL ModelDownloadDialog_Show(HWND hWndParent, HINSTANCE hInstance);

// Show download dialog with pre-filled URL
BOOL ModelDownloadDialog_ShowWithURL(HWND hWndParent, HINSTANCE hInstance, 
                                     const char* url, const char* model_name);

// Dialog procedure
INT_PTR CALLBACK ModelDownloadDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

//==============================================================================
// Dialog State
//==============================================================================

typedef struct DownloadDialogState {
    int download_id;
    int is_downloading;
    int is_completed;
    DownloadConfig config;
    DownloadProgress last_progress;
    char detected_quantization[32];
    uint64_t detected_params;
} DownloadDialogState;

//==============================================================================
// Helper Functions
//==============================================================================

// Initialize dialog controls
void DownloadDlg_InitControls(HWND hDlg, HINSTANCE hInstance);

// Start download
void DownloadDlg_StartDownload(HWND hDlg);

// Cancel download
void DownloadDlg_CancelDownload(HWND hDlg);

// Update progress display
void DownloadDlg_UpdateProgress(HWND hDlg, const DownloadProgress* progress);

// Handle download completion
void DownloadDlg_OnComplete(HWND hDlg, int success, const char* error);

// Browse for output directory
void DownloadDlg_BrowseDirectory(HWND hDlg);

// Parse HuggingFace model ID
int DownloadDlg_ParseHFModelID(const char* input, char* out_url, char* out_name);

// Auto-fill from HuggingFace
void DownloadDlg_AutoFillFromHF(HWND hDlg, const char* model_id);

// Show quantization info after download
void DownloadDlg_ShowQuantizationInfo(HWND hDlg);

// Install to registry
void DownloadDlg_InstallToRegistry(HWND hDlg);

#ifdef __cplusplus
}
#endif

#endif // MODEL_DOWNLOAD_DIALOG_H
