// Win32IDE_Resource.h
// Menu command IDs for Win32IDE

#ifndef WIN32IDE_RESOURCE_H
#define WIN32IDE_RESOURCE_H

// File Menu
#define ID_FILE_NEW_PROJECT     40001
#define ID_FILE_OPEN_PROJECT    40002
#define ID_FILE_SAVE_PROJECT    40003
#define ID_FILE_EXIT            40004

// Build Menu
#define ID_BUILD_COMPILE        40101
#define ID_BUILD_RUN            40102
#define ID_BUILD_DEBUG          40103
#define ID_BUILD_CLEAN          40104

// Tools Menu
#define ID_TOOLS_ANALYZE        40201
#define ID_TOOLS_PATCH          40202
#define ID_TOOLS_OPTIONS        40203

// Edit Menu
#define ID_EDIT_UNDO            40301
#define ID_EDIT_REDO            40302
#define ID_EDIT_CUT             40303
#define ID_EDIT_COPY            40304
#define ID_EDIT_PASTE           40305

// View Menu
#define ID_VIEW_OUTPUT          40401
#define ID_VIEW_PROJECT         40402

// Dialog IDs
#define IDD_NEW_PROJECT         50001
#define IDC_EDIT_PROJECT_NAME   50002

// Standard dialog buttons
#ifndef IDOK
#define IDOK                    1
#endif
#ifndef IDCANCEL
#define IDCANCEL                2
#endif

#endif // WIN32IDE_RESOURCE_H
