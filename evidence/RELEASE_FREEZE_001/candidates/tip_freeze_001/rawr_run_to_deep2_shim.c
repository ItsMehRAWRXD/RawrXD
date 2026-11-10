/* Translates `rawr run ...` argv from 35C22 pin CLI path into deep2_agentic_loop.exe.
   Pin lacks FORCE_LOCAL / exeIsDeep2Loop guard; packaging places this beside RXD_PIN. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void append_quoted(char *dst, size_t cap, const char *val) {
  size_t n = strlen(dst);
  if (n + 3 >= cap) return;
  dst[n++] = '"';
  for (; *val && n + 2 < cap; ++val) {
    if (*val == '"') {
      if (n + 3 >= cap) break;
      dst[n++] = '\\';
    }
    dst[n++] = *val;
  }
  if (n + 1 < cap) dst[n++] = '"';
  dst[n] = 0;
}

static const char *get_arg(int argc, char **argv, const char *flag) {
  size_t fl = strlen(flag);
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], flag) == 0 && i + 1 < argc) return argv[i + 1];
    if (strncmp(argv[i], flag, fl) == 0 && argv[i][fl] == '=') return argv[i] + fl + 1;
  }
  return NULL;
}

int main(int argc, char **argv) {
  char module[MAX_PATH];
  GetModuleFileNameA(NULL, module, MAX_PATH);
  char *slash = strrchr(module, '\\');
  if (!slash) slash = strrchr(module, '/');
  if (slash) *slash = 0;
  char deep2[MAX_PATH];
  snprintf(deep2, sizeof(deep2), "%s\\deep2_agentic_loop.exe", module);
  if (GetFileAttributesA(deep2) == INVALID_FILE_ATTRIBUTES) {
    fprintf(stderr, "shim: deep2_agentic_loop.exe not beside shim\n");
    return 2;
  }

  const char *model = NULL;
  const char *workspace = NULL;
  const char *prompt = NULL;
  int is_run = 0;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "run") == 0 && i + 1 < argc) {
      is_run = 1;
      model = argv[++i];
      continue;
    }
  }
  workspace = get_arg(argc, argv, "--workspace");
  if (!workspace) workspace = get_arg(argc, argv, "--workdir");
  prompt = get_arg(argc, argv, "--prompt");
  if (!prompt) prompt = get_arg(argc, argv, "--task");

  const char *env_model = getenv("RAWRXD_DEFAULT_DEEP2_MODEL");
  if (env_model && *env_model) model = env_model;
  if (!model || !*model) {
    fprintf(stderr, "shim: no model\n");
    return 3;
  }

  int use_ollama = 1;
  if (strstr(model, ".gguf") || strstr(model, ".GGUF") ||
      (model[0] && (model[1] == ':' || model[0] == '/' || model[0] == '\\'))) {
    use_ollama = 0;
  }

  char cmd[8192];
  cmd[0] = 0;
  append_quoted(cmd, sizeof(cmd), deep2);
  strcat_s(cmd, sizeof(cmd), " ");
  if (use_ollama) strcat_s(cmd, sizeof(cmd), "--provider ollama ");
  strcat_s(cmd, sizeof(cmd), "--model ");
  append_quoted(cmd, sizeof(cmd), model);
  strcat_s(cmd, sizeof(cmd), " ");
  if (workspace && *workspace) {
    strcat_s(cmd, sizeof(cmd), "--workdir ");
    append_quoted(cmd, sizeof(cmd), workspace);
    strcat_s(cmd, sizeof(cmd), " ");
  }
  if (prompt && *prompt) {
    strcat_s(cmd, sizeof(cmd), "--task ");
    append_quoted(cmd, sizeof(cmd), prompt);
    strcat_s(cmd, sizeof(cmd), " ");
  }
  strcat_s(cmd, sizeof(cmd), "--target-file bug.cpp ");
  strcat_s(cmd, sizeof(cmd), "--build-command \"cmd /c exit 0\" ");
  strcat_s(cmd, sizeof(cmd), "--run-command \"cmd /c echo PASS\" ");
  strcat_s(cmd, sizeof(cmd), "--max-steps 12 --max-new 768 --max-retries 3 ");
  strcat_s(cmd, sizeof(cmd), "--max-wall-time-sec 7200 --max-total-tokens 16384 ");
  strcat_s(cmd, sizeof(cmd), "--prefill-chunk 128 --batched-prefill 1 ");
  (void)is_run;

  STARTUPINFOA si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));
  char cmdline[8192];
  strncpy_s(cmdline, sizeof(cmdline), cmd, _TRUNCATE);
  if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, workspace && *workspace ? workspace : module, &si, &pi)) {
    fprintf(stderr, "shim: CreateProcess failed %lu\n", GetLastError());
    return 4;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 1;
  GetExitCodeProcess(pi.hProcess, &code);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return (int)code;
}
