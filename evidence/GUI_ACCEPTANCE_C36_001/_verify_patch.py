from pathlib import Path

t = Path(r"g:\~dev\rawrxd\src\win32app\Win32IDE_LSPClient.cpp").read_text(
    encoding="utf-8", errors="replace"
)
i = t.find("PROCESS_INFORMATION pi")
print(t[i : i + 1200])
print("==== INIT ====")
j = t.find('int id = sendLSPRequest(lang, "initialize"')
print(t[j : j + 1700])
print("==== flags ====")
print("cstring", "#include <cstring>" in t)
print("LSP_STAGE emit", "LSP_STAGE=%s" in t)
print("UNFULFILLED_HANDSHAKE", "UNFULFILLED_HANDSHAKE" in t)
print("init_send_begin", "init_send_begin" in t)
print("g_c36InitWaitLang.store", "g_c36InitWaitLang.store" in t)
print("proc_begin", 'c36Phase("proc_begin"' in t)
print("proc_ok", 'c36Phase("proc_ok"' in t)
print("pipe_ok", 'c36Phase("pipe_ok"' in t)
