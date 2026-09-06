import pathlib
p = pathlib.Path(r"F:\~dev\rawrxd\src\win32app\Win32IDE_Product100Wire.cpp")
c = p.read_text(encoding="utf-8")
old = """    if (P100_LoadSession(&session) == P100_OK && session.model_path[0])
        const std::string saved = std::string("[P100] Saved model: ") +
                                  RawrXD::WideToUtf8(std::wstring(session.model_path));
        appendCommandOutput(saved);
        appendCommandConversation(saved);"""
new = """    if (P100_LoadSession(&session) == P100_OK && session.model_path[0]) {
        const std::string saved = std::string("[P100] Saved model: ") +
                                  RawrXD::WideToUtf8(std::wstring(session.model_path));
        appendCommandOutput(saved);
        appendCommandConversation(saved);
    }"""
if old not in c:
    raise SystemExit("pattern not found")
p.write_text(c.replace(old, new), encoding="utf-8")
print("ok")
