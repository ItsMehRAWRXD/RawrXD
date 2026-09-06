$path = 'F:\~dev\rawrxd\src\win32app\Win32IDE_Product100Wire.cpp'
$c = [IO.File]::ReadAllText($path)
$old = @'
    if (P100_LoadSession(&session) == P100_OK && session.model_path[0])
        const std::string saved = std::string("[P100] Saved model: ") +
                                  RawrXD::WideToUtf8(std::wstring(session.model_path));
        appendCommandOutput(saved);
        appendCommandConversation(saved);
'@
$new = @'
    if (P100_LoadSession(&session) == P100_OK && session.model_path[0]) {
        const std::string saved = std::string("[P100] Saved model: ") +
                                  RawrXD::WideToUtf8(std::wstring(session.model_path));
        appendCommandOutput(saved);
        appendCommandConversation(saved);
    }
'@
if (-not $c.Contains($old)) { throw 'pattern not found' }
[IO.File]::WriteAllText($path, $c.Replace($old, $new))
Write-Host ok
