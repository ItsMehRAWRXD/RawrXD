param(
    [int]$Port = 8799,
    [string]$ResponseFile = "",
    [string]$CaptureFile = "",
    [int]$MaxRequests = 6
)

$ErrorActionPreference = "Stop"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
Write-Output "MOCK_LISTENING http://127.0.0.1:$Port"

for ($i = 0; $i -lt $MaxRequests; $i++) {
    $ctx = $listener.GetContext()
    $req = $ctx.Request
    $path = $req.Url.AbsolutePath

    $body = ""
    if ($req.HasEntityBody) {
        $sr = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
        $body = $sr.ReadToEnd()
        $sr.Close()
        if ($CaptureFile) { Add-Content -LiteralPath $CaptureFile -Value $body }
    }

    if ($path -like "/api/version") {
        # OllamaClient::testConnection probes /api/version and needs a version field
        $payload = "{`"version`":`"0.40.16`"}"
    } elseif ($path -like "/api/tags") {
        $payload = '{"models":[]}'
    } elseif ($ResponseFile -and (Test-Path $ResponseFile)) {
        $payload = [System.IO.File]::ReadAllText($ResponseFile)
    } else {
        $payload = '{"model":"mock","message":{"content":"OK"},"done":true,"done_reason":"stop"}'
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $ctx.Response.ContentType = "application/json"
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $ctx.Response.Close()
}
$listener.Stop()
Write-Output "MOCK_DONE"