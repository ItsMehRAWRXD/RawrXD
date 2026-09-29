$ErrorActionPreference = "Stop"
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 11436)
$listener.Start()
$log = "F:\~dev\_mock_upstream.log"
"UPSTREAM_LISTEN=11436 $(Get-Date -Format o)" | Out-File $log -Encoding UTF8

while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII)
    $sb = ""
    # read headers
    $contentLength = 0
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line) { break }
        $sb += $line + "`n"
        if ($line -eq "") { break }
        if ($line -match '^Content-Length:\s*(\d+)') { $contentLength = [int]$Matches[1] }
    }
    $body = ""
    if ($contentLength -gt 0) {
        $buf = New-Object char[] $contentLength
        $read = $reader.Read($buf, 0, $contentLength)
        $body = -join $buf[0..($read-1)]
    }
    ("REQ {0}" -f $sb.Split("`n")[0]) | Out-File $log -Append -Encoding UTF8
    ("BODY {0}" -f $body) | Out-File $log -Append -Encoding UTF8

    $respBody = '{"id":"mock-1","object":"chat.completion","model":"qwen2.5-coder-1.5b-base","choices":[{"index":0,"message":{"role":"assistant","content":"DEEP2_SERVERLESS_OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14}}'
    if ($sb -match 'GET /health') {
        $respBody = '{"status":"ok","engine":"deep2"}'
    }
    $resp = "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: $($respBody.Length)`r`nConnection: close`r`n`r`n$respBody"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($resp)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
    $client.Close()
}
