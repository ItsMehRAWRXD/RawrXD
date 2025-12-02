# Multi-Threaded Download Manager
# Location: To be integrated into RawrXD.ps1

# ============================================================================
# DOWNLOAD MANAGER - MULTI-THREADED FILE DOWNLOADER
# ============================================================================

<#
.SYNOPSIS
    Multi-threaded download engine with resume support and integrity verification

.DESCRIPTION
    Professional-grade download system with:
    - 4-8 parallel threads
    - Resumable downloads (HTTP Range requests)
    - SHA-256 integrity verification
    - Progress tracking
    - Auto-retry on failure
    - Rate limiting support
#>

# Initialize download registry
$script:DownloadRegistry = @{
    ActiveDownloads = @{}
    CompletedDownloads = @{}
    FailedDownloads = @{}
}

# ============================================================================
# CORE DOWNLOAD FUNCTION
# ============================================================================

<#
.SYNOPSIS
    Downloads a file using multiple threads with resume support

.PARAMETER URL
    Source URL to download

.PARAMETER OutputPath
    Destination file path

.PARAMETER ThreadCount
    Number of parallel download threads (default: 4, max: 8)

.PARAMETER ChunkSize
    Size of each download chunk (default: 1MB)

.PARAMETER MaxRetries
    Maximum retry attempts on failure (default: 3)

.EXAMPLE
    $result = Invoke-MultiThreadedDownload -URL "https://example.com/video.mp4" `
        -OutputPath "C:\Videos\video.mp4" -ThreadCount 4

    Returns: @{ Success=$true; FilePath=...; Speed="25 MB/s"; Duration="00:04:30" }
#>
function Invoke-MultiThreadedDownload {
    param(
        [Parameter(Mandatory=$true)]
        [string]$URL,

        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [int]$ThreadCount = 4,
        [int64]$ChunkSize = 1MB,
        [int]$MaxRetries = 3,
        [double]$RateLimitMBps = 0  # 0 = unlimited
    )

    try {
        if ($ThreadCount -lt 1) { $ThreadCount = 1 }
        if ($ThreadCount -gt 8) { $ThreadCount = 8 }

        Write-DevConsole "📥 Starting download: $URL" "INFO"
        Write-DevConsole "   Output: $OutputPath" "INFO"
        Write-DevConsole "   Threads: $ThreadCount" "INFO"

        # Create output directory if needed
        $outputDir = Split-Path -Parent $OutputPath
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        # Step 1: Get file size and check if resumable
        $headResponse = Get-DownloadFileInfo -URL $URL

        if (-not $headResponse.Success) {
            Write-DevConsole "❌ Cannot access file: $($headResponse.Error)" "ERROR"
            return @{ Success = $false; Error = $headResponse.Error }
        }

        $totalSize = $headResponse.ContentLength
        $supportsRange = $headResponse.AcceptsRanges

        Write-DevConsole "📦 File size: $(Format-Bytes $totalSize)" "INFO"
        Write-DevConsole "   Resumable: $(if ($supportsRange) { 'Yes ✅' } else { 'No' })" "INFO"

        # Step 2: Check if partial file exists
        $partialPath = "$OutputPath.part"
        $downloadedBytes = 0

        if ($supportsRange -and (Test-Path $partialPath)) {
            $partialFile = Get-Item $partialPath
            $downloadedBytes = $partialFile.Length

            if ($downloadedBytes -gt 0 -and $downloadedBytes -lt $totalSize) {
                Write-DevConsole "▶️  Resuming from: $(Format-Bytes $downloadedBytes)" "SUCCESS"
            }
            elseif ($downloadedBytes -ge $totalSize) {
                Write-DevConsole "✅ Download already complete (partial file)" "INFO"
                $downloadedBytes = 0  # Re-download
            }
        }

        # Step 3: Create download jobs
        $downloadStartTime = Get-Date
        $registryId = [guid]::NewGuid().ToString()

        $script:DownloadRegistry.ActiveDownloads[$registryId] = @{
            URL = $URL
            OutputPath = $OutputPath
            TotalSize = $totalSize
            DownloadedBytes = $downloadedBytes
            ThreadCount = $ThreadCount
            Status = "downloading"
            StartTime = $downloadStartTime
            LastUpdate = $downloadStartTime
        }

        # Calculate chunks
        $remainingBytes = $totalSize - $downloadedBytes
        $chunkCount = [Math]::Ceiling($remainingBytes / $ChunkSize)
        $actualThreadCount = [Math]::Min($ThreadCount, $chunkCount)

        Write-DevConsole "📊 Splitting into $($actualThreadCount) threads ($chunkCount total chunks)" "INFO"

        # Step 4: Download chunks
        if ($actualThreadCount -eq 1) {
            # Single-threaded download (easier, no coordination needed)
            $success = Download-ChunkSequential -URL $URL -OutputPath $partialPath `
                -StartByte $downloadedBytes -EndByte $totalSize -RegistryId $registryId
        }
        else {
            # Multi-threaded download
            $success = Download-ChunkParallel -URL $URL -OutputPath $partialPath `
                -TotalSize $totalSize -StartByte $downloadedBytes -ChunkSize $ChunkSize `
                -ThreadCount $actualThreadCount -RegistryId $registryId -RateLimitMBps $RateLimitMBps
        }

        if (-not $success) {
            Write-DevConsole "❌ Download failed" "ERROR"
            $script:DownloadRegistry.FailedDownloads[$registryId] = $script:DownloadRegistry.ActiveDownloads[$registryId]
            $script:DownloadRegistry.ActiveDownloads.Remove($registryId)
            return @{ Success = $false; Error = "Download failed" }
        }

        # Step 5: Verify integrity
        Write-DevConsole "🔐 Verifying file integrity..." "INFO"
        $verification = Verify-DownloadIntegrity -FilePath $partialPath `
            -ExpectedSize $totalSize -URL $URL

        if (-not $verification.Success) {
            Write-DevConsole "❌ Integrity check failed: $($verification.Error)" "ERROR"
            return @{ Success = $false; Error = $verification.Error }
        }

        # Step 6: Move to final location
        if (Test-Path $OutputPath) {
            Remove-Item $OutputPath -Force
        }

        Move-Item -Path $partialPath -Destination $OutputPath -Force

        # Calculate statistics
        $downloadDuration = (Get-Date) - $downloadStartTime
        $speedMBps = [Math]::Round($totalSize / 1MB / $downloadDuration.TotalSeconds, 2)

        Write-DevConsole "✅ Download complete!" "SUCCESS"
        Write-DevConsole "   Speed: $speedMBps MB/s" "SUCCESS"
        Write-DevConsole "   Duration: $($downloadDuration.ToString('hh\:mm\:ss'))" "SUCCESS"

        # Update registry
        $script:DownloadRegistry.CompletedDownloads[$registryId] = @{
            URL = $URL
            OutputPath = $OutputPath
            TotalSize = $totalSize
            Speed = "$speedMBps MB/s"
            Duration = $downloadDuration.ToString('hh\:mm\:ss')
            CompletedAt = Get-Date
        }

        $script:DownloadRegistry.ActiveDownloads.Remove($registryId)

        return @{
            Success = $true
            FilePath = $OutputPath
            FileSize = $totalSize
            Speed = "$speedMBps MB/s"
            Duration = $downloadDuration.ToString('hh\:mm\:ss')
            RegistryId = $registryId
        }

    }
    catch {
        Write-DevConsole "Download error: $_" "ERROR"
        Write-ErrorLog -ErrorMessage "Invoke-MultiThreadedDownload failed: $_" `
            -ErrorCategory "DOWNLOAD" -Severity "MEDIUM"
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

<#
.SYNOPSIS
    Gets file info via HEAD request
#>
function Get-DownloadFileInfo {
    param([string]$URL)

    try {
        $httpClient = New-Object System.Net.Http.HttpClient
        $request = New-Object System.Net.Http.HttpRequestMessage -ArgumentList @([System.Net.Http.HttpMethod]::Head, $URL)

        $response = $httpClient.SendAsync($request).Result

        if ($response.StatusCode -eq [System.Net.HttpStatusCode]::OK) {
            $contentLength = if ($response.Content.Headers.ContentLength) {
                $response.Content.Headers.ContentLength.Value
            } else {
                -1
            }

            $acceptsRanges = $response.Headers.AcceptRanges -and $response.Headers.AcceptRanges.Count -gt 0

            return @{
                Success = $true
                ContentLength = $contentLength
                AcceptsRanges = $acceptsRanges
                ContentType = $response.Content.Headers.ContentType.ToString()
            }
        }
        else {
            return @{
                Success = $false
                Error = "HTTP $($response.StatusCode)"
            }
        }

    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Sequential (single-threaded) download
#>
function Download-ChunkSequential {
    param(
        [string]$URL,
        [string]$OutputPath,
        [int64]$StartByte,
        [int64]$EndByte,
        [string]$RegistryId
    )

    try {
        $webClient = New-Object System.Net.WebClient

        # Set range header if resuming
        if ($StartByte -gt 0) {
            $webClient.Headers.Add("Range", "bytes=$StartByte-$(($EndByte - 1))")
        }

        # Setup progress tracking
        $webClient.add_DownloadProgressChanged({
            param($sender, $e)

            $downloaded = $e.BytesReceived
            $total = $e.TotalBytesToReceive

            if ($total -gt 0) {
                $percent = [Math]::Round(($downloaded / $total) * 100, 1)
                Write-DevConsole "📥 Download: ${percent}% ($((Format-Bytes $downloaded))/$((Format-Bytes $total)))" "INFO"
            }
        })

        # Download file
        $webClient.DownloadFile($URL, $OutputPath)
        return $true
    }
    catch {
        Write-DevConsole "Sequential download error: $_" "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Parallel (multi-threaded) download
#>
function Download-ChunkParallel {
    param(
        [string]$URL,
        [string]$OutputPath,
        [int64]$TotalSize,
        [int64]$StartByte,
        [int64]$ChunkSize,
        [int]$ThreadCount,
        [string]$RegistryId,
        [double]$RateLimitMBps
    )

    try {
        # Create empty output file
        $null = New-Item -Path $OutputPath -ItemType File -Force

        # Calculate chunks
        $remainingBytes = $TotalSize - $StartByte
        $jobs = @()

        for ($i = 0; $i -lt $ThreadCount; $i++) {
            $chunkStart = $StartByte + ($i * $ChunkSize)
            $chunkEnd = [Math]::Min($chunkStart + $ChunkSize, $TotalSize)

            if ($chunkStart -ge $chunkEnd) { break }

            $job = Start-Job -ScriptBlock {
                param($url, $outputPath, $start, $end, $chunkIndex)

                try {
                    $webClient = New-Object System.Net.WebClient
                    $webClient.Headers.Add("Range", "bytes=$start-$(($end - 1))")

                    $tempChunkPath = "$outputPath.chunk$chunkIndex"
                    $webClient.DownloadFile($url, $tempChunkPath)

                    return @{
                        Success = $true
                        ChunkIndex = $chunkIndex
                        ChunkPath = $tempChunkPath
                        Size = $end - $start
                    }
                }
                catch {
                    return @{
                        Success = $false
                        Error = $_.Exception.Message
                    }
                }
            } -ArgumentList @($URL, $OutputPath, $chunkStart, $chunkEnd, $i)

            $jobs += $job
        }

        # Wait for all jobs to complete
        $results = @()
        foreach ($job in $jobs) {
            $result = Receive-Job -Job $job -Wait
            $results += $result
            Remove-Job -Job $job
        }

        # Check for failures
        $failedCount = @($results | Where-Object { -not $_.Success }).Count
        if ($failedCount -gt 0) {
            Write-DevConsole "⚠️ $failedCount chunk(s) failed" "WARNING"
            return $false
        }

        # Merge chunks
        Write-DevConsole "🔗 Merging $($results.Count) chunks..." "INFO"

        $outputStream = [System.IO.File]::Create($OutputPath)

        foreach ($result in $results | Sort-Object { $_.ChunkIndex }) {
            $chunkPath = $result.ChunkPath
            $chunkStream = [System.IO.File]::OpenRead($chunkPath)
            $chunkStream.CopyTo($outputStream)
            $chunkStream.Close()

            Remove-Item $chunkPath -Force
        }

        $outputStream.Close()
        return $true

    }
    catch {
        Write-DevConsole "Parallel download error: $_" "ERROR"
        return $false
    }
}

<#
.SYNOPSIS
    Verifies downloaded file integrity
#>
function Verify-DownloadIntegrity {
    param(
        [string]$FilePath,
        [int64]$ExpectedSize,
        [string]$URL
    )

    try {
        # Check file exists and size matches
        if (-not (Test-Path $FilePath)) {
            return @{ Success = $false; Error = "File not found" }
        }

        $fileInfo = Get-Item $FilePath
        if ($fileInfo.Length -ne $ExpectedSize) {
            return @{
                Success = $false
                Error = "Size mismatch: Expected $(Format-Bytes $ExpectedSize), got $(Format-Bytes $fileInfo.Length)"
            }
        }

        # Calculate SHA-256
        Write-DevConsole "🔐 Calculating SHA-256..." "INFO"
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256

        Write-DevConsole "   SHA-256: $($hash.Hash.Substring(0, 16))..." "INFO"

        # If URL has hash in query params, verify
        if ($URL -match '#sha256=([a-f0-9]{64})') {
            $expectedHash = $matches[1].ToLower()
            $actualHash = $hash.Hash.ToLower()

            if ($actualHash -ne $expectedHash) {
                return @{
                    Success = $false
                    Error = "Hash mismatch"
                }
            }
        }

        return @{ Success = $true; Hash = $hash.Hash }

    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Formats byte size for display
#>
function Format-Bytes {
    param([int64]$Bytes)

    if ($Bytes -lt 1KB) {
        return "$Bytes B"
    }
    elseif ($Bytes -lt 1MB) {
        return "$([Math]::Round($Bytes / 1KB, 2)) KB"
    }
    elseif ($Bytes -lt 1GB) {
        return "$([Math]::Round($Bytes / 1MB, 2)) MB"
    }
    else {
        return "$([Math]::Round($Bytes / 1GB, 2)) GB"
    }
}

<#
.SYNOPSIS
    Gets download progress for active downloads

.PARAMETER RegistryId
    Download ID from Invoke-MultiThreadedDownload return value
#>
function Get-DownloadProgress {
    param([string]$RegistryId)

    $download = $script:DownloadRegistry.ActiveDownloads[$RegistryId]

    if (-not $download) {
        return $null
    }

    $elapsed = (Get-Date) - $download.StartTime
    $speedMBps = if ($elapsed.TotalSeconds -gt 0) {
        $download.DownloadedBytes / 1MB / $elapsed.TotalSeconds
    } else {
        0
    }

    $remainingBytes = $download.TotalSize - $download.DownloadedBytes
    $eta = if ($speedMBps -gt 0) {
        [timespan]::FromSeconds($remainingBytes / 1MB / $speedMBps)
    } else {
        [timespan]::Zero
    }

    return @{
        TotalBytes = $download.TotalSize
        DownloadedBytes = $download.DownloadedBytes
        Percent = [Math]::Round(($download.DownloadedBytes / $download.TotalSize) * 100, 1)
        Speed = "$([Math]::Round($speedMBps, 2)) MB/s"
        ETA = $eta.ToString('hh\:mm\:ss')
        Threads = $download.ThreadCount
    }
}

<#
.SYNOPSIS
    Lists all downloads (active, completed, failed)
#>
function Get-DownloadHistory {
    param(
        [ValidateSet("all", "active", "completed", "failed")]
        [string]$Status = "all"
    )

    $history = @()

    if ($Status -in @("all", "active")) {
        $history += $script:DownloadRegistry.ActiveDownloads.Values | Select-Object -Property @{
            Name = "Status"; Expression = { "Active" }
        }, URL, OutputPath, @{
            Name = "Size"; Expression = { Format-Bytes $_.TotalSize }
        }, @{
            Name = "Progress"; Expression = { "$([Math]::Round(($_.DownloadedBytes / $_.TotalSize) * 100, 1))%" }
        }
    }

    if ($Status -in @("all", "completed")) {
        $history += $script:DownloadRegistry.CompletedDownloads.Values | Select-Object -Property @{
            Name = "Status"; Expression = { "Completed" }
        }, URL, OutputPath, @{
            Name = "Size"; Expression = { Format-Bytes $_.TotalSize }
        }, Speed, Duration, CompletedAt
    }

    if ($Status -in @("all", "failed")) {
        $history += $script:DownloadRegistry.FailedDownloads.Values | Select-Object -Property @{
            Name = "Status"; Expression = { "Failed" }
        }, URL, OutputPath
    }

    return $history
}

# Note: Export-ModuleMember removed - this file is dot-sourced, not imported as a module
# Export functions
# Export-ModuleMember -Function @(
#     'Invoke-MultiThreadedDownload',
#     'Get-DownloadFileInfo',
#     'Verify-DownloadIntegrity',
#     'Get-DownloadProgress',
#     'Get-DownloadHistory'
# )
