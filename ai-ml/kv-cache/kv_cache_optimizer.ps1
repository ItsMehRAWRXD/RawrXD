# RawrXD KV-Cache Optimizer
# Phase L Batch 3/5: Memory-Efficient Attention Caching
# Optimizes key-value cache for transformer attention mechanisms

param(
    [Parameter()]
    [ValidateSet("Configure", "Allocate", "Evict", "Compress", "Analyze", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$SessionId,
    
    [Parameter()]
    [int]$ContextLength = 4096,
    
    [Parameter()]
    [int]$NumLayers = 32,
    
    [Parameter()]
    [int]$NumHeads = 32,
    
    [Parameter()]
    [int]$HeadDim = 128,
    
    [Parameter()]
    [ValidateSet("Standard", "Paged", "SlidingWindow", "H2O", "Streaming")]
    [string]$CacheStrategy = "Paged",
    
    [Parameter()]
    [ValidateSet("FP32", "FP16", "BF16", "INT8", "Q4_0", "Q8_0")]
    [string]$Precision = "FP16",
    
    [Parameter()]
    [int]$MaxMemoryMB = 4096,
    
    [Parameter()]
    [hashtable]$Config = @{},
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\kv_cache_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\ai-ml"
)

# Cache strategies
$CacheStrategies = @{
    "Standard" = @{
        Name = "Standard KV Cache"
        Description = "Full context caching with contiguous memory"
        MemoryEfficiency = 1.0
        Speed = "Fast"
        MaxContext = "Limited by VRAM"
        Compression = $false
        Eviction = $false
    }
    "Paged" = @{
        Name = "PagedAttention"
        Description = "Block-based memory management like OS paging"
        MemoryEfficiency = 0.85
        Speed = "Very Fast"
        MaxContext = "Very Large"
        Compression = $false
        Eviction = $true
        BlockSize = 16
    }
    "SlidingWindow" = @{
        Name = "Sliding Window"
        Description = "Fixed-size rolling window cache"
        MemoryEfficiency = 0.5
        Speed = "Fast"
        MaxContext = "Fixed window"
        Compression = $false
        Eviction = $true
        WindowSize = 4096
    }
    "H2O" = @{
        Name = "Heavy Hitter Oracle"
        Description = "Keep important tokens, evict others"
        MemoryEfficiency = 0.4
        Speed = "Medium"
        MaxContext = "Very Large"
        Compression = $true
        Eviction = $true
        HeavyHitterRatio = 0.2
    }
    "Streaming" = @{
        Name = "StreamingLLM"
        Description = "Attention sink + rolling window"
        MemoryEfficiency = 0.3
        Speed = "Fast"
        MaxContext = "Infinite"
        Compression = $false
        Eviction = $true
        SinkTokens = 4
    }
}

# Precision formats
$PrecisionFormats = @{
    "FP32" = @{ Bits = 32; Compression = 1.0; Accuracy = 1.0 }
    "FP16" = @{ Bits = 16; Compression = 2.0; Accuracy = 0.999 }
    "BF16" = @{ Bits = 16; Compression = 2.0; Accuracy = 0.999 }
    "INT8" = @{ Bits = 8; Compression = 4.0; Accuracy = 0.98 }
    "Q4_0" = @{ Bits = 4; Compression = 8.0; Accuracy = 0.95 }
    "Q8_0" = @{ Bits = 8; Compression = 4.0; Accuracy = 0.99 }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\kv_cache_state.json"

function Write-KVCacheLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [KV-CACHE] $Message"
    
    $logFile = Join-Path $LogPath "kv_cache_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "KV-CACHE" { "Cyan" }
        "MEMORY" { "Magenta" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-KVCacheState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Sessions = @{}
        Allocations = @{}
        Statistics = @{
            TotalAllocations = 0
            TotalEvictions = 0
            TotalCompressed = 0
        }
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-KVCacheState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function Get-PrecisionSize {
    param([string]$Precision)
    return $PrecisionFormats[$Precision].Bits / 8  # Convert bits to bytes
}

function Get-KVCacheSize {
    param(
        [int]$ContextLength,
        [int]$NumLayers,
        [int]$NumHeads,
        [int]$HeadDim,
        [string]$Precision
    )
    
    $bytesPerElement = Get-PrecisionSize -Precision $Precision
    
    # KV cache size = 2 * (layers * context * heads * head_dim * bytes)
    # 2 for Key and Value
    $size = 2 * $NumLayers * $ContextLength * $NumHeads * $HeadDim * $bytesPerElement
    
    return $size
}

function New-KVCacheSession {
    param(
        [string]$SessionId,
        [int]$ContextLength,
        [int]$NumLayers,
        [int]$NumHeads,
        [int]$HeadDim,
        [string]$Strategy,
        [string]$Precision,
        [int]$MaxMemoryMB
    )
    
    Write-KVCacheLog "Creating KV cache session: $SessionId" "KV-CACHE"
    
    $strategyInfo = $CacheStrategies[$Strategy]
    $precisionInfo = $PrecisionFormats[$Precision]
    
    # Calculate base cache size
    $baseSize = Get-KVCacheSize -ContextLength $ContextLength -NumLayers $NumLayers -NumHeads $NumHeads -HeadDim $HeadDim -Precision $Precision
    
    # Apply strategy efficiency
    $effectiveSize = [math]::Floor($baseSize * $strategyInfo.MemoryEfficiency)
    
    # Check memory constraints
    $maxBytes = $MaxMemoryMB * 1MB
    $actualContextLength = $ContextLength
    
    if ($effectiveSize -gt $maxBytes) {
        # Adjust context length to fit memory
        $scaleFactor = $maxBytes / $effectiveSize
        $actualContextLength = [math]::Floor($ContextLength * $scaleFactor)
        $effectiveSize = [math]::Floor($effectiveSize * $scaleFactor)
        
        Write-KVCacheLog "Adjusted context length: $ContextLength -> $actualContextLength (memory constraint)" "WARN"
    }
    
    $session = @{
        Id = $SessionId
        Config = @{
            ContextLength = $ContextLength
            ActualContextLength = $actualContextLength
            NumLayers = $NumLayers
            NumHeads = $NumHeads
            HeadDim = $HeadDim
            Strategy = $Strategy
            Precision = $Precision
            MaxMemoryMB = $MaxMemoryMB
        }
        Memory = @{
            Allocated = $effectiveSize
            Used = 0
            Available = $effectiveSize
            PeakUsage = 0
        }
        Statistics = @{
            Allocations = 0
            Evictions = 0
            Compressions = 0
            CacheHits = 0
            CacheMisses = 0
        }
        Status = "Active"
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $state = Get-KVCacheState
    $state.Sessions[$SessionId] = $session
    $state.Statistics.TotalAllocations++
    Save-KVCacheState -State $state
    
    Write-KVCacheLog "Session created: $SessionId ($([math]::Round($effectiveSize / 1MB, 2)) MB allocated)" "SUCCESS"
    
    return $session
}

function Invoke-CacheAllocation {
    param(
        [string]$SessionId,
        [int]$TokenCount
    )
    
    $state = Get-KVCacheState
    $session = $state.Sessions[$SessionId]
    
    if (-not $session) {
        Write-KVCacheLog "Session not found: $SessionId" "ERROR"
        return $null
    }
    
    # Calculate memory needed
    $bytesPerToken = $session.Memory.Allocated / $session.Config.ActualContextLength
    $memoryNeeded = $TokenCount * $bytesPerToken
    
    # Check if we need eviction
    if ($session.Memory.Used + $memoryNeeded -gt $session.Memory.Available) {
        $evicted = Invoke-CacheEviction -SessionId $SessionId -MemoryNeeded ($memoryNeeded - ($session.Memory.Available - $session.Memory.Used))
        Write-KVCacheLog "Evicted $evicted tokens to make room" "MEMORY"
    }
    
    # Allocate
    $session.Memory.Used += $memoryNeeded
    if ($session.Memory.Used -gt $session.Memory.PeakUsage) {
        $session.Memory.PeakUsage = $session.Memory.Used
    }
    $session.Statistics.Allocations++
    
    Save-KVCacheState -State $state
    
    return @{
        Allocated = $true
        Tokens = $TokenCount
        MemoryUsed = $memoryNeeded
        Remaining = $session.Memory.Available - $session.Memory.Used
    }
}

function Invoke-CacheEviction {
    param(
        [string]$SessionId,
        [long]$MemoryNeeded
    )
    
    $state = Get-KVCacheState
    $session = $state.Sessions[$SessionId]
    
    $strategy = $session.Config.Strategy
    $evicted = 0
    
    switch ($strategy) {
        "SlidingWindow" {
            # Evict oldest tokens
            $evicted = [math]::Floor($MemoryNeeded / ($session.Memory.Allocated / $session.Config.ActualContextLength))
        }
        "H2O" {
            # Evict non-heavy-hitters
            $evicted = [math]::Floor($MemoryNeeded / ($session.Memory.Allocated / $session.Config.ActualContextLength) * 0.8)
        }
        "Streaming" {
            # Keep sink tokens, evict from window
            $evicted = [math]::Floor($MemoryNeeded / ($session.Memory.Allocated / $session.Config.ActualContextLength))
        }
        default {
            $evicted = [math]::Floor($MemoryNeeded / ($session.Memory.Allocated / $session.Config.ActualContextLength))
        }
    }
    
    $session.Memory.Used -= $MemoryNeeded
    $session.Statistics.Evictions += $evicted
    $state.Statistics.TotalEvictions += $evicted
    
    return $evicted
}

function Invoke-CacheCompression {
    param(
        [string]$SessionId,
        [string]$TargetPrecision = "INT8"
    )
    
    Write-KVCacheLog "Compressing cache for session: $SessionId" "KV-CACHE"
    
    $state = Get-KVCacheState
    $session = $state.Sessions[$SessionId]
    
    if (-not $session) {
        Write-KVCacheLog "Session not found: $SessionId" "ERROR"
        return $null
    }
    
    $currentBits = $PrecisionFormats[$session.Config.Precision].Bits
    $targetBits = $PrecisionFormats[$TargetPrecision].Bits
    
    if ($targetBits -ge $currentBits) {
        Write-KVCacheLog "Target precision not more compact" "WARN"
        return $null
    }
    
    $compressionRatio = $currentBits / $targetBits
    $oldSize = $session.Memory.Allocated
    $newSize = [math]::Floor($oldSize / $compressionRatio)
    
    $session.Memory.Allocated = $newSize
    $session.Memory.Available = $newSize
    $session.Config.Precision = $TargetPrecision
    $session.Statistics.Compressions++
    $state.Statistics.TotalCompressed++
    
    Save-KVCacheState -State $state
    
    Write-KVCacheLog "Cache compressed: $([math]::Round($oldSize / 1MB, 2))MB -> $([math]::Round($newSize / 1MB, 2))MB ($([math]::Round($compressionRatio, 1))x)" "SUCCESS"
    
    return @{
        OldSize = $oldSize
        NewSize = $newSize
        CompressionRatio = $compressionRatio
        NewPrecision = $TargetPrecision
    }
}

function Get-CacheAnalysis {
    param([string]$SessionId)
    
    $state = Get-KVCacheState
    $session = $state.Sessions[$SessionId]
    
    if (-not $session) {
        return @{ Error = "Session not found" }
    }
    
    $utilization = if ($session.Memory.Allocated -gt 0) { 
        $session.Memory.Used / $session.Memory.Allocated 
    } else { 0 }
    
    $hitRate = if (($session.Statistics.CacheHits + $session.Statistics.CacheMisses) -gt 0) {
        $session.Statistics.CacheHits / ($session.Statistics.CacheHits + $session.Statistics.CacheMisses)
    } else { 0 }
    
    return @{
        SessionId = $SessionId
        Strategy = $session.Config.Strategy
        Precision = $session.Config.Precision
        ContextLength = $session.Config.ActualContextLength
        Memory = @{
            Allocated = $session.Memory.Allocated
            Used = $session.Memory.Used
            Available = $session.Memory.Available
            PeakUsage = $session.Memory.PeakUsage
            Utilization = [math]::Round($utilization, 4)
        }
        Statistics = $session.Statistics
        Performance = @{
            HitRate = [math]::Round($hitRate, 4)
            EvictionRate = if ($session.Statistics.Allocations -gt 0) { 
                [math]::Round($session.Statistics.Evictions / $session.Statistics.Allocations, 4) 
            } else { 0 }
        }
    }
}

function Show-KVCacheStatus {
    $state = Get-KVCacheState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD KV-Cache Optimizer Status                    ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Active Sessions: $($state.Sessions.Count)" -ForegroundColor Cyan
    Write-Host "║ Total Allocations: $($state.Statistics.TotalAllocations)" -ForegroundColor Cyan
    Write-Host "║ Total Evictions: $($state.Statistics.TotalEvictions)" -ForegroundColor Cyan
    Write-Host "║ Total Compressed: $($state.Statistics.TotalCompressed)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Cache Strategies:" -ForegroundColor Cyan
    foreach ($strat in $CacheStrategies.Keys | Sort-Object) {
        $info = $CacheStrategies[$strat]
        Write-Host "║   $strat - $($info.Name)" -ForegroundColor Gray
        Write-Host "║     Efficiency: $($info.MemoryEfficiency) | Speed: $($info.Speed)" -ForegroundColor DarkGray
    }
    
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Precision Formats:" -ForegroundColor Cyan
    foreach ($prec in $PrecisionFormats.Keys | Sort-Object) {
        $info = $PrecisionFormats[$prec]
        Write-Host "║   $prec - $($info.Bits)-bit ($($info.Compression)x compression)" -ForegroundColor Gray
    }
    
    if ($state.Sessions.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Active Sessions:" -ForegroundColor Cyan
        foreach ($session in $state.Sessions.Values | Select-Object -First 5) {
            $memMB = [math]::Round($session.Memory.Allocated / 1MB, 2)
            Write-Host "║   $($session.Id.Substring(0,8))... - $($session.Config.Strategy) ($memMB MB)" -ForegroundColor Gray
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Configure" {
        if (-not $SessionId) {
            $SessionId = [System.Guid]::NewGuid().ToString()
        }
        $session = New-KVCacheSession -SessionId $SessionId -ContextLength $ContextLength -NumLayers $NumLayers -NumHeads $NumHeads -HeadDim $HeadDim -Strategy $CacheStrategy -Precision $Precision -MaxMemoryMB $MaxMemoryMB
        $session | ConvertTo-Json -Depth 10
    }
    "Allocate" {
        if (-not $SessionId) {
            Write-KVCacheLog "SessionId required" "ERROR"
            exit 1
        }
        $tokens = if ($Config.ContainsKey("Tokens")) { $Config.Tokens } else { 512 }
        $result = Invoke-CacheAllocation -SessionId $SessionId -TokenCount $tokens
        $result | ConvertTo-Json
    }
    "Evict" {
        if (-not $SessionId) {
            Write-KVCacheLog "SessionId required" "ERROR"
            exit 1
        }
        $memory = if ($Config.ContainsKey("Memory")) { $Config.Memory } else { 100MB }
        $evicted = Invoke-CacheEviction -SessionId $SessionId -MemoryNeeded $memory
        @{ Evicted = $evicted } | ConvertTo-Json
    }
    "Compress" {
        if (-not $SessionId) {
            Write-KVCacheLog "SessionId required" "ERROR"
            exit 1
        }
        $target = if ($Config.ContainsKey("TargetPrecision")) { $Config.TargetPrecision } else { "INT8" }
        $result = Invoke-CacheCompression -SessionId $SessionId -TargetPrecision $target
        if ($result) {
            $result | ConvertTo-Json
        }
    }
    "Analyze" {
        if (-not $SessionId) {
            Write-KVCacheLog "SessionId required" "ERROR"
            exit 1
        }
        $analysis = Get-CacheAnalysis -SessionId $SessionId
        $analysis | ConvertTo-Json -Depth 10
    }
    "ShowStatus" {
        Show-KVCacheStatus
    }
}
