# RawrXD Knowledge Base
# Phase G.3 Batch 4/5: Learned Optimization Patterns Storage
# Stores and retrieves learned patterns from system operation

param(
    [Parameter()]
    [ValidateSet("Store", "Retrieve", "Query", "Analyze", "Export", "Import", "Prune")]
    [string]$Action = "Query",
    
    [Parameter()]
    [string]$KnowledgePath = "$PSScriptRoot\knowledge_store",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\autonomous\knowledge",
    
    [Parameter()]
    [string]$Category,
    
    [Parameter()]
    [string]$Key,
    
    [Parameter()]
    [object]$Value,
    
    [Parameter()]
    [hashtable]$Metadata = @{},
    
    [Parameter()]
    [string]$Query,
    
    [Parameter()]
    [int]$MaxResults = 10,
    
    [Parameter()]
    [double]$MinConfidence = 0.5,
    
    [Parameter()]
    [string]$ExportPath,
    
    [Parameter()]
    [string]$ImportPath,
    
    [Parameter()]
    [int]$RetentionDays = 90,
    
    [Parameter()]
    [switch]$ShowStats
)

# Knowledge categories
$Categories = @{
    Optimization = @{
        Description = "Learned optimization patterns"
        Schema = @{
            ParameterSet = "hashtable"
            PerformanceGain = "double"
            Context = "hashtable"
            Confidence = "double"
            UsageCount = "int"
        }
    }
    AnomalyPattern = @{
        Description = "Detected anomaly patterns"
        Schema = @{
            Pattern = "string"
            Indicators = "array"
            Severity = "string"
            Frequency = "int"
        }
    }
    DecisionOutcome = @{
        Description = "Results of autonomous decisions"
        Schema = @{
            DecisionType = "string"
            Parameters = "hashtable"
            Outcome = "string"
            Success = "boolean"
            Duration = "double"
        }
    }
    PerformanceProfile = @{
        Description = "System performance profiles"
        Schema = @{
            HardwareConfig = "hashtable"
            ModelConfig = "hashtable"
            Metrics = "hashtable"
            Timestamp = "datetime"
        }
    }
    FailurePattern = @{
        Description = "Failure patterns and recovery"
        Schema = @{
            FailureType = "string"
            Symptoms = "array"
            RootCause = "string"
            RecoveryAction = "string"
            SuccessRate = "double"
        }
    }
    BestPractice = @{
        Description = "Emerging best practices"
        Schema = @{
            Practice = "string"
            Context = "string"
            Benefit = "string"
            AdoptionCount = "int"
        }
    }
}

# Ensure directories exist
if (-not (Test-Path $KnowledgePath)) {
    New-Item -ItemType Directory -Path $KnowledgePath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Index file for fast lookups
$IndexFile = Join-Path $KnowledgePath "index.json"

function Write-KnowledgeLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $logFile = Join-Path $LogPath "knowledge_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "LEARN" { "Green" }
        "QUERY" { "Cyan" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-KnowledgeIndex {
    if (Test-Path $IndexFile) {
        return Get-Content $IndexFile | ConvertFrom-Json
    }
    return @{
        Version = "1.0"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Entries = @{}
        Stats = @{
            TotalEntries = 0
            Categories = @{}
        }
    }
}

function Save-KnowledgeIndex {
    param($Index)
    
    $Index.LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Index | ConvertTo-Json -Depth 10 | Out-File $IndexFile -Encoding UTF8
}

function Get-CategoryPath {
    param([string]$Category)
    return Join-Path $KnowledgePath $Category
}

function Ensure-CategoryPath {
    param([string]$Category)
    
    $path = Get-CategoryPath -Category $Category
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

function Get-EntryPath {
    param([string]$Category, [string]$Key)
    
    $categoryPath = Ensure-CategoryPath -Category $Category
    $safeKey = $Key -replace '[^a-zA-Z0-9_-]', '_'
    return Join-Path $categoryPath "$safeKey.json"
}

function Store-Knowledge {
    param(
        [string]$Category,
        [string]$Key,
        [object]$Value,
        [hashtable]$Metadata = @{}
    )
    
    if (-not $Categories.ContainsKey($Category)) {
        Write-KnowledgeLog "Unknown category: $Category" "ERROR"
        return $false
    }
    
    $entry = @{
        Key = $Key
        Category = $Category
        Value = $Value
        Metadata = $Metadata
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Modified = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        AccessCount = 0
        Confidence = if ($Metadata.Confidence) { $Metadata.Confidence } else { 0.5 }
        Tags = if ($Metadata.Tags) { $Metadata.Tags } else { @() }
    }
    
    $entryPath = Get-EntryPath -Category $Category -Key $Key
    $entry | ConvertTo-Json -Depth 10 | Out-File $entryPath -Encoding UTF8
    
    # Update index
    $index = Get-KnowledgeIndex
    if (-not $index.Entries[$Category]) {
        $index.Entries[$Category] = @{}
    }
    $index.Entries[$Category][$Key] = @{
        Path = $entryPath
        Created = $entry.Created
        Modified = $entry.Modified
        Confidence = $entry.Confidence
    }
    
    $index.Stats.TotalEntries++
    if (-not $index.Stats.Categories[$Category]) {
        $index.Stats.Categories[$Category] = 0
    }
    $index.Stats.Categories[$Category]++
    
    Save-KnowledgeIndex -Index $index
    
    Write-KnowledgeLog "Stored knowledge: [$Category] $Key" "LEARN"
    return $true
}

function Retrieve-Knowledge {
    param([string]$Category, [string]$Key)
    
    $entryPath = Get-EntryPath -Category $Category -Key $Key
    
    if (-not (Test-Path $entryPath)) {
        return $null
    }
    
    $entry = Get-Content $entryPath | ConvertFrom-Json
    
    # Update access count
    $entry.AccessCount++
    $entry | ConvertTo-Json -Depth 10 | Out-File $entryPath -Encoding UTF8
    
    # Update index
    $index = Get-KnowledgeIndex
    if ($index.Entries[$Category] -and $index.Entries[$Category][$Key]) {
        $index.Entries[$Category][$Key].LastAccessed = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Save-KnowledgeIndex -Index $index
    }
    
    Write-KnowledgeLog "Retrieved knowledge: [$Category] $Key" "QUERY"
    return $entry
}

function Query-Knowledge {
    param(
        [string]$Category,
        [string]$Query,
        [int]$MaxResults = 10,
        [double]$MinConfidence = 0.5
    )
    
    $index = Get-KnowledgeIndex
    $results = @()
    
    $categoriesToSearch = if ($Category) { @($Category) } else { $Categories.Keys }
    
    foreach ($cat in $categoriesToSearch) {
        if (-not $index.Entries[$cat]) { continue }
        
        $categoryPath = Get-CategoryPath -Category $cat
        if (-not (Test-Path $categoryPath)) { continue }
        
        $entries = Get-ChildItem $categoryPath -Filter "*.json" | ForEach-Object {
            $entry = Get-Content $_.FullName | ConvertFrom-Json
            
            # Filter by confidence
            if ($entry.Confidence -lt $MinConfidence) { return }
            
            # Simple text search in key, value, and tags
            $matchScore = 0
            if ($Query) {
                $searchable = "$($entry.Key) $($entry.Value | ConvertTo-Json -Compress) $($entry.Tags -join ' ')"
                if ($searchable -like "*$Query*") {
                    $matchScore = 1
                }
                else {
                    return
                }
            }
            else {
                $matchScore = 1
            }
            
            [PSCustomObject]@{
                Category = $entry.Category
                Key = $entry.Key
                Value = $entry.Value
                Confidence = $entry.Confidence
                Created = $entry.Created
                Modified = $entry.Modified
                AccessCount = $entry.AccessCount
                Tags = $entry.Tags
                MatchScore = $matchScore
            }
        }
        
        $results += $entries
    }
    
    # Sort by confidence and match score
    return $results | Sort-Object -Property @{Expression = "MatchScore"; Descending = $true}, 
                                              @{Expression = "Confidence"; Descending = $true}, 
                                              @{Expression = "AccessCount"; Descending = $true} | 
                     Select-Object -First $MaxResults
}

function Analyze-Knowledge {
    $index = Get-KnowledgeIndex
    $analysis = @{
        Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalEntries = $index.Stats.TotalEntries
        Categories = @{}
        Trends = @{
            HighConfidence = 0
            FrequentlyAccessed = 0
            RecentlyLearned = 0
        }
        Recommendations = @()
    }
    
    $oneWeekAgo = (Get-Date).AddDays(-7).ToString("yyyy-MM-dd")
    
    foreach ($category in $Categories.Keys) {
        $catPath = Get-CategoryPath -Category $category
        if (-not (Test-Path $catPath)) { continue }
        
        $entries = Get-ChildItem $catPath -Filter "*.json" | ForEach-Object {
            Get-Content $_.FullName | ConvertFrom-Json
        }
        
        $analysis.Categories[$category] = @{
            Count = $entries.Count
            AvgConfidence = if ($entries.Count -gt 0) { 
                ($entries | Measure-Object -Property Confidence -Average).Average 
            } else { 0 }
            HighConfidence = ($entries | Where-Object { $_.Confidence -ge 0.8 }).Count
            TotalAccesses = ($entries | Measure-Object -Property AccessCount -Sum).Sum
            RecentEntries = ($entries | Where-Object { $_.Created -gt $oneWeekAgo }).Count
        }
        
        $analysis.Trends.HighConfidence += $analysis.Categories[$category].HighConfidence
        $analysis.Trends.RecentlyLearned += $analysis.Categories[$category].RecentEntries
    }
    
    # Generate recommendations
    if ($analysis.Trends.HighConfidence -lt ($index.Stats.TotalEntries * 0.3)) {
        $analysis.Recommendations += "Low high-confidence knowledge. Consider more training/validation."
    }
    
    if ($analysis.Trends.RecentlyLearned -eq 0) {
        $analysis.Recommendations += "No new knowledge in past week. System may need retraining."
    }
    
    return $analysis
}

function Export-Knowledge {
    param([string]$ExportPath)
    
    $index = Get-KnowledgeIndex
    $export = @{
        Version = "1.0"
        Exported = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Categories = @{}
    }
    
    foreach ($category in $Categories.Keys) {
        $catPath = Get-CategoryPath -Category $category
        if (-not (Test-Path $catPath)) { continue }
        
        $export.Categories[$category] = @()
        
        Get-ChildItem $catPath -Filter "*.json" | ForEach-Object {
            $entry = Get-Content $_.FullName | ConvertFrom-Json
            $export.Categories[$category] += $entry
        }
    }
    
    $export | ConvertTo-Json -Depth 10 | Out-File $ExportPath -Encoding UTF8
    Write-KnowledgeLog "Exported knowledge to: $ExportPath"
    
    return $true
}

function Import-Knowledge {
    param([string]$ImportPath)
    
    if (-not (Test-Path $ImportPath)) {
        Write-KnowledgeLog "Import file not found: $ImportPath" "ERROR"
        return $false
    }
    
    $import = Get-Content $ImportPath | ConvertFrom-Json
    $imported = 0
    
    foreach ($category in $import.Categories.PSObject.Properties.Name) {
        foreach ($entry in $import.Categories[$category]) {
            $success = Store-Knowledge -Category $category -Key $entry.Key -Value $entry.Value -Metadata $entry.Metadata
            if ($success) { $imported++ }
        }
    }
    
    Write-KnowledgeLog "Imported $imported knowledge entries from: $ImportPath"
    return $true
}

function Prune-Knowledge {
    param([int]$RetentionDays)
    
    $cutoff = (Get-Date).AddDays(-$RetentionDays).ToString("yyyy-MM-dd")
    $pruned = 0
    
    foreach ($category in $Categories.Keys) {
        $catPath = Get-CategoryPath -Category $category
        if (-not (Test-Path $catPath)) { continue }
        
        Get-ChildItem $catPath -Filter "*.json" | ForEach-Object {
            $entry = Get-Content $_.FullName | ConvertFrom-Json
            
            if ($entry.Modified -lt $cutoff -and $entry.AccessCount -eq 0) {
                Remove-Item $_.FullName
                $pruned++
            }
        }
    }
    
    # Rebuild index
    $index = Get-KnowledgeIndex
    $index.Entries = @{}
    $index.Stats.TotalEntries = 0
    $index.Stats.Categories = @{}
    
    foreach ($category in $Categories.Keys) {
        $catPath = Get-CategoryPath -Category $category
        if (-not (Test-Path $catPath)) { continue }
        
        $count = 0
        Get-ChildItem $catPath -Filter "*.json" | ForEach-Object {
            $entry = Get-Content $_.FullName | ConvertFrom-Json
            
            if (-not $index.Entries[$category]) {
                $index.Entries[$category] = @{}
            }
            $index.Entries[$category][$entry.Key] = @{
                Path = $_.FullName
                Created = $entry.Created
                Modified = $entry.Modified
                Confidence = $entry.Confidence
            }
            $count++
        }
        
        $index.Stats.Categories[$category] = $count
        $index.Stats.TotalEntries += $count
    }
    
    Save-KnowledgeIndex -Index $index
    
    Write-KnowledgeLog "Pruned $pruned old knowledge entries"
    return $pruned
}

function Show-KnowledgeStats {
    $index = Get-KnowledgeIndex
    $analysis = Analyze-Knowledge
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              RawrXD Knowledge Base Statistics                   ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Entries: $($index.Stats.TotalEntries)" -ForegroundColor Cyan
    Write-Host "║ Version: $($index.Version)" -ForegroundColor Cyan
    Write-Host "║ Last Updated: $($index.LastUpdated)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Categories:" -ForegroundColor Cyan
    foreach ($cat in $analysis.Categories.Keys) {
        $stats = $analysis.Categories[$cat]
        Write-Host "║   $cat`: $($stats.Count) entries" -ForegroundColor Cyan
        Write-Host "║     Avg Confidence: $([math]::Round($stats.AvgConfidence * 100, 1))%" -ForegroundColor Gray
        Write-Host "║     High Confidence: $($stats.HighConfidence)" -ForegroundColor Green
        Write-Host "║     Recent: $($stats.RecentEntries)" -ForegroundColor Yellow
    }
    
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Trends:" -ForegroundColor Cyan
    Write-Host "║   High Confidence Entries: $($analysis.Trends.HighConfidence)" -ForegroundColor Green
    Write-Host "║   Recently Learned: $($analysis.Trends.RecentlyLearned)" -ForegroundColor Yellow
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    if ($analysis.Recommendations.Count -gt 0) {
        Write-Host "║ Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $analysis.Recommendations) {
            Write-Host "║   ! $rec" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "║ No recommendations - system healthy" -ForegroundColor Green
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "Store" {
        if (-not $Category -or -not $Key) {
            Write-KnowledgeLog "Category and Key required for Store action" "ERROR"
            exit 1
        }
        $success = Store-Knowledge -Category $Category -Key $Key -Value $Value -Metadata $Metadata
        exit ($success ? 0 : 1)
    }
    
    "Retrieve" {
        if (-not $Category -or -not $Key) {
            Write-KnowledgeLog "Category and Key required for Retrieve action" "ERROR"
            exit 1
        }
        $entry = Retrieve-Knowledge -Category $Category -Key $Key
        if ($entry) {
            $entry | ConvertTo-Json -Depth 10
            exit 0
        }
        else {
            Write-KnowledgeLog "Entry not found: [$Category] $Key" "WARN"
            exit 1
        }
    }
    
    "Query" {
        $results = Query-Knowledge -Category $Category -Query $Query -MaxResults $MaxResults -MinConfidence $MinConfidence
        if ($results.Count -gt 0) {
            $results | Format-Table -AutoSize
        }
        else {
            Write-KnowledgeLog "No results found" "WARN"
        }
        exit 0
    }
    
    "Analyze" {
        $analysis = Analyze-Knowledge
        $analysis | ConvertTo-Json -Depth 10
        exit 0
    }
    
    "Export" {
        if (-not $ExportPath) {
            $ExportPath = "knowledge_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        }
        $success = Export-Knowledge -ExportPath $ExportPath
        exit ($success ? 0 : 1)
    }
    
    "Import" {
        if (-not $ImportPath) {
            Write-KnowledgeLog "ImportPath required for Import action" "ERROR"
            exit 1
        }
        $success = Import-Knowledge -ImportPath $ImportPath
        exit ($success ? 0 : 1)
    }
    
    "Prune" {
        $pruned = Prune-Knowledge -RetentionDays $RetentionDays
        Write-KnowledgeLog "Pruned $pruned entries older than $RetentionDays days"
        exit 0
    }
}

if ($ShowStats) {
    Show-KnowledgeStats
    exit 0
}

Write-KnowledgeLog "RawrXD Knowledge Base"
Write-KnowledgeLog "Usage: Store, Retrieve, Query, Analyze, Export, Import, Prune"
Write-KnowledgeLog "Categories: $($Categories.Keys -join ', ')"
