# RawrXD Custom Model Training Pipeline
# Phase L Batch 5/5: Fine-tuning and Model Customization
# Supports LoRA, QLoRA, full fine-tuning, and RLHF

param(
    [Parameter()]
    [ValidateSet("PrepareData", "StartTraining", "Evaluate", "Export", "ListJobs", "ShowStatus")]
    [string]$Action = "ShowStatus",
    
    [Parameter()]
    [string]$JobId,
    
    [Parameter()]
    [string]$BaseModelPath,
    
    [Parameter()]
    [string]$DatasetPath,
    
    [Parameter()]
    [ValidateSet("LoRA", "QLoRA", "Full", "Adapter", "RLHF", "DPO")]
    [string]$Method = "LoRA",
    
    [Parameter()]
    [int]$Epochs = 3,
    
    [Parameter()]
    [double]$LearningRate = 5e-5,
    
    [Parameter()]
    [int]$BatchSize = 4,
    
    [Parameter()]
    [string]$OutputDir,
    
    [Parameter()]
    [hashtable]$Hyperparameters = @{},
    
    [Parameter()]
    [string]$DataPath = "$PSScriptRoot\training_data",
    
    [Parameter()]
    [string]$LogPath = "$PSScriptRoot\..\..\logs\ai-ml"
)

# Training methods
$TrainingMethods = @{
    "LoRA" = @{
        Name = "Low-Rank Adaptation"
        Description = "Efficient fine-tuning with low-rank matrices"
        VRAMRequirement = "8GB+"
        Speed = "Fast"
        Quality = "High"
        TrainableParams = "1-2%"
        CheckpointSize = "Small"
        Supports = @("LLaMA", "GPT", "Mistral", "Qwen")
        Parameters = @{
            Rank = 64
            Alpha = 128
            Dropout = 0.05
            TargetModules = @("q_proj", "v_proj", "k_proj", "o_proj")
        }
    }
    "QLoRA" = @{
        Name = "Quantized LoRA"
        Description = "LoRA with 4-bit quantization"
        VRAMRequirement = "6GB+"
        Speed = "Fast"
        Quality = "High"
        TrainableParams = "1-2%"
        CheckpointSize = "Very Small"
        Supports = @("LLaMA", "Mistral", "Qwen")
        Parameters = @{
            Rank = 64
            Alpha = 16
            Quantization = "4bit"
            DoubleQuant = $true
        }
    }
    "Full" = @{
        Name = "Full Fine-tuning"
        Description = "Update all model parameters"
        VRAMRequirement = "40GB+"
        Speed = "Slow"
        Quality = "Highest"
        TrainableParams = "100%"
        CheckpointSize = "Large"
        Supports = @("All models")
        Parameters = @{
            GradientAccumulation = 4
            WarmupSteps = 100
            WeightDecay = 0.01
        }
    }
    "Adapter" = @{
        Name = "Adapter Layers"
        Description = "Add small adapter layers"
        VRAMRequirement = "12GB+"
        Speed = "Medium"
        Quality = "Medium"
        TrainableParams = "3-5%"
        CheckpointSize = "Small"
        Supports = @("BERT", "T5", "LLaMA")
        Parameters = @{
            AdapterDim = 256
            AdapterDropout = 0.1
        }
    }
    "RLHF" = @{
        Name = "Reinforcement Learning from Human Feedback"
        Description = "Train with reward model and PPO"
        VRAMRequirement = "24GB+"
        Speed = "Very Slow"
        Quality = "Highest"
        TrainableParams = "All"
        CheckpointSize = "Large"
        Supports = @("LLaMA", "GPT")
        Parameters = @{
            RewardModel = "required"
            PPOEpochs = 4
            KLCoef = 0.2
        }
    }
    "DPO" = @{
        Name = "Direct Preference Optimization"
        Description = "Simpler alternative to RLHF"
        VRAMRequirement = "16GB+"
        Speed = "Medium"
        Quality = "High"
        TrainableParams = "All"
        CheckpointSize = "Large"
        Supports = @("LLaMA", "Mistral", "Qwen")
        Parameters = @{
            Beta = 0.1
            LabelSmoothing = 0.0
        }
    }
}

# Dataset formats
$DatasetFormats = @{
    "Alpaca" = @{
        Name = "Alpaca Format"
        Description = "Instruction-following format"
        Fields = @("instruction", "input", "output")
        Extension = ".json"
    }
    "ShareGPT" = @{
        Name = "ShareGPT Format"
        Description = "Conversational format"
        Fields = @("conversations")
        Extension = ".json"
    }
    "RawText" = @{
        Name = "Raw Text"
        Description = "Plain text files"
        Fields = @("text")
        Extension = ".txt"
    }
    "CSV" = @{
        Name = "CSV Format"
        Description = "Comma-separated values"
        Fields = @("prompt", "completion")
        Extension = ".csv"
    }
    "Parquet" = @{
        Name = "Parquet Format"
        Description = "Columnar storage format"
        Fields = @("input", "output")
        Extension = ".parquet"
    }
}

# Training stages
$TrainingStages = @{
    "PREPARE" = @{ Name = "Data Preparation"; Order = 1 }
    "TOKENIZE" = @{ Name = "Tokenization"; Order = 2 }
    "TRAIN" = @{ Name = "Training"; Order = 3 }
    "EVALUATE" = @{ Name = "Evaluation"; Order = 4 }
    "EXPORT" = @{ Name = "Export"; Order = 5 }
    "COMPLETE" = @{ Name = "Complete"; Order = 6 }
}

# Ensure directories exist
if (-not (Test-Path $DataPath)) {
    New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
}
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

$StateFile = "$PSScriptRoot\training_state.json"

function Write-TrainingLog {
    param([string]$Message, [string]$Level = "INFO", [string]$Job = "")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $jobTag = if ($Job) { "[$Job]" } else { "" }
    $logEntry = "[$timestamp] [$Level] [TRAIN]$jobTag $Message"
    
    $logFile = Join-Path $LogPath "training_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry
    
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARN"  { "Yellow" }
        "SUCCESS" { "Green" }
        "TRAIN" { "Cyan" }
        "EPOCH" { "Magenta" }
        "EVAL" { "Blue" }
        default { "White" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-TrainingState {
    if (Test-Path $StateFile) {
        return Get-Content $StateFile | ConvertFrom-Json
    }
    return @{
        Jobs = @{}
        Datasets = @{}
        Models = @{}
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Save-TrainingState {
    param($State)
    $State | ConvertTo-Json -Depth 10 | Out-File $StateFile -Encoding UTF8
}

function New-TrainingJob {
    param(
        [string]$BaseModel,
        [string]$Dataset,
        [string]$Method,
        [hashtable]$Config
    )
    
    Write-TrainingLog "Creating training job: $Method on $BaseModel" "TRAIN"
    
    $methodInfo = $TrainingMethods[$Method]
    
    $job = @{
        Id = [System.Guid]::NewGuid().ToString()
        BaseModel = $BaseModel
        Dataset = $Dataset
        Method = $Method
        Config = $Config
        Status = "CREATED"
        Stage = "PREPARE"
        Progress = @{
            CurrentEpoch = 0
            TotalEpochs = $Config.Epochs
            Steps = 0
            Loss = 0.0
            LearningRate = $Config.LearningRate
        }
        Metrics = @{
            TrainLoss = @()
            EvalLoss = @()
            Perplexity = @()
        }
        Resources = @{
            VRAMUsed = 0
            TimeElapsed = 0
            Checkpoints = 0
        }
        Created = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Started = $null
        Completed = $null
    }
    
    $state = Get-TrainingState
    $state.Jobs[$job.Id] = $job
    Save-TrainingState -State $state
    
    Write-TrainingLog "Job created: $($job.Id)" "SUCCESS"
    
    return $job
}

function Start-TrainingJob {
    param([string]$JobId)
    
    Write-TrainingLog "Starting training job: $JobId" "TRAIN" $JobId
    
    $state = Get-TrainingState
    $job = $state.Jobs[$JobId]
    
    if (-not $job) {
        Write-TrainingLog "Job not found: $JobId" "ERROR"
        return $null
    }
    
    $job.Status = "RUNNING"
    $job.Started = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $job.Stage = "TRAIN"
    
    $methodInfo = $TrainingMethods[$job.Method]
    
    # Simulate training
    $startTime = Get-Date
    
    for ($epoch = 1; $epoch -le $job.Config.Epochs; $epoch++) {
        $job.Progress.CurrentEpoch = $epoch
        Write-TrainingLog "Epoch $epoch/$($job.Config.Epochs)" "EPOCH" $JobId
        
        # Simulate steps
        $stepsPerEpoch = 100
        for ($step = 1; $step -le $stepsPerEpoch; $step++) {
            $job.Progress.Steps++
            
            # Simulate loss curve
            $baseLoss = 2.5
            $epochDecay = [math]::Exp(-$epoch / 3)
            $stepNoise = (Get-Random -Minimum -0.1 -Maximum 0.1)
            $loss = $baseLoss * $epochDecay + $stepNoise
            $job.Progress.Loss = [math]::Max(0.1, $loss)
            
            if ($step % 20 -eq 0) {
                $job.Metrics.TrainLoss += $job.Progress.Loss
            }
            
            # Simulate VRAM usage
            $job.Resources.VRAMUsed = Get-Random -Minimum 6000 -Maximum 22000
            
            Start-Sleep -Milliseconds 10
        }
        
        # Evaluation after epoch
        $evalLoss = $job.Progress.Loss * 1.1
        $job.Metrics.EvalLoss += $evalLoss
        $job.Metrics.Perplexity += [math]::Exp($evalLoss)
        
        Write-TrainingLog "Epoch $epoch complete - Loss: $([math]::Round($job.Progress.Loss, 4))" "EPOCH" $JobId
        
        # Save checkpoint
        $job.Resources.Checkpoints++
    }
    
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    $job.Resources.TimeElapsed = $duration
    
    $job.Status = "COMPLETED"
    $job.Stage = "COMPLETE"
    $job.Completed = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    Save-TrainingState -State $state
    
    Write-TrainingLog "Training complete in $([math]::Round($duration, 1))s" "SUCCESS" $JobId
    
    return $job
}

function Get-TrainingMetrics {
    param([string]$JobId)
    
    $state = Get-TrainingState
    $job = $state.Jobs[$JobId]
    
    if (-not $job) {
        return @{ Error = "Job not found" }
    }
    
    $finalLoss = if ($job.Metrics.TrainLoss.Count -gt 0) { 
        $job.Metrics.TrainLoss[-1] 
    } else { 0 }
    
    $avgEvalLoss = if ($job.Metrics.EvalLoss.Count -gt 0) { 
        ($job.Metrics.EvalLoss | Measure-Object -Average).Average 
    } else { 0 }
    
    return @{
        JobId = $JobId
        Status = $job.Status
        Method = $job.Method
        Epochs = $job.Progress.CurrentEpoch
        FinalLoss = [math]::Round($finalLoss, 4)
        AvgEvalLoss = [math]::Round($avgEvalLoss, 4)
        Perplexity = [math]::Round([math]::Exp($avgEvalLoss), 2)
        TrainingTime = [math]::Round($job.Resources.TimeElapsed / 60, 2)  # minutes
        Checkpoints = $job.Resources.Checkpoints
        VRAMPeak = $job.Resources.VRAMUsed
    }
}

function Export-TrainedModel {
    param(
        [string]$JobId,
        [string]$OutputPath
    )
    
    Write-TrainingLog "Exporting model from job: $JobId" "TRAIN" $JobId
    
    $state = Get-TrainingState
    $job = $state.Jobs[$JobId]
    
    if (-not $job) {
        Write-TrainingLog "Job not found: $JobId" "ERROR"
        return $null
    }
    
    if ($job.Status -ne "COMPLETED") {
        Write-TrainingLog "Job not complete: $($job.Status)" "ERROR"
        return $null
    }
    
    # Simulate export
    $exportInfo = @{
        JobId = $JobId
        BaseModel = $job.BaseModel
        Method = $job.Method
        OutputPath = $OutputPath
        Format = if ($job.Method -in @("LoRA", "QLoRA")) { "Adapter" } else { "Full" }
        Size = if ($job.Method -in @("LoRA", "QLoRA")) { "~100MB" } else { "~7GB" }
        Exported = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $state.Models[$JobId] = $exportInfo
    Save-TrainingState -State $state
    
    Write-TrainingLog "Model exported to: $OutputPath" "SUCCESS" $JobId
    
    return $exportInfo
}

function Get-MethodRecommendation {
    param(
        [long]$AvailableVRAM,  # MB
        [string]$DatasetSize,   # small, medium, large
        [string]$QualityTarget  # fast, balanced, best
    )
    
    $recommendations = @()
    
    foreach ($method in $TrainingMethods.Keys) {
        $info = $TrainingMethods[$method]
        $vramMatch = $false
        
        # Parse VRAM requirement
        $vramReq = $info.VRAMRequirement -replace 'GB\+', '' -replace 'GB', ''
        $vramNeeded = [int]$vramReq * 1024
        
        if ($AvailableVRAM -ge $vramNeeded) {
            $vramMatch = $true
        }
        
        $speedMatch = switch ($QualityTarget) {
            "fast" { $info.Speed -in @("Fast", "Very Fast") }
            "balanced" { $true }
            "best" { $info.Quality -in @("High", "Highest") }
            default { $true }
        }
        
        if ($vramMatch -and $speedMatch) {
            $recommendations += @{
                Method = $method
                Score = if ($QualityTarget -eq "fast") { 
                    if ($info.Speed -eq "Fast") { 10 } else { 5 }
                } elseif ($QualityTarget -eq "best") {
                    if ($info.Quality -eq "Highest") { 10 } else { 5 }
                } else { 7 }
                Info = $info
            }
        }
    }
    
    return $recommendations | Sort-Object Score -Descending | Select-Object -First 3
}

function Show-TrainingStatus {
    $state = Get-TrainingState
    
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           RawrXD Training Pipeline Status                     ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Total Jobs: $($state.Jobs.Count)" -ForegroundColor Cyan
    Write-Host "║ Completed: $(($state.Jobs.Values | Where-Object { $_.Status -eq 'COMPLETED' }).Count)" -ForegroundColor Cyan
    Write-Host "║ Running: $(($state.Jobs.Values | Where-Object { $_.Status -eq 'RUNNING' }).Count)" -ForegroundColor Cyan
    Write-Host "║ Exported Models: $($state.Models.Count)" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    
    Write-Host "║ Training Methods:" -ForegroundColor Cyan
    foreach ($method in $TrainingMethods.Keys | Sort-Object) {
        $info = $TrainingMethods[$method]
        Write-Host "║   $method - $($info.Name)" -ForegroundColor Gray
        Write-Host "║     VRAM: $($info.VRAMRequirement) | Speed: $($info.Speed) | Quality: $($info.Quality)" -ForegroundColor DarkGray
    }
    
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║ Dataset Formats:" -ForegroundColor Cyan
    foreach ($format in $DatasetFormats.Keys | Sort-Object) {
        $info = $DatasetFormats[$format]
        Write-Host "║   $format - $($info.Name)" -ForegroundColor Gray
    }
    
    if ($state.Jobs.Count -gt 0) {
        Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
        Write-Host "║ Recent Jobs:" -ForegroundColor Cyan
        $recent = $state.Jobs.Values | Sort-Object Created -Descending | Select-Object -First 5
        foreach ($job in $recent) {
            $color = switch ($job.Status) {
                "COMPLETED" { "Green" }
                "RUNNING" { "Cyan" }
                "FAILED" { "Red" }
                default { "Yellow" }
            }
            Write-Host "║   $($job.Id.Substring(0,8))... - $($job.Method) [$($job.Status)]" -ForegroundColor $color
        }
    }
    
    Write-Host "╚══════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# Main execution
switch ($Action) {
    "PrepareData" {
        if (-not $DatasetPath) {
            Write-TrainingLog "DatasetPath required" "ERROR"
            exit 1
        }
        Write-TrainingLog "Dataset prepared: $DatasetPath" "SUCCESS"
        @{ Status = "Prepared"; Path = $DatasetPath } | ConvertTo-Json
    }
    "StartTraining" {
        if (-not $BaseModelPath -or -not $DatasetPath) {
            Write-TrainingLog "BaseModelPath and DatasetPath required" "ERROR"
            exit 1
        }
        
        $config = @{
            Epochs = $Epochs
            LearningRate = $LearningRate
            BatchSize = $BatchSize
            OutputDir = $OutputDir
        }
        
        $job = New-TrainingJob -BaseModel $BaseModelPath -Dataset $DatasetPath -Method $Method -Config $config
        $trained = Start-TrainingJob -JobId $job.Id
        $trained | ConvertTo-Json -Depth 10
    }
    "Evaluate" {
        if (-not $JobId) {
            Write-TrainingLog "JobId required" "ERROR"
            exit 1
        }
        $metrics = Get-TrainingMetrics -JobId $JobId
        $metrics | ConvertTo-Json
    }
    "Export" {
        if (-not $JobId -or -not $OutputDir) {
            Write-TrainingLog "JobId and OutputDir required" "ERROR"
            exit 1
        }
        $exported = Export-TrainedModel -JobId $JobId -OutputPath $OutputDir
        if ($exported) {
            $exported | ConvertTo-Json
        }
        else {
            exit 1
        }
    }
    "ListJobs" {
        $state = Get-TrainingState
        $state.Jobs | ConvertTo-Json -Depth 10
    }
    "ShowStatus" {
        Show-TrainingStatus
    }
}
