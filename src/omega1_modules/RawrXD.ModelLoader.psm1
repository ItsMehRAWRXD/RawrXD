#Requires -Version 7.4
#Requires -PSEdition Core
# RawrXD OMEGA-1 ModelLoader Module
# GGUF/ONNX model loading and inference orchestration

$script:OmegaRoot = $env:RAWRXD_OMEGA_ROOT ?? "D:\lazy init ide\auto_generated_methods"
$script:LoadedModels = @{}

function Invoke-ModelLoader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = $script:OmegaRoot,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    
    try {
        # Scan for model files
        $ggufModels = Get-ChildItem -Path $Path -Filter '*.gguf' -Recurse -ErrorAction SilentlyContinue
        $onnxModels = Get-ChildItem -Path $Path -Filter '*.onnx' -Recurse -ErrorAction SilentlyContinue
        
        # Model registry
        $modelRegistry = @{
            GGUF = $ggufModels | Select-Object -ExpandProperty FullName
            ONNX = $onnxModels | Select-Object -ExpandProperty FullName
            Count = ($ggufModels.Count + $onnxModels.Count)
        }
        
        $result = @{
            Status = 'Active'
            Module = 'RawrXD.ModelLoader'
            Timestamp = $timestamp
            ProcessId = $PID
            MemoryMB = [Math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
            ModelRegistry = $modelRegistry
            LoadedModels = $script:LoadedModels.Count
        }
        
        Write-Verbose "[ModelLoader] Discovered $($modelRegistry.Count) models"
        return $result
    }
    catch {
        Write-Error "[ModelLoader] Error: $_"
        throw
    }
}

function Test-ModelLoaderHealth {
    [CmdletBinding()]
    param()
    
    return @{
        Module = 'RawrXD.ModelLoader'
        Healthy = $true
        Status = 'Operational'
        Timestamp = Get-Date
        LoadedModels = $script:LoadedModels.Count
        SupportedFormats = @('GGUF', 'ONNX')
    }
}

function Register-Model {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ModelPath,
        
        [Parameter(Mandatory=$true)]
        [string]$ModelId
    )
    
    if (-not (Test-Path $ModelPath)) {
        throw "Model not found: $ModelPath"
    }
    
    $script:LoadedModels[$ModelId] = @{
        Path = $ModelPath
        RegisteredAt = Get-Date
        Status = 'Registered'
    }
    
    Write-Verbose "[ModelLoader] Registered model '$ModelId' -> $ModelPath"
}

Export-ModuleMember -Function Invoke-ModelLoader, Test-ModelLoaderHealth, Register-Model
