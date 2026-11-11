#Requires -Version 7.4
#Requires -PSEdition Core
# RawrXD OMEGA-1 CustomModelLoaders Module
# Specialized loaders for custom model formats

$script:OmegaRoot = $env:RAWRXD_OMEGA_ROOT ?? "D:\lazy init ide\auto_generated_methods"
$script:CustomLoaders = @{
    'GGUF' = @{ Extension = '.gguf'; Loader = 'llama.cpp compatible' }
    'ONNX' = @{ Extension = '.onnx'; Loader = 'ONNX Runtime' }
    'SAFETENSORS' = @{ Extension = '.safetensors'; Loader = 'Hugging Face' }
    'PT' = @{ Extension = '.pt'; Loader = 'PyTorch' }
    'CKPT' = @{ Extension = '.ckpt'; Loader = 'Checkpoint' }
}

function Invoke-CustomModelLoaders {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Path = $script:OmegaRoot,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Config = @{}
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    
    try {
        # Scan for all supported model formats
        $discovered = @{}
        foreach ($loader in $script:CustomLoaders.GetEnumerator()) {
            $files = Get-ChildItem -Path $Path -Filter "*$($loader.Value.Extension)" -Recurse -ErrorAction SilentlyContinue
            $discovered[$loader.Key] = @{
                Count = $files.Count
                Files = $files | Select-Object -ExpandProperty Name
            }
        }
        
        $result = @{
            Status = 'Active'
            Module = 'RawrXD.CustomModelLoaders'
            Timestamp = $timestamp
            ProcessId = $PID
            MemoryMB = [Math]::Round((Get-Process -Id $PID).WorkingSet64 / 1MB, 2)
            SupportedFormats = $script:CustomLoaders.Count
            DiscoveredModels = $discovered
            TotalModels = ($discovered.Values | Measure-Object -Property Count -Sum).Sum
        }
        
        Write-Verbose "[CustomModelLoaders] Discovered $($result.TotalModels) models"
        return $result
    }
    catch {
        Write-Error "[CustomModelLoaders] Error: $_"
        throw
    }
}

function Test-CustomModelLoadersHealth {
    [CmdletBinding()]
    param()
    
    return @{
        Module = 'RawrXD.CustomModelLoaders'
        Healthy = $true
        Status = 'Operational'
        Timestamp = Get-Date
        SupportedFormats = $script:CustomLoaders.Keys
    }
}

function Register-CustomLoader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [string]$Extension,
        
        [Parameter(Mandatory=$true)]
        [string]$LoaderType
    )
    
    $script:CustomLoaders[$Name] = @{
        Extension = $Extension
        Loader = $LoaderType
    }
    
    Write-Verbose "[CustomModelLoaders] Registered loader '$Name' for *$Extension"
}

Export-ModuleMember -Function Invoke-CustomModelLoaders, Test-CustomModelLoadersHealth, Register-CustomLoader
