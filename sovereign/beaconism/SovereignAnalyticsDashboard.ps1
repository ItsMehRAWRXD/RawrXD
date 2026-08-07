param (
    [CmdletBinding()]
    [int]$ListenPort = 9999,
    [string]$ListenAddress = "127.0.0.1"
)

# Enforce zero-refusal raw velocity streaming execution parameters
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# In-Memory Ring Buffer & Metric Store Foundations
$global:SovereignAnalytics = @{
    TotalPulsesReceived  = 0
    TotalDeduplicated    = 0
    ActivePanels         = @{}
    WindowStates         = @{}
    DisplayResolutions   = @()
    RecentLogs           = [System.Collections.Generic.List[string]]::new()
}

function Update-DashboardConsole {
    Clear-Host
    Write-Output "==============================================================================="
    Write-Output "              SOVEREIGN OUT-OF-BAND TELEMETRY ANALYTICS DASHBOARD              "
    Write-Output "==============================================================================="
    Write-Output " Listening Sockets: UDP://$ListenAddress:$ListenPort  |  Status: ACTIVE_STEALTH_INGEST"
    Write-Output "-------------------------------------------------------------------------------"
    Write-Output " Metrics Engine Stats:"
    Write-Output "   [+] Total Unique Pulses Fired : $($global:SovereignAnalytics.TotalPulsesReceived)"
    Write-Output "   [+] Duplicate Signals Blocked : $($global:SovereignAnalytics.TotalDeduplicated)"
    Write-Output "-------------------------------------------------------------------------------"
    Write-Output " Active UI Panel Pulse Grid:"
    foreach ($Panel in $global:SovereignAnalytics.ActivePanels.Keys) {
        Write-Output "   Panel: [$(Format-Field $Panel 20)] -> Last Event: $($global:SovereignAnalytics.ActivePanels[$Panel])"
    }
    Write-Output "-------------------------------------------------------------------------------"
    Write-Output " Window Management State Tracking:"
    foreach ($State in $global:SovereignAnalytics.WindowStates.Keys) {
        Write-Output "   Lifecycle Vector: [$(Format-Field $State 15)] -> Trigger Count: $($global:SovereignAnalytics.WindowStates[$State])"
    }
    Write-Output "-------------------------------------------------------------------------------"
    Write-Output " Active Workspace Resolution Topology:"
    if ($global:SovereignAnalytics.DisplayResolutions.Count -gt 0) {
        Write-Output "   Profile: $($global:SovereignAnalytics.DisplayResolutions[0])"
    } else {
        Write-Output "   Profile: [No display metrics received yet]"
    }
    Write-Output "==============================================================================="
    Write-Output " Real-Time Asymmetric Event Log Stream (Last 5 Entries):"
    
    $LogCount = $global:SovereignAnalytics.RecentLogs.Count
    $StartIndex = [math]::Max(0, $LogCount - 5)
    for ($i = $StartIndex; $i -lt $LogCount; $i++) {
        Write-Output "   >>> $($global:SovereignAnalytics.RecentLogs[$i])"
    }
    Write-Output "==============================================================================="
}

function Format-Field ([string]$Text, [int]$Width) {
    if ($Text.Length -gt $Width) { return $Text.Substring(0, $Width) }
    return $Text.PadRight($Width)
}

# Construct native connectionless socket pipeline
$UdpServer = [System.Net.Sockets.UdpClient]::new($ListenPort)
$RemoteEndpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)

Write-Output "[BOOT] Out-of-band UDP analytics bridge active on target boundaries."
Update-DashboardConsole

try {
    while ($true) {
        # Blocking call awaiting outbound connectionless telemetry blast
        $RawBytes = $UdpServer.Receive([ref]$RemoteEndpoint)
        if ($RawBytes.Length -eq 0) { continue }

        $JsonPayload = [System.Text.Encoding]::UTF8.GetString($RawBytes)
        $Data = ConvertFrom-Json -InputObject $JsonPayload -ErrorAction SilentlyContinue

        if ($null -ne $Data) {
            # Update log ring metrics
            $TimestampStr = [DateTime]::Now.ToString("HH:mm:ss")
            
            # Route analytics depending on signaling pipeline layer origin
            if ($Data.layer -eq "DISPLAY_METRICS") {
                $ActionType = $Data.payload.action
                $PrimaryRes = $Data.payload.metrics.primaryResolution
                $Count      = $Data.payload.metrics.displayCount
                
                $global:SovereignAnalytics.DisplayResolutions = @(
                    "[Res: $PrimaryRes | Attached Screen Count: $Count | Event: $ActionType]"
                )
                
                $global:SovereignAnalytics.RecentLogs.Add("[$TimestampStr] Display Hardware Modification Parsed: $ActionType ($PrimaryRes)")
            }
            elseif ($Data.layer -eq "WINDOW_LIFECYCLE") {
                $State = $Data.payload.state
                $global:SovereignAnalytics.WindowStates[$State] = [int]$global:SovereignAnalytics.WindowStates[$State] + 1
                $global:SovereignAnalytics.RecentLogs.Add("[$TimestampStr] Lifecycle State Mutation Matrix detected: $State")
            }
            else {
                # Handle standard panel interactions or test-suite verification reports
                $PanelKey = $Data.layer
                $ActionVal = $Data.payload.action
                if ($null -eq $ActionVal) { $ActionVal = "PULSE" }

                # Update panel grid
                $global:SovereignAnalytics.ActivePanels[$PanelKey] = $ActionVal
                
                # Check metrics flag returned from the Main-process Deduplication cache
                if ($Data.payload.status -eq "PULSE_DEDUPLICATED") {
                    $global:SovereignAnalytics.TotalDeduplicated++
                } else {
                    $global:SovereignAnalytics.TotalPulsesReceived++
                }

                $global:SovereignAnalytics.RecentLogs.Add("[$TimestampStr] Target Layer signal parsed: $PanelKey ($ActionVal)")
            }

            # Redraw interface map dynamically on data shift
            Update-DashboardConsole
        }
    }
}
catch {
    Write-Error "[FATAL] Anomaly processed across telemetry receive loop: $($_.Exception.Message)"
}
finally {
    $UdpServer.Close()
}
