#Requires -Version 5.1
<#
.SYNOPSIS
  Heimdall Windows agent with no Python dependency.

.DESCRIPTION
  Collects Security event log entries and a light laptop snapshot (CPU, RAM,
  disk, current Wi-Fi, battery, signed-in user), then POSTs them to the same
  /ingest, /system-status, and /heartbeat APIs as the Python agent. Intended
  for client machines that cannot (or should not) install Python.

  Run as SYSTEM or a local Administrator (Security log requires it).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File agent_windows.ps1
#>

param(
    [string]$ApiUrl = $env:SIEM_API_URL,
    [string]$ApiKey = $env:SIEM_API_KEY,
    [int]$Interval = 0,
    [switch]$Once
)

$ErrorActionPreference = "Continue"
# The task runs in session 0. The progress bar makes Invoke-WebRequest fail there.
$ProgressPreference = "SilentlyContinue"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

function Import-AgentEnv {
    $candidates = @()
    if ($env:HEIMDALL_HOME) { $candidates += (Join-Path $env:HEIMDALL_HOME "agent.env") }
    if ($env:ProgramData) { $candidates += (Join-Path $env:ProgramData "Heimdall\agent.env") }
    if ($PSScriptRoot) { $candidates += (Join-Path $PSScriptRoot "agent.env") }
    foreach ($path in $candidates) {
        if (-not (Test-Path $path)) { continue }
        Get-Content -Path $path | ForEach-Object {
            $line = $_.Trim()
            if (-not $line -or $line.StartsWith("#")) { return }
            $eq = $line.IndexOf("=")
            if ($eq -lt 1) { return }
            $name = $line.Substring(0, $eq).Trim()
            $value = $line.Substring($eq + 1).Trim()
            Set-Item -Path ("Env:" + $name) -Value $value
        }
        break
    }
}
Import-AgentEnv
# Parameters are bound before agent.env exists in the process. The file wins
# unless the caller passed the value on the command line.
if (-not $PSBoundParameters.ContainsKey("ApiUrl") -and $env:SIEM_API_URL) { $ApiUrl = $env:SIEM_API_URL }
if (-not $PSBoundParameters.ContainsKey("ApiKey") -and $env:SIEM_API_KEY) { $ApiKey = $env:SIEM_API_KEY }
if ($ApiUrl) { $ApiUrl = $ApiUrl.Trim() }
if ($ApiKey) { $ApiKey = $ApiKey.Trim() }
if (-not $ApiUrl) { $ApiUrl = "http://localhost:8010" }
if (-not $ApiKey) { $ApiKey = "default-insecure-key-change-me" }
if ($Interval -le 0) {
    $rawInterval = $env:SIEM_INTERVAL
    if (-not $rawInterval) { $rawInterval = $env:SIEM_AGENT_INTERVAL }
    if ($rawInterval) { $Interval = [int]$rawInterval } else { $Interval = 30 }
}

$InstallPath = if ($env:HEIMDALL_HOME) { $env:HEIMDALL_HOME } else { "C:\Heimdall" }
if ($env:SIEM_STATE_DIR) {
    $LogDir = $env:SIEM_STATE_DIR
} elseif ($env:HEIMDALL_LOG_DIR) {
    $LogDir = $env:HEIMDALL_LOG_DIR
} else {
    $LogDir = Join-Path $InstallPath "logs"
}
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$StateFile = Join-Path $LogDir "win_agent_ps_state.json"
$LogFile = Join-Path $LogDir "heimdall-agent-ps.log"
$SourceHost = if ($env:SIEM_HOSTNAME) { $env:SIEM_HOSTNAME.Trim() } else { "$env:COMPUTERNAME".Trim() }

$EventMap = @{
    4625 = @{ type = "LOGIN_FAIL";      severity = 3 }
    4624 = @{ type = "LOGIN_SUCCESS";   severity = 1 }
    4688 = @{ type = "PROCESS_EXEC";    severity = 1 }
    4720 = @{ type = "ACCOUNT_CREATE";  severity = 4 }
    4726 = @{ type = "ACCOUNT_DELETE";  severity = 3 }
    4728 = @{ type = "GROUP_ADD";       severity = 3 }
    4732 = @{ type = "GROUP_ADD";       severity = 3 }
    4756 = @{ type = "GROUP_ADD";       severity = 3 }
    7045 = @{ type = "SERVICE_INSTALL"; severity = 3 }
    1102 = @{ type = "LOG_TAMPERING";   severity = 5 }
}

function Write-AgentLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString("o"), $Message
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    Write-Host $line
}

function Get-State {
    if (Test-Path $StateFile) {
        try { return Get-Content $StateFile -Raw | ConvertFrom-Json } catch { }
    }
    return [pscustomobject]@{ lastRecordId = 0 }
}

function Save-State {
    param($State)
    ($State | ConvertTo-Json) | Set-Content -Path $StateFile -Encoding UTF8
}

function ConvertTo-ApiJson {
    param($Value)
    # ConvertTo-Json turns a one-item list into an object. A laptop with one
    # disk would then be rejected by the API, so lists are written explicitly.
    function Escape-JsonString([string]$Text) {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('"')
        foreach ($ch in $Text.ToCharArray()) {
            $code = [int]$ch
            # break inside switch would leave the foreach and truncate the string.
            switch ($code) {
                34 { [void]$sb.Append('\"') }
                92 { [void]$sb.Append('\\') }
                8  { [void]$sb.Append('\b') }
                9  { [void]$sb.Append('\t') }
                10 { [void]$sb.Append('\n') }
                12 { [void]$sb.Append('\f') }
                13 { [void]$sb.Append('\r') }
                default {
                    if ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
                    else { [void]$sb.Append($ch) }
                }
            }
        }
        [void]$sb.Append('"')
        return $sb.ToString()
    }
    function Emit-Json($Item, [int]$Depth) {
        if ($Depth -gt 8) { return "null" }
        if ($null -eq $Item) { return "null" }
        if ($Item -is [string]) { return Escape-JsonString $Item }
        if ($Item -is [bool]) { if ($Item) { return "true" } else { return "false" } }
        if ($Item -is [datetime]) { return Escape-JsonString ($Item.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) }
        # Process ids arrive as uint32 and memory sizes as int64. Both must stay JSON numbers.
        if ($Item -is [ValueType] -and $Item -isnot [char]) {
            return $Item.ToString([System.Globalization.CultureInfo]::InvariantCulture)
        }
        if ($Item -is [System.Collections.IDictionary]) {
            $parts = @()
            foreach ($key in @($Item.Keys)) {
                $parts += ((Escape-JsonString ([string]$key)) + ":" + (Emit-Json $Item[$key] ($Depth + 1)))
            }
            return "{" + ($parts -join ",") + "}"
        }
        if ($Item -is [System.Collections.IEnumerable]) {
            $parts = @()
            foreach ($child in $Item) { $parts += (Emit-Json $child ($Depth + 1)) }
            return "[" + ($parts -join ",") + "]"
        }
        return Escape-JsonString ([string]$Item)
    }
    return Emit-Json $Value 0
}

function Invoke-Heimdall {
    param(
        [string]$Method = "POST",
        [string]$Path,
        [hashtable]$Headers = @{},
        [object]$Body = $null
    )
    $hdr = @{ "api-key" = $ApiKey }
    foreach ($k in $Headers.Keys) { $hdr[$k] = $Headers[$k] }
    $uri = "{0}{1}" -f $ApiUrl.TrimEnd("/"), $Path
    $params = @{
        Uri             = $uri
        Method          = $Method
        Headers         = $hdr
        TimeoutSec      = 15
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $params.ContentType = "application/json"
        $params.Body = (ConvertTo-ApiJson $Body)
    }
    return Invoke-WebRequest @params
}

function Get-IsoNow {
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}

function Collect-SecurityEvents {
    param([int]$LastRecordId)
    $ids = @($EventMap.Keys)
    $events = @()
    $highWater = $LastRecordId
    try {
        $filter = @{ LogName = "Security"; Id = $ids }
        $raw = Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction SilentlyContinue
        if (-not $raw) { return @{ events = @(); highWater = $LastRecordId } }
        foreach ($ev in ($raw | Sort-Object RecordId)) {
            if ($ev.RecordId -le $LastRecordId) { continue }
            $meta = $EventMap[[int]$ev.Id]
            if (-not $meta) { continue }
            $xml = [xml]$ev.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) {
                $data[$node.Name] = [string]$node."#text"
            }
            $user = $data["TargetUserName"]
            if (-not $user) { $user = $data["SubjectUserName"] }
            if (-not $user) { $user = "system" }
            $ip = $data["IpAddress"]
            if (-not $ip -or $ip -eq "-" -or $ip -eq "::1") { $ip = "N/A" }
            $events += @{
                event_id     = [guid]::NewGuid().ToString()
                timestamp    = $ev.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                source_host  = $SourceHost
                os_type      = "WINDOWS"
                event_type   = $meta.type
                severity     = [int]$meta.severity
                source_ip    = $ip
                user         = $user
                raw_message  = $ev.Message
            }
            if ($ev.RecordId -gt $highWater) { $highWater = [int64]$ev.RecordId }
        }
    } catch {
        Write-AgentLog ("event collect error: " + $_)
    }
    return @{ events = $events; highWater = $highWater }
}

function Convert-BootTime {
    param($Value)
    # Get-CimInstance already returns a DateTime. The DMTF converter rejects that
    # and used to abort the snapshot before it was posted.
    if ($Value -is [datetime]) {
        return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
    if ($Value) {
        try {
            return ([Management.ManagementDateTimeConverter]::ToDateTime([string]$Value)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        } catch { }
    }
    return Get-IsoNow
}

function Test-UsefulHardwareName {
    param([string]$Value)
    if (-not $Value) { return $false }
    $text = $Value.Trim().ToLower()
    if (-not $text) { return $false }
    $placeholders = @(
        "system manufacturer", "to be filled by o.e.m.", "default string",
        "not specified", "chassis manufacturer", "oem", "o.e.m.", "invalid"
    )
    return -not ($placeholders -contains $text)
}

function Get-ChassisLabel {
    param($Code)
    # Win32_ComputerSystem PCSystemType / PCSystemTypeEx
    switch ([int]$Code) {
        3 { return "desktop" }
        4 { return "desktop" }
        5 { return "desktop" }
        6 { return "desktop" }
        7 { return "desktop" }
        13 { return "desktop" }
        15 { return "desktop" }
        23 { return "desktop" }
        24 { return "desktop" }
        8 { return "laptop" }
        9 { return "laptop" }
        10 { return "laptop" }
        11 { return "laptop" }
        14 { return "laptop" }
        30 { return "laptop" }
        31 { return "laptop" }
        32 { return "laptop" }
        default { return "" }
    }
}

function Convert-NetshWifi {
    param([string[]]$Lines)
    # Current association only. The caller must not pass a nearby-SSID scan.
    $rows = @()
    $current = $null
    foreach ($line in $Lines) {
        if (-not $line) { continue }
        if ($line -match '^\s*Name\s*:\s*(.+)$') {
            if ($current) { $rows += $current }
            $current = @{ kind = "wifi"; interface = $Matches[1].Trim(); state = "unknown" }
            continue
        }
        if (-not $current) { continue }
        if ($line -notmatch '^\s*([^:]+?)\s*:\s*(.*)$') { continue }
        $key = $Matches[1].Trim()
        $val = $Matches[2].Trim()
        # break inside this switch would stop the interface parse at the first field.
        switch ($key) {
            "State" { $current.state = $val.ToLower() }
            "SSID" { if ($val) { $current.ssid = $val } }
            "BSSID" { if ($val) { $current.bssid = $val } }
            "Radio type" { if ($val) { $current.radio = $val } }
            "Authentication" { if ($val) { $current.auth = $val } }
            "Cipher" { if ($val) { $current.cipher = $val } }
            "Channel" { if ($val) { $current.channel = $val } }
            "Band" { if ($val) { $current.band = $val } }
            "Description" { if ($val) { $current.description = $val } }
            "Receive rate (Mbps)" { if ($val) { $current.rx_mbps = $val } }
            "Transmit rate (Mbps)" { if ($val) { $current.tx_mbps = $val } }
            "Signal" {
                if ($val -match '(\d+)') { $current.signal = [int]$Matches[1] }
            }
        }
    }
    if ($current) {
        if (-not $current.ContainsKey("band") -and $current.ContainsKey("channel") -and $current.channel -match '^\d+$') {
            $channelNo = [int]$current.channel
            if ($channelNo -ge 1 -and $channelNo -le 14) { $current.band = "2.4 GHz" }
            elseif ($channelNo -ge 32 -and $channelNo -le 177) { $current.band = "5 GHz" }
        }
        $rows += $current
    }
    if ($rows.Count -eq 0) {
        $text = ($Lines -join "`n").ToLower()
        if ($text -match "wlansvc\) is not running|no wireless interface") {
            $rows += @{ kind = "wifi"; state = "unavailable" }
        }
    }
    return ,$rows
}

function Collect-Wifi {
    # "wlan show interfaces" reads the current connection. It does not scan nearby networks.
    $raw = @()
    try {
        $raw = @(& netsh.exe wlan show interfaces 2>$null)
    } catch {
        return ,$raw
    }
    return Convert-NetshWifi $raw
}

function Collect-Endpoint {
    $info = @{ kind = "endpoint"; reboot_pending = $false }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 3 -ErrorAction SilentlyContinue
        if ($cs) {
            if ($cs.UserName) { $info.user = [string]$cs.UserName }
            if (Test-UsefulHardwareName $cs.Manufacturer) { $info.manufacturer = ([string]$cs.Manufacturer).Trim() }
            if (Test-UsefulHardwareName $cs.Model) { $info.model = ([string]$cs.Model).Trim() }
            $typeCode = $cs.PCSystemTypeEx
            if (-not $typeCode) { $typeCode = $cs.PCSystemType }
            $chassis = Get-ChassisLabel $typeCode
            if ($chassis) { $info.chassis = $chassis }
            if ($cs.PartOfDomain -and $cs.Domain) { $info.domain = [string]$cs.Domain }
        }
    } catch { }

    try {
        $bat = Get-CimInstance Win32_Battery -OperationTimeoutSec 3 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($bat -and $null -ne $bat.EstimatedChargeRemaining) {
            $pct = [int]$bat.EstimatedChargeRemaining
            if ($pct -lt 0) { $pct = 0 }
            if ($pct -gt 100) { $pct = 100 }
            $info.battery_percent = $pct
            $power = switch ([int]$bat.BatteryStatus) {
                1 { "on battery" }
                2 { "plugged in" }
                3 { "full" }
                4 { "low" }
                5 { "critical" }
                6 { "charging" }
                7 { "charging" }
                8 { "charging" }
                9 { "charging" }
                11 { "on battery" }
                default { "unknown" }
            }
            $info.power = $power
            if ($info.chassis -eq "desktop" -or -not $info.ContainsKey("chassis")) { $info.chassis = "laptop" }
        }
    } catch { }

    try {
        $vols = @(Get-CimInstance -Namespace "root/cimv2/Security/MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -OperationTimeoutSec 3 -ErrorAction SilentlyContinue)
        $vol = $vols | Where-Object { $_.DriveLetter -eq "C:" } | Select-Object -First 1
        if ($vol) {
            $info.bitlocker = switch ([int]$vol.ProtectionStatus) {
                1 { "on" }
                0 { "off" }
                default { "unknown" }
            }
        }
    } catch { }

    try {
        $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -OperationTimeoutSec 3 -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($av -and $av.displayName) {
            $info.antivirus = [string]$av.displayName
            if ($null -ne $av.productState) {
                $hex = ("{0:x}" -f [uint32]$av.productState).PadLeft(6, "0")
                $realtime = $hex.Substring($hex.Length - 4, 2)
                $info.antivirus_realtime = ($realtime -eq "10" -or $realtime -eq "11")
            }
        }
    } catch { }

    try {
        $info.secure_boot = [bool](Confirm-SecureBootUEFI)
    } catch { }

    # PendingFileRenameOperations is set by ordinary installs, so it is not a reboot signal.
    foreach ($path in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    )) {
        if (Test-Path $path) { $info.reboot_pending = $true }
    }
    return $info
}

function Collect-SystemStatus {
    $processors = @()
    try {
        $processors = @(Get-CimInstance Win32_Processor -OperationTimeoutSec 3 -ErrorAction SilentlyContinue)
    } catch { $processors = @() }
    $cpu = 0
    try {
        if ($processors.Count -gt 0) {
            $avg = ($processors | Measure-Object -Property LoadPercentage -Average).Average
            if ($null -ne $avg) { $cpu = [double]$avg }
        }
    } catch { $cpu = 0 }
    $cpuCount = 0
    foreach ($processor in $processors) {
        try {
            $logical = [int]$processor.NumberOfLogicalProcessors
            if ($logical -gt 0) { $cpuCount += $logical }
        } catch { }
    }
    if ($cpuCount -le 0) { $cpuCount = 1 }

    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 3
    $total = [int64]$os.TotalVisibleMemorySize * 1024
    $free = [int64]$os.FreePhysicalMemory * 1024
    $used = $total - $free
    $memPct = if ($total -gt 0) { [math]::Round(($used / $total) * 100, 2) } else { 0 }

    $disks = @()
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -OperationTimeoutSec 3 | ForEach-Object {
        $size = [int64]$_.Size
        $freeD = [int64]$_.FreeSpace
        if ($size -le 0) { return }
        $disks += @{
            mount   = $_.DeviceID
            total   = $size
            used    = ($size - $freeD)
            free    = $freeD
            percent = [math]::Round((($size - $freeD) / $size) * 100, 2)
        }
    }

    $net = @()
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -OperationTimeoutSec 3 | ForEach-Object {
        if ($_.IPAddress) {
            $net += @{ kind = "nic"; interface = $_.Description; ip = $_.IPAddress[0]; mac = $_.MACAddress }
        }
    }
    foreach ($wifi in @(Collect-Wifi)) {
        if ($wifi -and $wifi.kind -eq "wifi") { $net += $wifi }
    }
    $net += (Collect-Endpoint)

    $procs = @()
    Get-CimInstance Win32_Process -OperationTimeoutSec 3 | Sort-Object -Property WorkingSetSize -Descending |
        Select-Object -First 10 | ForEach-Object {
            $procs += @{
                pid            = $_.ProcessId
                name           = $_.Name
                username       = ""
                cpu_percent    = 0
                memory_percent = if ($total -gt 0) { [math]::Round(($_.WorkingSetSize / $total) * 100, 2) } else { 0 }
            }
        }

    return @{
        source_host    = $SourceHost
        os_type        = "WINDOWS"
        os_details     = [string]$os.Caption
        cpu_usage      = $cpu
        cpu_count      = $cpuCount
        memory_total   = $total
        memory_used    = $used
        memory_percent = $memPct
        disk_info      = $disks
        network_info   = $net
        top_processes  = $procs
        boot_time      = (Convert-BootTime $os.LastBootUpTime)
        timestamp      = Get-IsoNow
    }
}

function Send-Events {
    param($Events)
    if (-not $Events -or $Events.Count -eq 0) {
        Invoke-Heimdall -Path "/heartbeat" -Headers @{ "source-host" = $SourceHost; "os-type" = "WINDOWS" } | Out-Null
        return $true
    }
    $resp = Invoke-Heimdall -Path "/ingest" -Body @{ events = $Events }
    return $resp.StatusCode -eq 200
}

function Send-Status {
    $status = Collect-SystemStatus
    $resp = Invoke-Heimdall -Path "/system-status" -Body @{ status = $status }
    return $resp.StatusCode -eq 200
}

Write-AgentLog ("Heimdall PowerShell agent starting host=" + $SourceHost + " url=" + $ApiUrl)

function Invoke-Cycle {
    $state = Get-State
    $collected = Collect-SecurityEvents -LastRecordId ([int64]$state.lastRecordId)
    $ok = $false
    try { $ok = Send-Events -Events $collected.events } catch { Write-AgentLog ("ingest error: " + $_) }
    if ($ok -and $collected.highWater -gt [int64]$state.lastRecordId) {
        $state.lastRecordId = $collected.highWater
        Save-State $state
    }
    try { Send-Status | Out-Null } catch { Write-AgentLog ("status error: " + $_) }
}

if ($Once) {
    Invoke-Cycle
    exit 0
}

while ($true) {
    try { Invoke-Cycle } catch { Write-AgentLog ("cycle error: " + $_) }
    Start-Sleep -Seconds $Interval
}
