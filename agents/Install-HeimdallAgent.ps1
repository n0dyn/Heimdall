# Heimdall Windows agent installer.
# Run from an elevated PowerShell.
#
# From the hub (the URL is filled in for you):
#   powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((Invoke-RestMethod http://HUB:8010/install/windows))) -ApiKey YOUR_KEY"
#
# From a downloaded copy:
#   powershell -ExecutionPolicy Bypass -File .\Install-HeimdallAgent.ps1 -ApiUrl http://HUB:8010 -ApiKey YOUR_KEY
#
# Re-running upgrades the agent and keeps working. -Uninstall removes the task.
# The agent is agent_windows.ps1, started by Windows PowerShell. That host is
# already on the machine and is allowed by Application Control. The unsigned
# HeimdallAgent.exe is not used.

param(
    [string]$ApiUrl = "__HEIMDALL_HUB_URL__",
    [string]$ApiKey = "",
    [string]$Hostname = "",
    [int]$Interval = 60,
    [string]$InstallPath = "$env:ProgramData\Heimdall",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
# Action1 runs this as a script block with no console. Progress bars make
# Invoke-WebRequest fail or stall in that session.
$ProgressPreference = "SilentlyContinue"
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}
# Split so the hub can replace the param default without rewriting these checks.
$Placeholder = '__HEIMDALL_HUB' + '_URL__'
$InsecureKey = "default-insecure-key-change-me"
$ServiceName = "HeimdallAgent"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Import-HeimdallEnvFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or -not $line.Contains("=")) { return }
        $key, $value = $line.Split("=", 2)
        $key = $key.Trim()
        $value = $value.Trim()
        switch ($key) {
            "SIEM_API_URL" {
                if (-not $script:ApiUrl -or $script:ApiUrl -eq $script:Placeholder) { $script:ApiUrl = $value }
            }
            "SIEM_API_KEY" {
                if (-not $script:ApiKey) { $script:ApiKey = $value }
            }
            "SIEM_HOSTNAME" {
                if (-not $script:Hostname) { $script:Hostname = $value }
            }
        }
    }
}

function Remove-HeimdallService {
    # Do not execute HeimdallAgent.exe. Application Control blocks that unsigned file.
    # A missing service or task prints "file not found" on stderr. With
    # ErrorAction Stop, PowerShell turns that into a failed install.
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing -and $existing.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    $pref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        cmd.exe /c "sc delete $ServiceName >nul 2>&1 & schtasks /End /TN $ServiceName >nul 2>&1 & schtasks /Delete /TN $ServiceName /F >nul 2>&1" | Out-Null
    } finally {
        $ErrorActionPreference = $pref
    }
}

function Write-AgentEnv {
    param([string]$ReportHost)
    $logDir = Join-Path $InstallPath "logs"
    $lines = @(
        "SIEM_API_URL=$ApiUrl",
        "SIEM_API_KEY=$ApiKey",
        "SIEM_INTERVAL=$Interval",
        "SIEM_AGENT_INTERVAL=$Interval",
        "SIEM_ROLE=windows",
        "SIEM_HOSTNAME=$ReportHost",
        "SIEM_STATE_DIR=$logDir",
        "HEIMDALL_LOG_DIR=$logDir",
        "HEIMDALL_HOME=$InstallPath"
    )
    $envFile = Join-Path $InstallPath "agent.env"
    Set-Content -Path $envFile -Value ($lines -join "`n") -Encoding ASCII
    return $envFile
}

function Invoke-HubCheckIn {
    param([string]$ReportHost)
    $health = Invoke-WebRequest -Uri "$ApiUrl/health" -UseBasicParsing -TimeoutSec 15
    if ($health.StatusCode -ne 200) {
        throw "Hub health check returned HTTP $($health.StatusCode)."
    }
    $headers = @{
        "api-key" = $ApiKey
        "source-host" = $ReportHost
        "os-type" = "WINDOWS"
    }
    $heartbeat = Invoke-WebRequest -Method POST -Uri "$ApiUrl/heartbeat" -Headers $headers -UseBasicParsing -TimeoutSec 15
    if ($heartbeat.StatusCode -ne 200) {
        throw "Hub rejected the check-in with HTTP $($heartbeat.StatusCode)."
    }
}

function Save-HubFile {
    param([string]$Name, [string]$Dest, [long]$MinimumBytes)
    $uri = "$ApiUrl/install/files/$Name"
    Write-Host "Downloading $Name"
    $response = $null
    $out = $null
    try {
        # HttpWebRequest, not Invoke-WebRequest. Action1 runs in session 0,
        # where the PowerShell progress bar fails the download.
        $request = [System.Net.HttpWebRequest]::Create($uri)
        $request.Method = "GET"
        $request.UserAgent = "HeimdallInstaller"
        $request.Timeout = 180000
        $request.ReadWriteTimeout = 180000
        $response = $request.GetResponse()
        $status = [int]$response.StatusCode
        if ($status -ne 200) { throw "Could not download $Name from $uri (HTTP $status)." }
        $out = [System.IO.File]::Create($Dest)
        $response.GetResponseStream().CopyTo($out)
    } catch {
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        if ($out) { $out.Close(); $out = $null }
        if ($response) { $response.Close(); $response = $null }
        if (Test-Path $Dest) { Remove-Item $Dest -Force -ErrorAction SilentlyContinue }
        if ($status) { throw "Could not download $Name from $uri (HTTP $status)." }
        throw "Could not download $Name from ${uri}: $($_.Exception.Message)"
    } finally {
        if ($out) { $out.Close() }
        if ($response) { $response.Close() }
    }
    if (-not (Test-Path $Dest) -or (Get-Item $Dest).Length -lt $MinimumBytes) {
        if (Test-Path $Dest) { Remove-Item $Dest -Force -ErrorAction SilentlyContinue }
        throw "Downloaded $Name is too small to be the agent."
    }
}

function Install-PowerShellAgent {
    param([string]$ReportHost)
    $dest = Join-Path $InstallPath "agent_windows.ps1"
    # Stop a running agent before replacing its script. Windows locks the file.
    Remove-HeimdallService
    $local = $null
    if ($PSScriptRoot) {
        $candidate = Join-Path $PSScriptRoot "agent_windows.ps1"
        if (Test-Path $candidate) { $local = $candidate }
    }
    if ($local) {
        Copy-Item $local $dest -Force
        if ((Get-Item $dest).Length -lt 100) {
            throw "agent_windows.ps1 next to the installer is empty."
        }
    } else {
        # Windows PowerShell 5.1 is already on the machine. This agent uses it.
        Save-HubFile -Name "agent_windows.ps1" -Dest $dest -MinimumBytes 100
    }

    Write-Host "Registering the PowerShell agent as $ReportHost"
    # Load agent.env in the task so SIEM_HOSTNAME and the hub URL reach the script.
    $runner = Join-Path $InstallPath "run-agent.cmd"
    @(
        "@echo off",
        "cd /d `"$InstallPath`"",
        ":loop",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$dest`"",
        "ping -n 11 127.0.0.1 >nul",
        "goto loop"
    ) | Set-Content -Path $runner -Encoding ASCII

    # schtasks fails to start a task whose command contains nested quotes.
    & schtasks.exe /Create /F /TN $ServiceName /SC ONSTART /RU SYSTEM /RL HIGHEST /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $dest" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Windows did not register the PowerShell agent task."
    }
    & schtasks.exe /Run /TN $ServiceName | Out-Null
}

if (-not (Test-Administrator)) {
    Write-Host "Run this installer from an elevated PowerShell window." -ForegroundColor Red
    exit 1
}

if ($Uninstall) {
    Remove-HeimdallService
    Write-Host "Removed $ServiceName."
    Write-Host "Left $InstallPath\agent.env in place."
    exit 0
}

if (-not $ApiKey -and $env:SIEM_API_KEY) { $ApiKey = $env:SIEM_API_KEY }
if (-not $Hostname -and $env:SIEM_HOSTNAME) { $Hostname = $env:SIEM_HOSTNAME }
if ((-not $ApiUrl -or $ApiUrl -eq $Placeholder) -and $env:SIEM_API_URL) {
    $ApiUrl = $env:SIEM_API_URL
}

$savedEnv = Join-Path $InstallPath "agent.env"
Import-HeimdallEnvFile $savedEnv
if ($PSScriptRoot) {
    Import-HeimdallEnvFile (Join-Path $PSScriptRoot "agent.env")
}

if (-not $ApiUrl -or $ApiUrl -eq $Placeholder) {
    Write-Host "Pass -ApiUrl http://HUB:8010" -ForegroundColor Red
    exit 1
}
$ApiUrl = $ApiUrl.TrimEnd("/")
if (-not $ApiKey -or $ApiKey -eq $InsecureKey) {
    Write-Host "Pass -ApiKey. The default key is refused." -ForegroundColor Red
    exit 1
}

$computer = $env:COMPUTERNAME
if (-not $Hostname) { $Hostname = $computer }

New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $InstallPath "logs") | Out-Null
Write-AgentEnv -ReportHost $Hostname | Out-Null

Write-Host "Installing Heimdall (windows) -> $ApiUrl"
Install-PowerShellAgent -ReportHost $Hostname

try {
    Invoke-HubCheckIn -ReportHost $Hostname
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "The agent is installed. Logs: $InstallPath\logs"
    exit 1
}

Write-Host "Heimdall is running as $Hostname (WINDOWS)."
Write-Host "Logs:    $InstallPath\logs"
Write-Host "Config:  $InstallPath\agent.env"
Write-Host "Remove:  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Uninstall"
