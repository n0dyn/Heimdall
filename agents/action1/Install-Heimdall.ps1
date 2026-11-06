# Heimdall installer for an Action1 PowerShell script.
# Action1 runs this as Local System on Windows.
#
# Prefer the hub button "Install Heimdall agent". That sends the script once
# and does not save the API key in the Script Library.
#
# For a manual paste, define Action1 parameters ApiUrl, ApiKey, and Hostname.
# Action1 exposes them as $ApiUrl, $ApiKey, and $Hostname.

$ErrorActionPreference = 'Stop'
if (-not $ApiUrl -or -not $ApiKey) {
    throw 'ApiUrl and ApiKey are required'
}
$response = Invoke-WebRequest -UseBasicParsing -Uri ($ApiUrl.TrimEnd('/') + '/install/windows')
$installer = [string]$response.Content
if ($Hostname) {
    & ([scriptblock]::Create($installer)) -ApiUrl $ApiUrl -ApiKey $ApiKey -Hostname $Hostname
} else {
    & ([scriptblock]::Create($installer)) -ApiUrl $ApiUrl -ApiKey $ApiKey
}
if (-not $?) { exit 1 }
