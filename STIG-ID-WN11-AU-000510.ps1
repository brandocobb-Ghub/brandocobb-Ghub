<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : Brandon Cobb
    LinkedIn        : https://www.linkedin.com/in/brandon-cobbprofile/
    GitHub          : https://github.com/brandocobb-Ghub/brandocobb-Ghub
    Date Created    : 06-08-2026
    Last Modified   : 06-08-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000510
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run the script from an elevated PowerShell prompt (Run as Administrator).
    Example syntax:
    PS C:\> .\WN11-AU-000500.ps1
#>

# 1. Define Variables
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$Name = "MaxSize"
$DesiredValue = 32768

# 2. Ensure Registry Key Path Exists
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

# 3. Create or Update Registry Value Safely
if ($null -eq (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
    # Value doesn't exist, create it with explicit property type to avoid PS 5.1 bugs
    New-ItemProperty -Path $Path -Name $Name -Value $DesiredValue -PropertyType DWord -Force | Out-Null
} else {
    # Value exists, update it
    Set-ItemProperty -Path $Path -Name $Name -Value $DesiredValue
}

# 4. Verify Success
$CurrentValue = (Get-ItemProperty -Path $Path -Name $Name).$Name

if ($CurrentValue -eq $DesiredValue) {
    Write-Host "PASS: WN11-AU-000500 remediated successfully." -ForegroundColor Green
} else {
    Write-Error "FAIL: Remediation unsuccessful."
}
