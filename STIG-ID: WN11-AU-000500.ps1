#Requires -RunAsAdministrator
 
<#
.SYNOPSIS
    Remediates DISA STIG WN11-AU-000500.

.NOTES
    Author          : Brandon Cobb
    GitHub          : https://github.com/brandocobb-Ghub/
    Date Created    : 06/21/2026
    Last Modified   : 06/21/2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000500/


.USAGE
    Put any usage instructions here.
    Example syntax:
    PS C:\> .\__remediation_template(STIG-ID-WN10-AU-000500).ps1 
 
.DESCRIPTION
    Configures the Windows Application event log maximum size
    to at least 32768 KB.
#>
 
$ErrorActionPreference = "Stop"
 
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName    = "MaxSize"
$RequiredKB   = 32768
$RequiredBytes = 33554432
 
try {
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "STIG Remediation: WN11-AU-000500" -ForegroundColor Cyan
    Write-Host "Application Event Log Maximum Size" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host
 
    if (-not (Test-Path -LiteralPath $RegistryPath)) {
        Write-Host "[INFO] Creating registry path..." -ForegroundColor Yellow
 
        New-Item `
            -Path $RegistryPath `
            -Force |
            Out-Null
    }
 
    $CurrentValue = Get-ItemPropertyValue `
        -LiteralPath $RegistryPath `
        -Name $ValueName `
        -ErrorAction SilentlyContinue
 
    if (($null -eq $CurrentValue) -or ($CurrentValue -lt $RequiredKB)) {
        Write-Host "[FINDING] System is noncompliant." -ForegroundColor Yellow
        Write-Host "[FIX] Setting MaxSize to $RequiredKB KB..." -ForegroundColor Green
 
        New-ItemProperty `
            -LiteralPath $RegistryPath `
            -Name $ValueName `
            -PropertyType DWord `
            -Value $RequiredKB `
            -Force |
            Out-Null
    }
    else {
        Write-Host "[SUCCESS] Policy value is already compliant." `
            -ForegroundColor Green
    }
 
    Write-Host "[INFO] Refreshing computer policy..." -ForegroundColor Cyan
 
    & "$env:SystemRoot\System32\gpupdate.exe" /target:computer /force |
        Out-Null
 
    # Set the effective event log size as well.
& "$env:SystemRoot\System32\wevtutil.exe" `
        set-log Application `
        "/ms:$RequiredBytes"
 
    if ($LASTEXITCODE -ne 0) {
        throw "wevtutil failed with exit code $LASTEXITCODE."
    }
 
    Start-Sleep -Seconds 2
 
    $VerifiedPolicyValue = Get-ItemPropertyValue `
        -LiteralPath $RegistryPath `
        -Name $ValueName `
        -ErrorAction Stop
 
    $EffectiveSizeBytes = (
        Get-WinEvent -ListLog Application -ErrorAction Stop
    ).MaximumSizeInBytes
 
    Write-Host
    Write-Host "Verification Results" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------"
    Write-Host "Policy value       : $VerifiedPolicyValue KB"
    Write-Host "Effective log size : $EffectiveSizeBytes bytes"
    Write-Host "Required size      : $RequiredKB KB"
    Write-Host
 
    if (
        ($VerifiedPolicyValue -ge $RequiredKB) -and
        ($EffectiveSizeBytes -ge $RequiredBytes)
    ) {
        Write-Host "STATUS: COMPLIANT" -ForegroundColor Green
        exit 0
    }
 
    Write-Host "STATUS: NON-COMPLIANT" -ForegroundColor Red
    exit 1
}
catch {
    Write-Host
    Write-Host "STATUS: REMEDIATION FAILED" -ForegroundColor Red
    Write-Error $_.Exception.Message
    exit 1
}
