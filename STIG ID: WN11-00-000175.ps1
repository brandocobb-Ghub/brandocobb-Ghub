.SYNOPSIS
    This PowerShell script disables the Secondary Logon service to comply with DISA STIG WN11-00-000175.

.NOTES
    Author          : Brandon Cobb
    GitHub          : https://github.com/brandocobb-Ghub/
    Date Created    : 6-23-2026
    Last Modified   : 6-23-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-00-000175
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-00-000175/



.USAGE
    Run this script with administrative privileges.

    Example syntax:
    PS C:\> .\WN11-00-000175.ps1

.DESCRIPTION
    DISA STIG WN11-00-000175 requires the Secondary Logon
    service (seclogon) to be disabled.

    Vulnerability Discussion:
    The Secondary Logon service allows users to start processes
    using alternate credentials. This can expose privileged
    credentials to theft when used within standard user sessions.

    Compliance Requirements:
    Service Name : seclogon
    Startup Type : Disabled
    Status       : Stopped
#>

# Define STIG Requirements
$ServiceName = "seclogon"

try {
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "STIG Remediation: WN11-00-000175" -ForegroundColor Cyan
    Write-Host "Secondary Logon Service" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""

    # Verify service exists
    $Service = Get-Service -Name $ServiceName -ErrorAction Stop

    Write-Host "[INFO] Found service: $($Service.DisplayName)" -ForegroundColor Green

    # Stop service if running
    if ($Service.Status -eq "Running") {
        Write-Host "[INFO] Service is currently running. Stopping service..." -ForegroundColor Yellow

        Stop-Service `
            -Name $ServiceName `
            -Force `
            -ErrorAction Stop

        Write-Host "[SUCCESS] Service stopped." -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] Service is already stopped." -ForegroundColor Green
    }

    # Disable startup type
    Write-Host "[INFO] Setting Startup Type to Disabled..." -ForegroundColor Yellow

    Set-Service `
        -Name $ServiceName `
        -StartupType Disabled `
        -ErrorAction Stop

    Write-Host "[SUCCESS] Startup Type set to Disabled." -ForegroundColor Green

    # Verification
    $ServiceConfig = Get-CimInstance Win32_Service `
        -Filter "Name='seclogon'"

    Write-Host ""
    Write-Host "Verification Results" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------"
    Write-Host "Service Name : $($ServiceConfig.Name)"
    Write-Host "Display Name : $($ServiceConfig.DisplayName)"
    Write-Host "State        : $($ServiceConfig.State)"
    Write-Host "Start Mode   : $($ServiceConfig.StartMode)"

    if (($ServiceConfig.State -eq "Stopped") -and ($ServiceConfig.StartMode -eq "Disabled")) {

        Write-Host ""
        Write-Host "STATUS: COMPLIANT" -ForegroundColor Green
        exit 0
    }
    else {

        Write-Host ""
        Write-Host "STATUS: NON-COMPLIANT" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Error "An error occurred while remediating STIG WN11-00-000175."
    Write-Error $_.Exception.Message
    exit 1
}
