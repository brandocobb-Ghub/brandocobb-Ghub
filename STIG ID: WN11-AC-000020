<#
.SYNOPSIS
    This PowerShell script configures the password history policy
    to remember the previous 24 passwords in accordance with
    DISA STIG WN11-AC-000020.

.NOTES
    Author          : Brandon Cobb
    GitHub          : https://github.com/brandocobb-Ghub/
    Date Created    : 06-27-2026
    Last Modified   : 06-27-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000020
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AC-000020/

.TESTED ON
    Date(s) Tested  :
    Tested By       :
    Systems Tested  :
    PowerShell Ver. :

.USAGE
    Run this script with administrative privileges.

    Example syntax:
    PS C:\> .\WN11-AC-000020.ps1

.DESCRIPTION
    DISA STIG WN11-AC-000020 requires the password history
    policy to remember the previous 24 passwords.

    Required Value:
        Enforce password history = 24 passwords remembered
#>

# Define STIG Requirement
$RequiredHistory = 24

try {

    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "STIG Remediation: WN11-AC-000020" -ForegroundColor Cyan
    Write-Host "Enforce Password History" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[INFO] Configuring password history..." -ForegroundColor Yellow

    net accounts /uniquepw:$RequiredHistory | Out-Null

    Write-Host "[SUCCESS] Password history configured." -ForegroundColor Green

    # Retrieve current configuration
    $NetAccounts = net accounts

    $HistoryLine = $NetAccounts |
        Where-Object { $_ -match "Length of password history maintained" }

    $CurrentValue = ($HistoryLine -replace '[^\d]', '')

    Write-Host ""
    Write-Host "Verification Results" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------"
    Write-Host "Required Value : $RequiredHistory"
    Write-Host "Current Value  : $CurrentValue"

    if ([int]$CurrentValue -ge $RequiredHistory) {

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

    Write-Error "An error occurred while remediating STIG WN11-AC-000020."
    Write-Error $_.Exception.Message
    exit 1

}
