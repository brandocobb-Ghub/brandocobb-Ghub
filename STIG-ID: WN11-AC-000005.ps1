<#
.SYNOPSIS
    This PowerShell script enables Failure auditing for
    Credential Validation in accordance with
    DISA STIG WN11-AU-000005.

.NOTES
    Author          : Brandon Cobb
    GitHub          : https://github.com/brandocobb-Ghub/
    Date Created    : 06-28-2026
    Last Modified   : 06-28-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000005
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AU-000005/

.USAGE
    Run this script with administrative privileges.

    Example syntax:

    PS C:\> .\WN11-AU-000005.ps1

.DESCRIPTION
    DISA STIG WN11-AU-000005 requires Windows to audit
    Account Logon Credential Validation failures.

    Required Setting:

        Audit Credential Validation
            Failure = Enabled
#>

# STIG Requirements
$SubCategory = "Credential Validation"

try {

    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "STIG Remediation: WN11-AU-000005" -ForegroundColor Cyan
    Write-Host "Audit Credential Validation - Failure" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""

    #
    # Enable Failure Auditing
    #

    Write-Host "[INFO] Enabling Failure Auditing..." -ForegroundColor Yellow

    auditpol.exe /set `
        /subcategory:"$SubCategory" `
        /failure:enable | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "AuditPol failed to configure Credential Validation auditing."
    }

    Write-Host "[SUCCESS] Failure auditing enabled." -ForegroundColor Green

    #
    # Verification
    #

    Write-Host ""
    Write-Host "Verification Results" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------"

    $AuditResult = auditpol.exe /get `
        /subcategory:"$SubCategory"

    $AuditResult

    if ($AuditResult -match "Failure\s+Enabled") {

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

    Write-Error "An error occurred while remediating STIG WN11-AU-000005."
    Write-Error $_.Exception.Message
    exit 1

}
