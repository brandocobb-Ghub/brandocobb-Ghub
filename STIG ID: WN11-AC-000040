<#
.SYNOPSIS
    This PowerShell script enables the built-in Microsoft password
    complexity filter in accordance with DISA STIG WN11-AC-000040.

.NOTES
    Author          : Brandon Cobb
    GitHub          : https://github.com/brandocobb-Ghub/
    Date Created    : 6-28-2026
    Last Modified   : 6-28-2026
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AC-000040
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-AC-000040/

.USAGE
    Run this script with administrative privileges.

    Example syntax:
    PS C:\> .\WN11-AC-000040.ps1

.DESCRIPTION
    DISA STIG WN11-AC-000040 requires the built-in Microsoft
    password complexity filter to be enabled.

    Required Value:
        PasswordComplexity = 1
#>

# Temporary working files
$ExportFile = "$env:TEMP\SecurityPolicy.cfg"
$Database   = "$env:SystemRoot\Security\Database\Local.sdb"

try {

    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "STIG Remediation: WN11-AC-000040" -ForegroundColor Cyan
    Write-Host "Enable Password Complexity" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "[INFO] Exporting current Local Security Policy..." -ForegroundColor Yellow

    secedit /export /cfg $ExportFile | Out-Null

    if (!(Test-Path $ExportFile)) {
        throw "Failed to export Local Security Policy."
    }

    Write-Host "[INFO] Updating PasswordComplexity setting..." -ForegroundColor Yellow

    $Content = Get-Content $ExportFile

    if ($Content -match "^PasswordComplexity") {

        $Content = $Content -replace "^PasswordComplexity\s*=\s*\d","PasswordComplexity = 1"

    }
    else {

        $Content += ""
        $Content += "[System Access]"
        $Content += "PasswordComplexity = 1"

    }

    $Content | Set-Content $ExportFile

    Write-Host "[INFO] Importing updated security policy..." -ForegroundColor Yellow

    secedit /configure `
        /db $Database `
        /cfg $ExportFile `
        /areas SECURITYPOLICY | Out-Null

    Write-Host "[SUCCESS] Password complexity has been enabled." -ForegroundColor Green

    # Verification

    secedit /export /cfg $ExportFile | Out-Null

    $VerifyLine = Select-String `
        -Path $ExportFile `
        -Pattern "^PasswordComplexity"

    $CurrentValue = ($VerifyLine.Line -replace '[^\d]', '')

    Write-Host ""
    Write-Host "Verification Results" -ForegroundColor Cyan
    Write-Host "---------------------------------------------------"
    Write-Host "Required Value : 1"
    Write-Host "Current Value  : $CurrentValue"

    if ($CurrentValue -eq "1") {

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

    Write-Error "An error occurred while remediating STIG WN11-AC-000040."
    Write-Error $_.Exception.Message
    exit 1

}
