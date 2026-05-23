<#
.SYNOPSIS
  Active Directory user hygiene audit for authorized environments.

.DESCRIPTION
  Uses the ActiveDirectory PowerShell module to report enabled users, locked users,
  stale logons, and password age indicators. This script does not collect passwords.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\powershell\ad_user_audit.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\powershell\ad_user_audit.ps1 -InactiveDays 60

.NOTES
  Safe lab disclaimer: Run only in domains where you have permission to audit users.
#>

param(
    [int]$InactiveDays = 90,
    [int]$StalePasswordDays = 180,
    [string]$OutputCsv = ""
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "ActiveDirectory module not found. Install RSAT tools or run on a domain admin workstation." -ForegroundColor Red
    exit 1
}

Import-Module ActiveDirectory

$cutoff = (Get-Date).AddDays(-$InactiveDays)

Write-Host "Active Directory User Audit" -ForegroundColor Cyan
Write-Host "Inactive threshold: $InactiveDays day(s)"
Write-Host ""

$users = Get-ADUser -Filter * -Properties Enabled, LockedOut, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AdminCount, ServicePrincipalName, DoesNotRequirePreAuth |
    Select-Object SamAccountName, Enabled, LockedOut, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AdminCount, ServicePrincipalName, DoesNotRequirePreAuth,
        @{Name="RiskNotes";Expression={
            $notes = @()
            if ($_.LockedOut) { $notes += "Locked account" }
            if ($_.PasswordNeverExpires) { $notes += "Password never expires" }
            if ($_.AdminCount -eq 1) { $notes += "AdminCount=1 privileged history" }
            if ($_.ServicePrincipalName) { $notes += "SPN-bearing account" }
            if ($_.DoesNotRequirePreAuth) { $notes += "Kerberos pre-auth disabled" }
            if (-not $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff) { $notes += "Inactive account" }
            if ($_.PasswordLastSet -and $_.PasswordLastSet -lt (Get-Date).AddDays(-$StalePasswordDays)) { $notes += "Stale password" }
            $notes -join "; "
        }}

$summary = [PSCustomObject]@{
    TotalUsers = $users.Count
    EnabledUsers = ($users | Where-Object { $_.Enabled }).Count
    LockedUsers = ($users | Where-Object { $_.LockedOut }).Count
    InactiveUsers = ($users | Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff }).Count
    PasswordNeverExpires = ($users | Where-Object { $_.PasswordNeverExpires }).Count
    SPNUsers = ($users | Where-Object { $_.ServicePrincipalName }).Count
    PreAuthDisabled = ($users | Where-Object { $_.DoesNotRequirePreAuth }).Count
    PrivilegedHistory = ($users | Where-Object { $_.AdminCount -eq 1 }).Count
}

Write-Host "==== Summary ====" -ForegroundColor Yellow
$summary | Format-List

Write-Host "==== Locked Users ====" -ForegroundColor Yellow
$users | Where-Object { $_.LockedOut } |
    Select-Object SamAccountName, LastLogonDate, PasswordLastSet |
    Format-Table -AutoSize

Write-Host "==== Inactive Users ====" -ForegroundColor Yellow
$users | Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff } |
    Select-Object SamAccountName, Enabled, LastLogonDate |
    Sort-Object LastLogonDate |
    Format-Table -AutoSize

Write-Host "==== Password Never Expires ====" -ForegroundColor Yellow
$users | Where-Object { $_.PasswordNeverExpires } |
    Select-Object SamAccountName, Enabled, LastLogonDate |
    Format-Table -AutoSize

Write-Host "==== High-Value Review Queue ====" -ForegroundColor Yellow
$users | Where-Object { $_.RiskNotes } |
    Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, RiskNotes |
    Sort-Object SamAccountName |
    Format-Table -Wrap -AutoSize

if ($OutputCsv) {
    $users | Export-Csv -Path $OutputCsv -NoTypeInformation
    Write-Host "Wrote CSV report to $OutputCsv" -ForegroundColor Green
}
