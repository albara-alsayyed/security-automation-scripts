<#
.SYNOPSIS
  PowerView-assisted Active Directory enumeration and auditing checklist.

.DESCRIPTION
  Uses PowerView functions when they are already available in the current
  PowerShell session. Falls back to the ActiveDirectory module where possible.
  Produces defensive audit output for domain visibility, privileged groups,
  risky user flags, computer inventory, SPN exposure, GPO inventory, and shares.

  This script does not perform exploitation, password attacks, relay attacks,
  coercion, persistence, or credential collection.

.EXAMPLE
  . .\PowerView.ps1
  powershell -ExecutionPolicy Bypass -File .\powershell\powerview_ad_audit.ps1 -OutputDirectory .\ad-audit

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\powershell\powerview_ad_audit.ps1 -UseNativeAD -OutputDirectory .\ad-audit

.NOTES
  Safe lab disclaimer: Run only in domains where you have explicit permission
  to perform Active Directory auditing.
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = ".\ad-audit",
    [switch]$UseNativeAD,
    [switch]$IncludeShares
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function New-ReportDirectory {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Export-AuditCsv {
    param(
        [Parameter(Mandatory)] [object[]]$Data,
        [Parameter(Mandatory)] [string]$Name
    )
    $path = Join-Path $OutputDirectory $Name
    if ($Data -and $Data.Count -gt 0) {
        $Data | Export-Csv -Path $path -NoTypeInformation
        Write-Host "[+] Wrote $path" -ForegroundColor Green
    }
    else {
        Write-Host "[i] No data for $Name" -ForegroundColor DarkGray
    }
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-ADDataSource {
    $hasPowerView = (Test-CommandAvailable "Get-Domain") -and (Test-CommandAvailable "Get-DomainUser")
    $hasNativeAD = [bool](Get-Module -ListAvailable -Name ActiveDirectory)

    if ($hasPowerView -and -not $UseNativeAD) {
        return "PowerView"
    }
    if ($hasNativeAD) {
        Import-Module ActiveDirectory
        return "ActiveDirectory"
    }
    throw "Neither PowerView functions nor the ActiveDirectory module are available."
}

function Get-AuditData {
    param([string]$Source)

    if ($Source -eq "PowerView") {
        $domain = Get-Domain | Select-Object Name, Forest, DomainControllers, DomainMode
        $users = Get-DomainUser -Properties samaccountname, useraccountcontrol, lastlogontimestamp, pwdlastset, serviceprincipalname, admincount |
            Select-Object samaccountname, useraccountcontrol, lastlogontimestamp, pwdlastset, serviceprincipalname, admincount
        $computers = Get-DomainComputer -Properties dnshostname, operatingsystem, lastlogontimestamp |
            Select-Object dnshostname, operatingsystem, lastlogontimestamp
        $groups = Get-DomainGroup -Properties samaccountname, admincount |
            Where-Object { $_.admincount -eq 1 -or $_.samaccountname -match "admin|operator|backup|domain" } |
            Select-Object samaccountname, admincount
        $gpos = Get-DomainGPO | Select-Object displayname, gpcfilesyspath, whenchanged
        $spnUsers = $users | Where-Object { $_.serviceprincipalname }

        $shares = @()
        if ($IncludeShares -and (Test-CommandAvailable "Find-DomainShare")) {
            $shares = Find-DomainShare -CheckShareAccess | Select-Object ComputerName, Name
        }
    }
    else {
        $domain = Get-ADDomain | Select-Object DNSRoot, Forest, DomainMode, PDCEmulator
        $users = Get-ADUser -Filter * -Properties SamAccountName, Enabled, LastLogonDate, PasswordLastSet, ServicePrincipalName, AdminCount, PasswordNeverExpires |
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, ServicePrincipalName, AdminCount, PasswordNeverExpires
        $computers = Get-ADComputer -Filter * -Properties DNSHostName, OperatingSystem, LastLogonDate |
            Select-Object DNSHostName, OperatingSystem, LastLogonDate
        $groups = Get-ADGroup -Filter * -Properties AdminCount |
            Where-Object { $_.AdminCount -eq 1 -or $_.Name -match "admin|operator|backup|domain" } |
            Select-Object Name, SamAccountName, AdminCount
        $gpos = Get-GPO -All -ErrorAction SilentlyContinue | Select-Object DisplayName, Path, ModificationTime
        $spnUsers = $users | Where-Object { $_.ServicePrincipalName }
        $shares = @()
    }

    return @{
        Domain = @($domain)
        Users = @($users)
        Computers = @($computers)
        PrivilegedGroups = @($groups)
        GPOs = @($gpos)
        SPNUsers = @($spnUsers)
        Shares = @($shares)
    }
}

function Write-Summary {
    param([hashtable]$Data, [string]$Source)

    $summaryPath = Join-Path $OutputDirectory "summary.md"
    $lines = @(
        "# Active Directory Audit Summary",
        "",
        "- Data source: ``$Source``",
        "- Users reviewed: ``$($Data.Users.Count)``",
        "- Computers reviewed: ``$($Data.Computers.Count)``",
        "- Privileged groups reviewed: ``$($Data.PrivilegedGroups.Count)``",
        "- SPN-bearing users: ``$($Data.SPNUsers.Count)``",
        "- GPOs reviewed: ``$($Data.GPOs.Count)``",
        "",
        "## Defensive Review Questions",
        "",
        "- Are privileged group memberships expected and approved?",
        "- Are SPN-bearing accounts managed service accounts where possible?",
        "- Are stale users and computers disabled or reviewed?",
        "- Are risky user flags documented and justified?",
        "- Are GPO changes reviewed through change control?",
        "",
        "## Safety",
        "",
        "This report is for authorized defensive auditing only."
    )
    $lines | Set-Content -Path $summaryPath
    Write-Host "[+] Wrote $summaryPath" -ForegroundColor Green
}

New-ReportDirectory -Path $OutputDirectory

try {
    $source = Get-ADDataSource
    Write-Host "[+] Data source: $source" -ForegroundColor Cyan
    $data = Get-AuditData -Source $source

    Export-AuditCsv -Data $data.Domain -Name "domain.csv"
    Export-AuditCsv -Data $data.Users -Name "users.csv"
    Export-AuditCsv -Data $data.Computers -Name "computers.csv"
    Export-AuditCsv -Data $data.PrivilegedGroups -Name "privileged-groups.csv"
    Export-AuditCsv -Data $data.SPNUsers -Name "spn-users.csv"
    Export-AuditCsv -Data $data.GPOs -Name "gpos.csv"
    if ($IncludeShares) {
        Export-AuditCsv -Data $data.Shares -Name "shares.csv"
    }
    Write-Summary -Data $data -Source $source
}
catch {
    Write-Host "[!] Audit failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
