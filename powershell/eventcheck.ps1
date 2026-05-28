<#
.SYNOPSIS
  Defensive Windows event checker.

.DESCRIPTION
  Reviews common Security and System event IDs used during basic blue-team triage.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\powershell\windows_event_checker.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\powershell\windows_event_checker.ps1 -Hours 12

.NOTES
  Safe lab disclaimer: Run only on Windows systems you own or administer with permission.
#>

param(
    [int]$Hours = 24,
    [int]$MaxEvents = 20
)

$startTime = (Get-Date).AddHours(-$Hours)

$eventGroups = @(
    @{ LogName = "Security"; Id = 4625; Name = "Failed logon" },
    @{ LogName = "Security"; Id = 4624; Name = "Successful logon" },
    @{ LogName = "Security"; Id = 4720; Name = "User account created" },
    @{ LogName = "Security"; Id = 4726; Name = "User account deleted" },
    @{ LogName = "Security"; Id = 4732; Name = "User added to local group" },
    @{ LogName = "System";   Id = 7045; Name = "Service installed" }
)

Write-Host "Windows Event Checker" -ForegroundColor Cyan
Write-Host "Review window: last $Hours hour(s)"
Write-Host ""

foreach ($group in $eventGroups) {
    Write-Host "==== $($group.Name) [$($group.LogName):$($group.Id)] ====" -ForegroundColor Yellow

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $group.LogName
            Id = $group.Id
            StartTime = $startTime
        } -MaxEvents $MaxEvents -ErrorAction Stop

        if (-not $events) {
            Write-Host "No events found."
            continue
        }

        $events | Select-Object TimeCreated, ProviderName, Id, Message |
            Format-Table -Wrap -AutoSize
    }
    catch {
        Write-Host "Could not read events: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
}
