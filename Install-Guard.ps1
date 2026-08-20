<#
.SYNOPSIS
  Install the self-healing guard that re-applies the RDP-host patch after a
  Windows Update replaces termsrv.dll.

.DESCRIPTION
  Copies termsrv_autopatch.py + termsrv_guard.ps1 into InstallDir, creates the
  event-log source, seeds state with the CURRENT termsrv.dll hash (so the first
  run reads "healthy" if you have already run Enable-RdpHost.ps1), and registers
  a Scheduled Task 'OpenRdpGuard' running as SYSTEM:
    * at system startup (catches an update that replaced termsrv.dll + rebooted)
    * every 6 hours (safety net)
    * on WindowsUpdateClient servicing success (EventID 19) - responsive re-patch

  Run elevated. Idempotent.
#>
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:ProgramData 'openrdp'))
$ErrorActionPreference='Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TASK = 'OpenRdpGuard'

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach($f in @('termsrv_autopatch.py','termsrv_guard.ps1')){
  Copy-Item (Join-Path $scriptDir $f) (Join-Path $InstallDir $f) -Force
}
$GUARD = Join-Path $InstallDir 'termsrv_guard.ps1'

if(-not [System.Diagnostics.EventLog]::SourceExists('OpenRdp')){
  New-EventLog -LogName Application -Source 'OpenRdp'
  Write-Output "created event source OpenRdp"
}

$STATE = Join-Path $InstallDir 'guard.state.json'
$cur = (Get-FileHash "$env:WINDIR\System32\termsrv.dll" -Algorithm SHA256).Hash
if(-not (Test-Path $STATE)){
  [pscustomobject]@{ last_patched=$cur; tries=[pscustomobject]@{} } | ConvertTo-Json -Depth 5 | Set-Content $STATE -Encoding ASCII
  Write-Output "seeded state last_patched=$($cur.Substring(0,16))..."
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$GUARD`" -InstallDir `"$InstallDir`""
$tBoot  = New-ScheduledTaskTrigger -AtStartup
$tHourly= New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 6)
$class  = Get-CimClass MSFT_TaskEventTrigger Root/Microsoft/Windows/TaskScheduler
$tEvt   = New-CimInstance -CimClass $class -ClientOnly
$tEvt.Enabled = $true
$tEvt.Subscription = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name=''Microsoft-Windows-WindowsUpdateClient''] and (EventID=19)]]</Select></Query></QueryList>'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

if(Get-ScheduledTask -TaskName $TASK -ErrorAction SilentlyContinue){ Unregister-ScheduledTask -TaskName $TASK -Confirm:$false }
Register-ScheduledTask -TaskName $TASK -Action $action -Trigger @($tBoot,$tHourly,$tEvt) -Principal $principal -Settings $settings `
  -Description 'Re-applies the termsrv.dll RDP-host patch after Windows Update; autopatcher refuses on ambiguity.' | Out-Null
Write-Output "registered scheduled task '$TASK' (boot + 6h + WU-servicing), running as SYSTEM"
Write-Output "guard log: $InstallDir\guard.log"
