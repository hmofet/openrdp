<#
.SYNOPSIS
  Install the self-healing guard that re-applies the RDP-host patch after a
  Windows Update replaces termsrv.dll.

.DESCRIPTION
  Copies openrdp_autopatch.py + openrdp_guard.ps1 into InstallDir, creates the
  event-log source, seeds state with the CURRENT termsrv.dll hash (so the first
  run reads "healthy" if you have already run Enable-OpenRdp.ps1), and registers
  a Scheduled Task 'OpenRdpGuard' running as SYSTEM:
    * at system startup (catches an update that replaced termsrv.dll + rebooted)
    * every 6 hours (safety net)
    * on WindowsUpdateClient servicing success (EventID 19) - responsive re-patch

  -Patches must match what Enable-OpenRdp.ps1 applied ('host', 'multi' or
  'host,multi'); the guard re-applies exactly that set after an update.

  The guard runs as SYSTEM, which cannot find a per-user Python install, so
  the python.exe found here (or passed with -Python) is recorded in the state
  file for the guard to use.

  Run elevated. Idempotent.
#>
[CmdletBinding()]
param([string]$InstallDir = (Join-Path $env:ProgramData 'openrdp'),
      [string]$Patches = 'host',
      [string]$Python)
$ErrorActionPreference='Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TASK = 'OpenRdpGuard'

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach($f in @('openrdp_autopatch.py','openrdp_guard.ps1')){
  Copy-Item (Join-Path $scriptDir $f) (Join-Path $InstallDir $f) -Force
}
$GUARD = Join-Path $InstallDir 'openrdp_guard.ps1'

if(-not [System.Diagnostics.EventLog]::SourceExists('OpenRdp')){
  New-EventLog -LogName Application -Source 'OpenRdp'
  Write-Output "created event source OpenRdp"
}

if(-not $Python){
  $Python = (Get-Command python -ErrorAction SilentlyContinue).Source
  if(-not $Python){
    $f = Get-ChildItem "$env:ProgramFiles\Python*\python.exe","$env:LOCALAPPDATA\Programs\Python\Python*\python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if($f){ $Python = $f.FullName }
  }
}
if(-not $Python -or -not (Test-Path $Python)){ throw "python.exe not found; pass -Python" }
$Python = (Resolve-Path $Python).Path
& $Python -c "import pefile" 2>$null
if($LASTEXITCODE -ne 0){ throw "$Python cannot import pefile; run Enable-OpenRdp.ps1 first or pip install pefile" }
Write-Output "guard will use $Python"

$STATE = Join-Path $InstallDir 'guard.state.json'
$cur = (Get-FileHash "$env:WINDIR\System32\termsrv.dll" -Algorithm SHA256).Hash
if(-not (Test-Path $STATE)){
  [pscustomobject]@{ last_patched=$cur; patches=$Patches; python=$Python; tries=[pscustomobject]@{} } | ConvertTo-Json -Depth 5 | Set-Content $STATE -Encoding ASCII
  Write-Output "seeded state last_patched=$($cur.Substring(0,16))... patches=$Patches"
} else {
  $s = Get-Content $STATE -Raw | ConvertFrom-Json
  $s | Add-Member -NotePropertyName patches -NotePropertyValue $Patches -Force
  $s | Add-Member -NotePropertyName python -NotePropertyValue $Python -Force
  $s | ConvertTo-Json -Depth 5 | Set-Content $STATE -Encoding ASCII
  Write-Output "state kept; patches=$Patches"
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
