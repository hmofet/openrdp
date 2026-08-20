<#
  termsrv_guard.ps1 - keep the RDP-host patch alive across Windows Updates.

  Runs unattended (Scheduled Task; see Install-Guard.ps1). Each run:
    HEALTHY : System32\termsrv.dll hash == the hash we last patched to.
              Verify 3389 is LISTENING; if not, restart TermService once and
              re-check. Alert if it still will not bind. Never re-patches.
    DRIFT   : the DLL changed (a cumulative update shipped a new termsrv.dll, or
              the patch was reverted). Back up the new file, run the symbol-free
              autopatcher against it, and if it succeeds deploy + verify 3389.
    REFUSE  : the autopatcher cannot safely locate the sites on this build. DO
              NOT touch System32. Alert (Application event log + log file), with
              bounded retries so it never loops. RDP stays off; the box is fine.

  Design rule: a mis-patch of a system DLL is worse than an unbound port. The
  autopatcher verifies every site before writing and refuses on ambiguity; the
  guard refuses to loop and always leaves a pristine backup.
#>
param([string]$InstallDir = (Join-Path $env:ProgramData 'openrdp'))

$ErrorActionPreference = 'Stop'
$TARGET = "$env:WINDIR\System32\termsrv.dll"
$AUTO   = Join-Path $InstallDir 'termsrv_autopatch.py'
$LOG    = Join-Path $InstallDir 'guard.log'
$STATE  = Join-Path $InstallDir 'guard.state.json'
$EVSRC  = 'OpenRdp'
$MAXTRY = 3

function Find-Python {
  $c = (Get-Command python -ErrorAction SilentlyContinue).Source
  if ($c) { return $c }
  foreach ($p in @("$env:ProgramFiles\Python*\python.exe","$env:ProgramFiles\Python*-arm64\python.exe",
                   "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe")) {
    $f = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($f) { return $f.FullName }
  }
  return $null
}
function Log($lvl,$msg){
  $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $lvl, $msg
  Add-Content -Path $LOG -Value $line; Write-Output $line
  if($lvl -in @('WARN','ERROR','ALERT')){
    try{ Write-EventLog -LogName Application -Source $EVSRC -EntryType ($(if($lvl -eq 'WARN'){'Warning'}else{'Error'})) -EventId 5150 -Message $msg }catch{}
  }
}
function Hash($p){ if(Test-Path $p){(Get-FileHash $p -Algorithm SHA256).Hash}else{$null} }
function LoadState(){ if(Test-Path $STATE){ Get-Content $STATE -Raw | ConvertFrom-Json }else{ [pscustomobject]@{last_patched=$null; tries=[pscustomobject]@{}} } }
function SaveState($s){ $s | ConvertTo-Json -Depth 5 | Set-Content -Path $STATE -Encoding ASCII }
function Listening(){ [bool](Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue) }
function EnsurePolicy(){
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -ErrorAction SilentlyContinue
  foreach($p in @('TCP','UDP')){
    $n="OpenRDP-$p"
    if(-not (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)){
      New-NetFirewallRule -DisplayName $n -Direction Inbound -Action Allow -Protocol $p -LocalPort 3389 -Profile Any | Out-Null
    }
  }
}
function SwapDll($src){
  Stop-Service UmRdpService -Force -ErrorAction SilentlyContinue
  Stop-Service TermService  -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
  takeown /F $TARGET /A | Out-Null
  icacls  $TARGET /grant "Administrators:F" | Out-Null
  try{ Copy-Item $src $TARGET -Force; return 'ok' }
  catch{
    Copy-Item $src "$TARGET.new" -Force
    $sig='[DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]public static extern bool MoveFileEx(string a,string b,int f);'
    $k=Add-Type -MemberDefinition $sig -Name MFE -Namespace GuardWin -PassThru
    if(-not $k::MoveFileEx("$TARGET.new",$TARGET,5)){ throw "MoveFileEx failed" }
    return 'pending-reboot'
  }
}

try{
  $py = Find-Python
  if(-not $py){ Log 'ERROR' 'python not found'; exit 1 }
  $state = LoadState
  $cur = Hash $TARGET
  Log 'INFO' "run: termsrv.dll=$($cur.Substring(0,16))... last_patched=$($state.last_patched)"

  if($cur -and $state.last_patched -and $cur -eq $state.last_patched){
    if(Listening){ Log 'INFO' 'healthy: patched DLL live, 3389 LISTENING'; exit 0 }
    Log 'WARN' 'patched DLL live but 3389 not listening; restarting TermService once'
    EnsurePolicy; Set-Service TermService -StartupType Automatic; Start-Service TermService -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4
    if(Listening){ Log 'INFO' 'recovered after restart' } else { Log 'ALERT' '3389 still not binding after restart - manual look needed' }
    exit 0
  }

  Log 'WARN' 'drift detected: termsrv.dll changed (Windows Update likely replaced it)'
  $tries=@{}; if($state.tries){ $state.tries.PSObject.Properties | ForEach-Object { $tries[$_.Name]=$_.Value } }
  $n=[int]($tries[$cur]); $n++; $tries[$cur]=$n; $state.tries=[pscustomobject]$tries
  if($n -gt $MAXTRY){ Log 'ALERT' "tried this build $($n-1)x already; giving up to avoid a loop"; SaveState $state; exit 0 }

  $bak = Join-Path $InstallDir ("termsrv.dll.{0}.bak" -f $cur.Substring(0,8))
  if(-not (Test-Path $bak)){ Copy-Item $TARGET $bak -Force; Log 'INFO' "backed up -> $bak" }

  $incoming = Join-Path $InstallDir 'termsrv_incoming.dll'; Copy-Item $TARGET $incoming -Force
  $cand = Join-Path $InstallDir 'termsrv_patched.dll'; if(Test-Path $cand){ Remove-Item $cand -Force }
  $out = & $py $AUTO patch $incoming $cand 2>&1; $rc = $LASTEXITCODE
  $out | ForEach-Object { Log 'INFO' "autopatch: $_" }
  if($rc -ne 0 -or -not (Test-Path $cand)){
    Log 'ALERT' "autopatcher REFUSED (rc=$rc) on this build - NOT modifying System32. Investigate offsets."
    SaveState $state; exit 0
  }
  $candHash = Hash $cand
  if($candHash -eq $cur){ Log 'ERROR' 'autopatch output identical to input - aborting'; SaveState $state; exit 1 }

  EnsurePolicy
  $res = SwapDll $cand
  if($res -eq 'pending-reboot'){
    Log 'WARN' "patched DLL staged via pending-rename; REBOOT REQUIRED to apply"
    $state.last_patched = $candHash; SaveState $state; exit 0
  }
  Set-Service TermService -StartupType Automatic; Start-Service TermService -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 4
  $state.last_patched = $candHash; SaveState $state
  if(Listening){ Log 'INFO' "SUCCESS: re-patched new build and 3389 LISTENING" }
  else{ Log 'ALERT' "re-patched but 3389 not binding - autopatch matched but semantics differ; manual review" }
  exit 0
}
catch{ Log 'ERROR' "guard exception: $($_.Exception.Message)"; exit 1 }
