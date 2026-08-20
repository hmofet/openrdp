<#
.SYNOPSIS
  Enable the RDP *host* role on a Windows client SKU by patching termsrv.dll.

.DESCRIPTION
  Windows Home (and single-session Pro) refuse to *host* Remote Desktop. This
  removes that SKU restriction on YOUR OWN machine, the same way RDP Wrapper
  does, but by re-deriving the patch from your actual termsrv.dll each run
  (works on both x64 and ARM64, and survives a build the tool has never seen).

  Steps: locate Python + openrdp_autopatch.py -> back up the live termsrv.dll ->
  produce a patched copy -> stop TermService -> swap it in (pending-rename +
  reboot if locked) -> set fDenyTSConnections=0 -> open the firewall -> start
  TermService -> verify port 3389 is LISTENING.

  Run elevated (Administrator). Idempotent: re-running when already patched is a
  no-op. A pristine backup is always kept so you can roll back.

.PARAMETER InstallDir
  Where the backup, patched DLL and state live. Default: %ProgramData%\openrdp

.PARAMETER Python
  Path to python.exe. Auto-discovered if omitted.

.NOTES
  This modifies a Windows system file. Use only on machines you own/administer.
  A cumulative update that ships a new termsrv.dll reverts the patch - re-run
  this, or install the guard (Install-OpenRdpGuard.ps1) to re-apply automatically.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:ProgramData 'openrdp'),
  [string]$Python
)
$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TARGET = "$env:WINDIR\System32\termsrv.dll"

function Find-Python {
  if ($Python -and (Test-Path $Python)) { return $Python }
  $c = (Get-Command python -ErrorAction SilentlyContinue).Source
  if ($c) { return $c }
  foreach ($p in @("$env:ProgramFiles\Python*\python.exe",
                   "$env:ProgramFiles\Python*-arm64\python.exe",
                   "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe")) {
    $f = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($f) { return $f.FullName }
  }
  throw "python.exe not found. Install Python 3, or pass -Python. (x64 also needs: pip install capstone)"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$py    = Find-Python
$auto  = Join-Path $scriptDir 'openrdp_autopatch.py'
if (-not (Test-Path $auto)) { throw "openrdp_autopatch.py not found next to this script" }

# ensure pefile (and capstone on x64) are importable
& $py -c "import pefile" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "installing pefile..."; & $py -m pip install --quiet pefile }
$isX64 = ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64')
if ($isX64) {
  & $py -c "import capstone" 2>$null
  if ($LASTEXITCODE -ne 0) { Write-Host "installing capstone (x64)..."; & $py -m pip install --quiet capstone }
}

$curHash = (Get-FileHash $TARGET -Algorithm SHA256).Hash
Write-Host "current termsrv.dll: $($curHash.Substring(0,16))..."

# back up the current file (idempotent, keyed by hash)
$bak = Join-Path $InstallDir ("termsrv.dll.{0}.bak" -f $curHash.Substring(0,8))
if (-not (Test-Path $bak)) { Copy-Item $TARGET $bak -Force; Write-Host "backed up -> $bak" }
$pristine = Join-Path $InstallDir 'termsrv.dll.pristine.bak'
if (-not (Test-Path $pristine)) { Copy-Item $TARGET $pristine -Force }

# produce a patched copy (autopatcher reads a copy; never touches System32)
$incoming = Join-Path $InstallDir 'termsrv_incoming.dll'
Copy-Item $TARGET $incoming -Force
$patched  = Join-Path $InstallDir 'termsrv_patched.dll'
if (Test-Path $patched) { Remove-Item $patched -Force }
& $py $auto patch $incoming $patched
if ($LASTEXITCODE -ne 0) {
  throw "autopatcher refused (already patched, or an unrecognized build). Nothing changed."
}
$patchedHash = (Get-FileHash $patched -Algorithm SHA256).Hash
if ($patchedHash -eq $curHash) { Write-Host "already patched; nothing to do."; exit 0 }

# policy + firewall
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
foreach ($p in @('TCP','UDP')) {
  $n = "OpenRDP-$p"
  if (-not (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $n -Direction Inbound -Action Allow -Protocol $p -LocalPort 3389 -Profile Any | Out-Null
  }
}

# swap the DLL
Stop-Service UmRdpService -Force -ErrorAction SilentlyContinue
Stop-Service TermService  -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
takeown /F $TARGET /A | Out-Null
icacls  $TARGET /grant "Administrators:F" | Out-Null
$reboot = $false
try {
  Copy-Item $patched $TARGET -Force
} catch {
  Copy-Item $patched "$TARGET.new" -Force
  $sig = '[DllImport("kernel32.dll",SetLastError=true,CharSet=CharSet.Unicode)]public static extern bool MoveFileEx(string a,string b,int f);'
  $k = Add-Type -MemberDefinition $sig -Name MFE -Namespace RdpHost -PassThru
  if (-not $k::MoveFileEx("$TARGET.new", $TARGET, 5)) { throw "MoveFileEx failed" }  # REPLACE|DELAY_UNTIL_REBOOT
  $reboot = $true
}
Set-Service TermService -StartupType Automatic
if ($reboot) {
  Write-Warning "termsrv.dll was locked; patched copy staged. REBOOT to apply, then re-run to verify."
  exit 0
}
Start-Service TermService
Start-Sleep -Seconds 4

$listening = [bool](Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue)
if ($listening) {
  Write-Host "`nSUCCESS: RDP host enabled. Port 3389 is LISTENING." -ForegroundColor Green
  Write-Host "termsrv.dll now: $($patchedHash.Substring(0,16))..."
} else {
  Write-Warning "Patched and service started, but 3389 is not listening yet. Check 'Get-NetTCPConnection -LocalPort 3389' and the Application event log."
}
