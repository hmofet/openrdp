# termsrv-rdp-host

Enable the Remote Desktop **host** role on Windows client SKUs (Home, and
single-session Pro) by patching `termsrv.dll` - on **x64 and ARM64** - with a
patch that is **re-derived from your own binary each run** instead of read from
a table of hard-coded offsets.

Same goal as [RDP Wrapper](https://github.com/stascorp/rdpwrap): let a machine
you own host RDP even though Microsoft gates that capability by edition. Two
differences that motivated this:

- **ARM64 works.** RDP Wrapper (and its offset databases) are x64-only. Windows
  on ARM ships `termsrv.dll` as an **ARM64X hybrid**, which needs a fundamentally
  different approach (see [How it works](#how-it-works)).
- **No offset database to go stale.** The patch sites are located structurally
  every run, so a cumulative update that ships a brand-new `termsrv.dll` - an
  unseen build with shifted offsets - is re-patched automatically instead of
  waiting for someone to publish new offsets.

> ⚠️ This modifies a Windows **system file**. Use it only on machines you own or
> administer, to enable a feature for **your own** remote access. It is not a way
> into anyone else's computer. See [Scope & legality](#scope--legality).

---

## What it changes

Inside `CSLQuery::Initialize` in `termsrv.dll`, two cached globals are forced on:

| Global | Normally on Home | Forced to | Effect |
|---|---|---|---|
| `IsServerSku` | 0 (`wProductType == VER_NT_WORKSTATION`) | 1 | machine is treated as server-class for RDP |
| `bRemoteConnAllowed` | 0 (Software-Licensing policy denies RDP host) | 1 | the connection manager creates + **binds** the RDP-Tcp/UDP listeners |

`bRemoteConnAllowed == 0` is the actual gate: with it clear, the connection
manager skips the whole block that enumerates `WinStations` and starts the
listeners, so **port 3389 never binds**. Forcing both globals to 1 makes the
listener bind, exactly as it does on Pro/Server. Each patch is a **single
changed instruction** (an immediate flipped from 0 to 1); nothing else in the
binary is touched.

The tool never installs a wrapper DLL and never changes `ServiceDll` -
`termsrv.dll` stays the real service DLL, just patched.

---

## Requirements

- Windows 10/11, **x64 or ARM64**, client edition (Home / single-session Pro).
- **Python 3** with `pefile` (`pip install pefile`).
  - On **x64**, also `capstone` (`pip install capstone`), used for the x86-64
    decoder. On **ARM64** no capstone is needed: the ARM64 path is pure-Python.
- Administrator rights (patching System32 + controlling TermService).

The scripts auto-discover Python and install the Python deps if missing.

---

## Quick start

From an **elevated** PowerShell, in the repo folder:

```powershell
# 1) enable RDP host now (backs up your DLL, patches, verifies 3389 binds)
.\Enable-RdpHost.ps1

# 2) (optional) keep it enabled across Windows Updates
.\Install-Guard.ps1
```

That's it. Connect with any RDP client to the machine's IP. If you use NLA, log
in with a normal local account. To confirm it's listening:

```powershell
Get-NetTCPConnection -LocalPort 3389 -State Listen
```

Enabling concurrent/multi-session (more than one simultaneous login) is a
*separate* set of tweaks this tool does **not** do - it only enables the host
role. Single remote session is what you get.

---

## Rollback

`Enable-RdpHost.ps1` keeps a pristine copy at
`%ProgramData%\termsrv-rdp-host\termsrv.dll.pristine.bak`. To revert:

```powershell
Stop-Service UmRdpService,TermService -Force
takeown /F C:\Windows\System32\termsrv.dll /A
icacls  C:\Windows\System32\termsrv.dll /grant Administrators:F
Copy-Item "$env:ProgramData\termsrv-rdp-host\termsrv.dll.pristine.bak" C:\Windows\System32\termsrv.dll -Force
Start-Service TermService
# remove the guard, if installed:
Unregister-ScheduledTask -TaskName TermsrvRdpHostGuard -Confirm:$false
```

A Windows cumulative update that ships a new `termsrv.dll` also reverts the
patch on its own (that's what the guard re-applies).

---

## The autopatcher (`termsrv_autopatch.py`)

Standalone and side-effect-free - it reads a DLL and writes a patched copy;
it never touches System32.

```
python termsrv_autopatch.py locate <in.dll>            # find + print the sites
python termsrv_autopatch.py patch  <in.dll> <out.dll>  # write a patched copy
# exit 0 = ok, 3 = refused (ambiguous / unrecognized / unsupported)
```

It auto-detects the architecture from the PE machine field and refuses cleanly
on anything it doesn't recognize.

### How it works

The patch sites are found from **stable structural anchors**, not offsets:

1. **Find `CSLQuery::Initialize`** as the function that calls the imported
   `GetVersionExW` (resolved through the import table / call thunk).
2. **Patch A (IsServerSku):** right after that call, the code reads
   `wProductType` from the `OSVERSIONINFOEXW` on the stack, compares it to
   `VER_NT_WORKSTATION`, and stores 0/1 to a global. The `store 0` on the
   workstation branch is flipped to `store 1`.
3. **Patch B (bRemoteConnAllowed):** the Software-Licensing query returns the
   distinctive status `0xC004F012` on client SKUs; the value it yields is stored
   to a second global. That `store 0` is flipped to `store 1`.

Every located site is re-checked against its expected instruction encoding
**before** a byte is written. If anything is ambiguous or doesn't match, the
tool **refuses** (a mis-patch of a system DLL is worse than an unbound port).

#### The ARM64 wrinkle: ARM64X

On Windows-on-ARM, `termsrv.dll` is an **ARM64X** image: it contains **two**
complete code streams - native **ARM64** and **ARM64EC** (x64-emulation) - and a
CHPE code-range map that selects one per process. TermService runs as a native
ARM64 process, so **only the native ARM64 stream executes**. A patch applied to
the ARM64EC copy disassembles and verifies perfectly and *never runs*. This tool
parses the CHPE map and restricts the search to the **native** code range. (This
is the single thing that makes hand-porting the RDP-Wrapper technique to ARM64
actually work - and the reason naive attempts silently fail.)

On x64 there's one code stream and no such trap.

### Why it survives updates

Because nothing is hard-coded, a Windows Update that ships a new `termsrv.dll`
with different offsets is handled by simply running `locate`/`patch` again - the
anchors (`GetVersionExW`, the `wProductType` compare, the `0xC004F012` status,
the two global stores) are compiler-invariant. If a future build changes shape
enough that the anchors no longer match unambiguously, the tool refuses rather
than guess.

---

## The guard (`termsrv_guard.ps1` + `Install-Guard.ps1`)

A Scheduled Task (`TermsrvRdpHostGuard`, running as SYSTEM) that fires at
startup, every 6 hours, and on a Windows-Update servicing event. Each run is one
of three outcomes:

- **healthy** - the live DLL matches what we last patched; it just checks that
  3389 is listening (and restarts TermService once if not).
- **drift** - the DLL changed (an update replaced it): back up, autopatch,
  deploy, verify 3389, record the new hash.
- **refuse** - the autopatcher won't touch an unrecognized build: it logs an
  **alert** to the Application event log (source `TermsrvRdpHost`) and to
  `%ProgramData%\termsrv-rdp-host\guard.log`, with bounded retries so it never
  loops. RDP stays off, the machine stays healthy.

---

## Scope & legality

- **Your own machines only.** This enables a feature on a computer you control;
  it is not an exploit and grants no access to systems you don't administer.
  Actual logins still require valid Windows credentials.
- **No Microsoft binaries are distributed.** This repository contains *no*
  `termsrv.dll` and no PDBs. The tool patches the copy already on your machine.
  Whether patching a Windows system file is consistent with your Windows license
  is between you and that license.
- **No warranty.** Patching a system DLL can break remote access or require a
  rollback/repair. See the BSD-3-Clause `LICENSE`. You run this at your own risk.

---

## Prior art & credits

- [RDP Wrapper](https://github.com/stascorp/rdpwrap) - the original technique of
  enabling the RDP host role by intercepting `termsrv.dll`'s licensing checks
  (x64, offset-database based).
- This project re-derives the equivalent patch structurally and adds first-class
  **ARM64X** support and self-healing across updates.
