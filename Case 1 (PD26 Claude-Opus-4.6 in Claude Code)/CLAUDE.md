# CLAUDE.md — InfoSec CTF 2026: Parallels Desktop Reverse Engineering

## Project Status: COMPLETE

All objectives achieved. VM launches and runs successfully with all license checks bypassed.

## What This Is

CTF competition challenge: reverse engineer and bypass the license verification mechanism of Parallels Desktop 26.2.2 (Build 57373) for macOS (Apple Silicon).

## Key Files

- `crack_parallels.py` — One-command solution: `sudo python3 crack_parallels.py`
- `CTF_WRITEUP.md` — Full writeup with all 15 defense layers documented
- `Parallels Desktop.app/` — Target app bundle (Parallels Desktop)

## Architecture (What You Need to Know)

Parallels uses a multi-process architecture with 5 binaries that cross-validate each other:

```
prl_client_app (GUI, user process)
    ↕ IPC
prl_disp_service (license engine, runs as ROOT via setuid wrapper)
    ↕ posix_spawn
prl_vm_app (VM hypervisor, inside Parallels VM.app bundle)

Shared libraries:
  libPrlGui.3.dylib — GUI message display
  libPrlXmlModel.1.dylib — License data model
```

## The 15 Essential Bypass Layers

1. **JLIC signature** — RSA sig on license JSON (`prl_disp_service`)
2. **VM start license check** — Semantic license validation (`prl_disp_service`)
3. **VM start final gate** — Flag-based gate after license check (`prl_disp_service`)
4. **VM lifetime expiry** — Online + offline time-based expiration (`prl_disp_service`)
5. **Client connection check** — Dispatcher validates connecting clients (`prl_disp_service`)
6. **SecStaticCodeCheckValidity** — macOS Security.framework API (`prl_disp_service`)
7. **MasterKey piracy handler** — Phone-home response business logic (`prl_client_app`)
8. **Client codesign verify** — 3-layer: Security API + cert chain + fork/exec codesign (`prl_client_app`)
9. **License wizard** — showWizard dispatch chokepoint, 13 callers (`prl_client_app`)
10. **VM peer validation** — VM validates dispatcher signature (`prl_vm_app`)
11. **Team ID check** — SecCodeCopySigningInformation team ID comparison (`prl_vm_app`)
12. **CMessageProcessor::showMessage** — Central message dialog display (`libPrlGui`)
13. **showMessageFromServer** — Server-pushed message caching (`libPrlGui`)
14. **raiseSpecificMessageBox** — Focus-switch dialog re-raise (`libPrlGui`)
15. **isTrial()** — `CDownloadedKeyInfo::isTrial()` data model (`libPrlXmlModel`)

Plus: ad-hoc codesign with `com.apple.security.hypervisor` entitlement on `Parallels VM.app`.

## Critical Gotchas (Hard-Won Lessons)

### Code Signing Order
Sign inside-out: scripts → Mach-O binaries → inner bundles → `Parallels VM.app` WITH entitlement → other bundles → main app LAST. Never use `--deep` with `--entitlements`. Never use `--deep` after adding entitlements (strips them).

### Entitlements
- `com.apple.security.hypervisor` on `Parallels VM.app` — **REQUIRED** for `hv_vm_create()`
- `com.apple.security.cs.disable-library-validation` — **DO NOT ADD**, causes AMFI SIGKILL on ad-hoc binaries
- `embedded.provisionprofile` — **MUST REMOVE** before signing (binds entitlements to original Developer ID)

### Process Management
- `prl_disp_service` runs as **root** — needs `sudo pkill -9` to restart
- After patching, the old dispatcher may still be running in memory with pre-patch code
- The dispatcher auto-restarts when the client app launches

### Piracy Detection (PRL_ERR_TRIGGERED)
The hardest part. Multiple redundant trigger paths in the dispatcher that couldn't all be traced at the binary level. The definitive fix was patching the **UI exit points** in `libPrlGui` (showMessage + showMessageFromServer + raiseSpecificMessageBox), not the generation points in the dispatcher.

The `raiseSpecificMessageBox` patch specifically fixes the "piracy dialog re-appears when switching window focus" behavior — it replays cached dialogs on focus change.

### Fat Binary Patching
All binaries are Universal (ARM64 + x86_64). The script parses fat headers and applies patches at `slice_offset + patch_offset` for each architecture. `codesign` only modifies `__LINKEDIT`, not `__TEXT`, so patches survive re-signing.

## How to Re-apply (if needed)

```bash
# From a clean Parallels Desktop.app:
sudo python3 crack_parallels.py

# Verify only (no sudo needed):
python3 crack_parallels.py --dry-run

# If app won't launch after codesign issues:
sudo chown -R $(whoami) Parallels Desktop.app
sudo python3 crack_parallels.py
```

## Tools Used

- `otool -arch arm64 -tV` — ARM64 disassembly
- `nm -arch arm64` — Symbol tables
- `strings -t x -arch arm64` — String offsets for xref tracing
- `xxd` — Hex byte verification
- `codesign` — macOS code signing
- Python `struct` — Fat binary header parsing
- `/Library/Logs/parallels.log` — Dispatcher log (key for tracing runtime behavior)
- `~/Parallels/<VM>.pvm/parallels.log` — VM process log

## Build & Version Info

```
CFBundleVersion: 57373
CFBundleShortVersionString: 26.2.2
Team ID: 4C6364ACXT (Parallels International GmbH)
Signed: Developer ID Application
Build date: Fri, 30 Jan 2026 16:42:51
```
