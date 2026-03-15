# CTF InfoSec 2026 — Parallels Desktop License Bypass: Full Writeup

## Target

- **Application:** Parallels Desktop 26.2.2 (Build 57373)
- **Bundle ID:** `com.parallels.desktop.console`
- **Architecture:** Universal (ARM64 + x86_64), Apple Silicon Mac
- **OS:** macOS 26 (Tahoe)

## Quick Start

```bash
sudo python3 crack_parallels.py
open Parallels Desktop.app
```

## Architecture

```
prl_client_app (GUI)          ← Layers 6,7,8: codesign, wizard, MasterKey
    │ IPC
    ▼
prl_disp_service (root)       ← Layers 1–5: JLIC sig, license gate, lifetime, client check, codesign
    │ posix_spawn
    ▼
prl_vm_app (VM hypervisor)    ← Layers 9,10: peer validate, Team ID
    │
    ▼
libPrlGui.3.dylib             ← Layers 11–13: message suppression (piracy dialog kill)
libPrlXmlModel.1.dylib        ← Layer 14: isTrial() data model
Hypervisor.framework           ← Layer 15: macOS entitlement
```

## The 15 Defense Layers

### Layer 1: JLIC Cryptographic Signature

Verifies RSA signature on license JSON. Single conditional branch gates the entire check.

**Patch:** `tbz w0,#0` → `b` at `0x1002BDA68` (ARM64)

### Layer 2+3: VM Start License Gate

Two sequential checks: status validation (`cbz w0`) and final flag gate (`tbnz w22`).

**Patches:** Unconditional branch + NOP at `0x10029FAA0`, `0x10029FB28`

### Layer 4: VM Lifetime Expiration

Compares `QDateTime::currentDateTimeUtc()` against license expiry. Two paths: online and offline.

**Patches:** Both `cbz` → `b` at `0x100291028`, `0x100290A90`

### Layer 5: Dispatcher Client Connection Check

Validates code signature of connecting clients. Rejects ad-hoc signed binaries.

**Patch:** Function entry → `mov w0,#1; ret` at `0x1000A0B8C`

### Layer 6: SecStaticCodeCheckValidity (Dispatcher)

macOS Security.framework API check on binary integrity.

**Patch:** `bl SecStaticCodeCheckValidity` → `mov w0,#0` at `0x1005C7D84`

### Layer 7: MasterKey Piracy Handler

Client-side business logic that processes MasterKey phone-home responses. Can set persistent flags and trigger piracy events beyond just showing a dialog.

**Patch:** Function entry → `ret` at `0x1006847FC`

### Layer 8: Client Codesign Verification

Three-layer verification: Security.framework API → certificate chain → `fork+exec /usr/bin/codesign --verify`. Failure shows "Cannot start Parallels Desktop."

**Patch:** Function entry → `mov w0,#1; ret` at `0x1007ADB34`

### Layer 9: License Wizard Display

`showWizard` dispatch function — single chokepoint for all 13 wizard callers (startup, timer, license change, etc.). Driven by `CLicenseWrap::LicenseInfo` struct, not `isTrial()`.

**Patch:** Function entry → `mov w0,#0; ret` at `0x100457E88`

### Layer 10: VM Peer Validation

VM process validates dispatcher's code signature before connecting. Failure: "Failed to validate peer" → exit code -2.

**Patch:** `cbz w0,+0x50` → `b +0x50` at `0x1000434F8`

### Layer 11: VM Team ID Verification

`SecCodeCopyGuestWithAttributes` → `SecCodeCopySigningInformation` → `CFStringCompare(kSecCodeInfoTeamIdentifier)`. Compares against Parallels Team ID `4C6364ACXT`. Ad-hoc = no Team ID = fail → sends `PRL_ERR_TRIGGERED` to dispatcher → client shows piracy dialog.

**Patch:** Function entry → `mov w0,#0; ret` at `0x1008B1F18`

### Layers 12–14: Message Display Suppression (libPrlGui)

The piracy detection system (`PRL_ERR_TRIGGERED`) has multiple redundant trigger paths in the dispatcher that couldn't all be traced. The definitive fix: patch the UI exit points.

| Function | Role | Address |
|----------|------|---------|
| `CMessageProcessor::showMessage` | Central message display — kills ALL dialogs | `0xE3434` |
| `showMessageFromServer` | Blocks server-pushed messages from being cached | `0xE74E4` |
| `raiseSpecificMessageBox` | Prevents re-raise on window focus switch | `0xE8740` |

**Why all three are needed:** `showMessage` kills initial display. `showMessageFromServer` prevents the message from being *cached* before `showMessage` runs. `raiseSpecificMessageBox` prevents cached messages from being *re-raised* when switching window focus — this was the "appears when switching apps" bug.

### Layer 15: CDownloadedKeyInfo::isTrial()

Data model function at offset `0xB4` in the license object. Returns trial flag from JLIC data.

**Patch:** `ldr; cmp; cset; ret` → `mov w0,#0; ret` at `0x7B19B4`

### Layer 16: Hypervisor.framework Entitlement

macOS requires `com.apple.security.hypervisor` to call `hv_vm_create()`. Without it: `HV_DENIED (0xfae94007)`.

**Solution:** Ad-hoc sign `Parallels VM.app` with the entitlement. Critical: `embedded.provisionprofile` must be removed first, and `com.apple.security.cs.disable-library-validation` must NOT be added (causes AMFI SIGKILL).

## Code Signing: Correct Order

```
1. Sign all scripts (parallels_wrapper, watchdog, etc.)
2. Sign all Mach-O binaries individually
3. Sign Parallels VM.app WITH hypervisor entitlement
4. Sign other bundles WITHOUT entitlements
5. Sign main app bundle LAST
```

**Rules learned the hard way:**
- `--deep --entitlements` applies entitlements to ALL nested binaries → AMFI rejects kexts/appex with hypervisor entitlement
- `--deep` after adding entitlements strips them from inner binaries
- `disable-library-validation` causes AMFI SIGKILL on ad-hoc binaries
- `embedded.provisionprofile` binds entitlements to original Developer ID
- Dispatcher runs as root → `sudo pkill -9` required to restart

## Patch Summary

| # | Binary | Arch | Offset | Original → Patch | Description |
|---|--------|------|--------|-----------------|-------------|
| P1 | prl_disp_service | arm64 | 0x2BDA68 | e0020036→17000014 | JLIC sig: tbz→b |
| P2a | prl_disp_service | x86_64 | 0x29FE5A | 7475→9090 | JLIC sig: je→nop |
| P2b | prl_disp_service | x86_64 | 0x29FE87 | 7471→9090 | JLIC parse: je→nop |
| P3 | prl_disp_service | arm64 | 0x29FAA0 | e0010034→0f000014 | VM license: cbz→b |
| P4 | prl_disp_service | arm64 | 0x29FB28 | 16460037→1f2003d5 | VM gate: tbnz→nop |
| P5 | prl_disp_service | arm64 | 0x5C7D84 | 43a10094→00008052 | Codesign→mov w0,#0 |
| P6 | prl_disp_service | x86_64 | 0x285078 | 0f8597000000→e99800000090 | VM license: jne→jmp |
| P7 | prl_disp_service | x86_64 | 0x58DE47 | e86e370500→31c0909090 | Codesign→xor eax |
| P8 | prl_disp_service | arm64 | 0x291028 | c80f0034→7e000014 | Lifetime on: cbz→b |
| P9 | prl_disp_service | arm64 | 0x290A90 | e81c0034→e7000014 | Lifetime off: cbz→b |
| P10 | prl_disp_service | x86_64 | 0x2765C5 | 0f84aa010000→e9ab01000090 | Lifetime on: je→jmp |
| P11 | prl_disp_service | x86_64 | 0x276085 | 0f8437030000→e93803000090 | Lifetime off: je→jmp |
| P12 | prl_disp_service | arm64 | 0xA0B8C | ffc300d1→20008052 | Client chk→mov w0,#1 |
| P13 | prl_disp_service | arm64 | 0xA0B90 | f44f01a9→c0035fd6 | Client chk→ret |
| P14 | prl_disp_service | x86_64 | 0x99D60 | 554889e5→b8010000 | Client chk→mov eax,1 |
| P15 | prl_disp_service | x86_64 | 0x99D64 | 5350→00c3 | Client chk→ret |
| MK1 | prl_client_app | arm64 | 0x6847FC | ff4302d1→c0035fd6 | MasterKey→ret |
| MK2 | prl_client_app | x86_64 | 0x639DE0 | 554889e5→c3909090 | MasterKey→ret |
| C1 | prl_client_app | arm64 | 0x7ADB34 | fa67bba9→20008052 | Codesign→mov w0,#1 |
| C2 | prl_client_app | arm64 | 0x7ADB38 | f85f01a9→c0035fd6 | Codesign→ret |
| C3 | prl_client_app | x86_64 | 0x77A0A0 | 554889e54157→b801000000c3 | Codesign→mov+ret |
| W1 | prl_client_app | arm64 | 0x457E88 | f44fbea9→00008052 | Wizard→mov w0,#0 |
| W2 | prl_client_app | arm64 | 0x457E8C | fd7b01a9→c0035fd6 | Wizard→ret |
| W3 | prl_client_app | x86_64 | 0x428150 | 554889e5→31c0c390 | Wizard→xor+ret |
| V1 | prl_vm_app | arm64 | 0x434F8 | 80020034→14000014 | Peer: cbz→b |
| V2 | prl_vm_app | x86_64 | 0x40B78 | 7445→eb45 | Peer: je→jmp |
| V3 | prl_vm_app | arm64 | 0x8B1F18 | ffc301d1→00008052 | Team ID→mov w0,#0 |
| V4 | prl_vm_app | arm64 | 0x8B1F1C | f85f03a9→c0035fd6 | Team ID→ret |
| V5 | prl_vm_app | x86_64 | 0x9B74E0 | 554889e54157→31c0c3909090 | Team ID→xor+ret |
| G1 | libPrlGui | arm64 | 0xE3434 | ff8301d1→c0035fd6 | showMessage→ret |
| G2 | libPrlGui | x86_64 | 0xD9220 | 554889e5→c3909090 | showMessage→ret |
| G3 | libPrlGui | arm64 | 0xE74E4 | ff0301d1→c0035fd6 | fromServer→ret |
| G4 | libPrlGui | x86_64 | 0xDD1A0 | 554889e5→c3909090 | fromServer→ret |
| G5 | libPrlGui | arm64 | 0xE8740 | ff4301d1→c0035fd6 | raiseSpecific→ret |
| G6 | libPrlGui | x86_64 | 0xDE290 | 554889e5→c3909090 | raiseSpecific→ret |
| T1 | libPrlXmlModel | arm64 | 0x7B19B4 | 08b440b9→00008052 | isTrial→mov w0,#0 |
| T2 | libPrlXmlModel | arm64 | 0x7B19B8 | 1f010071→c0035fd6 | isTrial→ret |
| T3 | libPrlXmlModel | x86_64 | 0x768A6B | 0f95c0→31c090 | isTrial→xor eax |

**Total: 38 instruction patches across 5 binaries + ad-hoc codesign with hypervisor entitlement.**

## Files

| File | Purpose |
|------|---------|
| `crack_parallels.py` | One-command solution (`sudo python3 crack_parallels.py`) |
| `CTF_WRITEUP.md` | This writeup |
| `Parallels Desktop.app/` | Target app bundle |

---

*CTF InfoSec 2026 — Authorized Competition Use Only*
