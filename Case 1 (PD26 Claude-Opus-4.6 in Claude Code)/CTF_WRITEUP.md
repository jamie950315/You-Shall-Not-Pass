# CTF InfoSec 2026 - Parallels Desktop License Bypass: Full Writeup

## Target

- **Application:** Parallels Desktop 26.2.2 (Build 57373)
- **Bundle ID:** `com.parallels.desktop.console`
- **Architecture:** Universal (ARM64 + x86_64)
- **Platform:** macOS 26 (Apple Silicon)

## Quick Start

```bash
# One command does everything:
sudo python3 crack_parallels.py

# Then launch:
open Question1.app
```

## Architecture Overview

Parallels uses a multi-process, multi-layer defense:

```
┌──────────────────────────────────────┐
│  prl_client_app (GUI)                │ ← Layer 5,6,7: codesign verify, wizard
│  Calls SDK → IPC to dispatcher       │
└──────────┬───────────────────────────┘
           │ DspCmdUserGetLicenseInfo / DspCmdVmStart
           ▼
┌──────────────────────────────────────┐
│  prl_disp_service (root daemon)      │ ← Layer 1,2,3,4: JLIC sig, license
│  CDspLicenseChecker, License_Sentry  │    gate, lifetime, client check
│  JLIC Engine → /licenses.json       │
└──────────┬───────────────────────────┘
           │ posix_spawn via prl_client_app --exec-vm-app
           ▼
┌──────────────────────────────────────┐
│  prl_vm_app (VM hypervisor process)  │ ← Layer 9,10: peer validate, HV entitlement
│  Hypervisor.framework → hv_vm_create │
└──────────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────┐
│  libPrlXmlModel.1.dylib             │ ← Layer 8: isTrial() data model
│  CDownloadedKeyInfo::isTrial()      │
└──────────────────────────────────────┘
```

## The 10 Defense Layers & How They Were Bypassed

### Layer 1: JLIC Cryptographic Signature (prl_disp_service)

**What it does:** Verifies RSA signature on the JSON license data in `/Library/Preferences/Parallels/licenses.json`.

**Key code (ARM64):**
```asm
0x1002bda68: tbz  w0, #0, 0x1002bdac4   ; if sig valid → skip error
; Error: "Signature check failed for license info"
```

**Patch:** `tbz` → unconditional `b` (bytes: `e0020036` → `17000014`)

**Why it works:** The signature verification function at `0x100034824` is called, but its result is never checked. The unconditional branch always takes the "valid" path.

---

### Layer 2: VM Start License Status (prl_disp_service)

**What it does:** Checks license validity before allowing VM to start. Throws C++ exception "Failed to start VM due license has some non valid status".

**Patch:** `cbz w0, +0x3c` → `b +0x3c` at `0x10029FAA0` (always valid)

---

### Layer 3: VM Start Final Gate (prl_disp_service)

**What it does:** Final check using w22 flag — if set, blocks VM start.

**Patch:** `tbnz w22, #0, +0x8c0` → `nop` at `0x10029FB28`

---

### Layer 4: VM Lifetime Expiration (prl_disp_service)

**What it does:** Compares current time against `main_period_ends_at` from license data. Two paths: online and offline.

**Key code:** Calls `QDateTime::operator<` to check if license has expired. Logs "Vm lifetime is expired. %s >= %s".

**Patches:**
- Online: `cbz w8, +0x1F8` → `b +0x1F8` at `0x100291028`
- Offline: `cbz w8, +0x39C` → `b +0x39C` at `0x100290A90`

---

### Layer 5: Dispatcher Client Check (prl_disp_service)

**What it does:** When prl_vm_app connects to the dispatcher via IPC, the dispatcher validates the connecting client's code signature. Logs "Connected client check failed, disconnecting".

**Patch:** Replace function entry with `mov w0, #1; ret` at `0x1000A0B8C` — always accept.

---

### Layer 6: Client Codesign Verification (prl_client_app)

**What it does:** Three-layer verification of the app bundle's code signature:
1. `SecStaticCodeCheckValidity` (Security.framework API)
2. Certificate chain validation (`SecCodeCopySigningInformation`)
3. `fork` + `exec /usr/bin/codesign --verify` (external CLI tool)

**Failure:** Shows "無法啟動 Parallels Desktop" (`GUI_ERR_APP_NEED_REINSTALL`).

**Patch:** Replace function at `0x1007ADB34` with `mov w0, #1; ret` — always return "valid".

---

### Layer 7: License Wizard Display (prl_client_app)

**What it does:** Shows trial promo page on startup. The `showWizard` dispatch function is called from 13 different places (startup, timer, license change, etc.).

**Key insight:** The wizard display is driven by `CLicenseWrap::LicenseInfo` struct fields (license type integer at offset +0x0), NOT by `isTrial()`. This is why patching only `isTrial()` didn't remove the trial page.

**Patch:** Replace `showWizard` dispatch at `0x100457E88` with `mov w0, #0; ret` — never show.

---

### Layer 8: Trial Status Data Model (libPrlXmlModel.1.dylib)

**What it does:** `CDownloadedKeyInfo::isTrial()` reads the trial flag from the license data object at offset `0xb4`.

**Patch:** Replace with `mov w0, #0; ret` at `0x7B19B4` — always return false.

---

### Layer 9: VM Peer Validation (prl_vm_app)

**What it does:** When prl_vm_app connects to the dispatcher, it validates the dispatcher's code signature using `SecStaticCodeCheckValidity` with requirement string `"anchor apple generic and certificate leaf[subject.OU] = \"4C6364ACXT\""`.

**Failure:** "Failed to validate peer" → "Connection to dispatcher failed!" → exit code -2.

**Patch:** `cbz w0, +0x50` → `b +0x50` at `0x1000434F8` — always skip error.

---

### Layer 10: Hypervisor.framework Entitlement (macOS kernel)

**What it does:** macOS requires `com.apple.security.hypervisor` entitlement to call `hv_vm_create()`. Without it: `HV_DENIED (0xfae94007)`.

**Solution:** Ad-hoc code sign `Parallels VM.app` with the entitlement.

**Critical findings:**
- `com.apple.security.hypervisor` works with ad-hoc signing (verified with test program)
- `com.apple.security.cs.disable-library-validation` **MUST NOT** be added — it triggers AMFI SIGKILL on ad-hoc signed binaries
- `embedded.provisionprofile` must be removed — it conflicts with ad-hoc signing identity

---

## Code Signing: The Correct Order

This was the hardest part. macOS code signing has strict rules about signing order and entitlements.

### Rules Learned (the hard way)

1. **Sign inside-out:** Scripts → Mach-O binaries → inner bundles → outer bundle
2. **Never use `--deep` with `--entitlements`** — it applies entitlements to ALL nested binaries including kexts and appex, causing AMFI rejection
3. **Never use `--deep` after adding entitlements** — it re-signs inner binaries, stripping their entitlements
4. **Sign `Parallels VM.app` bundle with `--entitlements`** — this correctly signs the bundle's main executable (prl_vm_app) with the entitlement
5. **Only use `com.apple.security.hypervisor`** — no `disable-library-validation`, no `allow-unsigned-executable-memory`
6. **Remove `embedded.provisionprofile`** — it binds entitlements to the original Developer ID (Team: 4C6364ACXT)
7. **The dispatcher runs as root** — `sudo pkill -9 prl_disp_service` is required to restart it

### Correct Signing Sequence

```bash
# 1. Sign all scripts (parallels_wrapper, watchdog, etc.)
codesign --force --sign - parallels_wrapper

# 2. Sign all Mach-O binaries individually
find $APP -type f -exec sh -c 'file "$1" | grep -q Mach-O && codesign --force --sign - "$1"' _ {} \;

# 3. Sign Parallels VM.app WITH hypervisor entitlement
codesign --force --sign - --entitlements ent_hv.plist "Parallels VM.app"

# 4. Sign other bundles WITHOUT entitlements
codesign --force --sign - "Parallels Service.app"
# ... other bundles ...

# 5. Sign main app bundle LAST
codesign --force --sign - Question1.app
```

## Patch Summary Table

| # | Binary | Arch | VA | Bytes | Instruction Change |
|---|--------|------|-----|-------|--------------------|
| P1 | prl_disp_service | arm64 | 0x1002BDA68 | e0020036→17000014 | tbz→b |
| P2a | prl_disp_service | x86_64 | 0x10029FE5A | 7475→9090 | je→nop |
| P2b | prl_disp_service | x86_64 | 0x10029FE87 | 7471→9090 | je→nop |
| P3 | prl_disp_service | arm64 | 0x10029FAA0 | e0010034→0f000014 | cbz→b |
| P4 | prl_disp_service | arm64 | 0x10029FB28 | 16460037→1f2003d5 | tbnz→nop |
| P5 | prl_disp_service | arm64 | 0x1005C7D84 | 43a10094→00008052 | bl→mov w0,#0 |
| P6 | prl_disp_service | x86_64 | 0x100285078 | 0f8597000000→e99800000090 | jne→jmp |
| P7 | prl_disp_service | x86_64 | 0x10058DE47 | e86e370500→31c0909090 | call→xor eax |
| P8 | prl_disp_service | arm64 | 0x100291028 | c80f0034→7e000014 | cbz→b |
| P9 | prl_disp_service | arm64 | 0x100290A90 | e81c0034→e7000014 | cbz→b |
| P10 | prl_disp_service | x86_64 | 0x1002765C5 | 0f84aa010000→e9ab01000090 | je→jmp |
| P11 | prl_disp_service | x86_64 | 0x100276085 | 0f8437030000→e93803000090 | je→jmp |
| P12 | prl_disp_service | arm64 | 0x1000A0B8C | ffc300d1→20008052 | sub→mov w0,#1 |
| P13 | prl_disp_service | arm64 | 0x1000A0B90 | f44f01a9→c0035fd6 | stp→ret |
| P14 | prl_disp_service | x86_64 | 0x100099D60 | 554889e5→b8010000 | push→mov eax,1 |
| P15 | prl_disp_service | x86_64 | 0x100099D64 | 5350→00c3 | push→ret |
| C1 | prl_client_app | arm64 | 0x1007ADB34 | fa67bba9→20008052 | stp→mov w0,#1 |
| C2 | prl_client_app | arm64 | 0x1007ADB38 | f85f01a9→c0035fd6 | stp→ret |
| C3 | prl_client_app | x86_64 | 0x10077A0A0 | 554889e54157→b801000000c3 | push→mov+ret |
| W1 | prl_client_app | arm64 | 0x100457E88 | f44fbea9→00008052 | stp→mov w0,#0 |
| W2 | prl_client_app | arm64 | 0x100457E8C | fd7b01a9→c0035fd6 | stp→ret |
| W3 | prl_client_app | x86_64 | 0x100428150 | 554889e5→31c0c390 | push→xor+ret |
| V1 | prl_vm_app | arm64 | 0x1000434F8 | 80020034→14000014 | cbz→b |
| V2 | prl_vm_app | x86_64 | 0x100040B78 | 7445→eb45 | je→jmp |
| T1 | libPrlXmlModel | arm64 | 0x7B19B4 | 08b440b9→00008052 | ldr→mov w0,#0 |
| T2 | libPrlXmlModel | arm64 | 0x7B19B8 | 1f010071→c0035fd6 | cmp→ret |
| T3 | libPrlXmlModel | x86_64 | 0x768A6B | 0f95c0→31c090 | setne→xor eax |

## Tools Used

- `otool -arch arm64 -tV` — ARM64 disassembly
- `strings -t x -arch arm64` — String offset finding
- `nm -arch arm64` — Symbol table analysis
- `xxd` — Hex verification
- `codesign` — macOS code signing
- Python `struct` — Fat binary header parsing

## Files

| File | Purpose |
|------|---------|
| `crack_parallels.py` | One-script solution (run with sudo) |
| `bypass_license.py` | Original iterative patch script |
| `CTF_ReverseAnalysis_Report.md` | Detailed reverse engineering report |
| `CTF_WRITEUP.md` | This writeup |

---

*CTF InfoSec 2026 - Authorized Competition Use Only*
