# CLAUDE.md — Parallels Desktop License Bypass (CTF InfoSec 2026)

## Project Status: COMPLETE (v26.2.2 Build 57373)

All objectives achieved. App launches without trial page, VMs start and run, no piracy dialogs.

## Files

| File | Purpose |
|------|---------|
| `crack_parallels.py` | One-command solution: `sudo python3 crack_parallels.py` |
| `CTF_WRITEUP.md` | Formal writeup with all defense layers documented |
| `CLAUDE.md` | This file — full context for future sessions |
| `Parallels Desktop.app/` | Target app bundle |

## Task: Adapting to a New Version

If the user provides a new version of Parallels Desktop, you need to:

1. **Run `--dry-run` first** to see which patches fail (byte mismatch)
2. **Re-locate each failed patch** using the string anchors listed below
3. **Update the offset in `crack_parallels.py`**
4. **Test with `sudo python3 crack_parallels.py`**

The defense architecture (15 binary patch layers + hypervisor entitlement) is unlikely to change fundamentally between minor versions. Function offsets WILL shift, but the surrounding code patterns and string references remain stable.

---

## Architecture: How Parallels Works

### Process Model

```
User launches Parallels Desktop.app
  → prl_client_app (GUI, runs as user)
      → launches "Parallels Service" (setuid wrapper, Contents/MacOS/)
          → forks prl_disp_service (license engine, runs as ROOT)
              → PID stored in /var/run/prl_disp_service.pid

User clicks "Start VM"
  → prl_client_app sends DspCmdVmStart via IPC
      → prl_disp_service checks license, then:
          → posix_spawn: prl_client_app --exec-vm-app
              → exec into prl_vm_app (Parallels VM.app/Contents/MacOS/)
                  → calls hv_vm_create() via Hypervisor.framework
```

### IPC Communication

- Client ↔ Dispatcher: Unix domain socket, protocol uses `DspCmd*` commands
- Dispatcher ↔ VM: Same socket mechanism, events use `PET_DSP_EVT_*` codes
- VM sends `PET_DSP_EVT_VM_MESSAGE` (code 100502) for piracy alerts
- Dispatcher forwards events to client for display

### Key Files on Disk

| Path | Purpose |
|------|---------|
| `/Library/Preferences/Parallels/licenses.json` | JLIC license data + RSA signature (read by dispatcher) |
| `/Library/Preferences/Parallels/dispatcher.desktop.xml` | Dispatcher config |
| `/Library/Logs/parallels.log` | Dispatcher + client log (ESSENTIAL for debugging) |
| `~/Parallels/<VM>.pvm/parallels.log` | Per-VM log from prl_vm_app |
| `/Library/Preferences/Parallels/parallels-desktop.loc` | Bundle location lock file |

### Binary Layout (Universal fat binaries: ARM64 + x86_64)

| Binary | Relative Path | Size | Role |
|--------|--------------|------|------|
| prl_client_app | Contents/MacOS/prl_client_app | ~60MB | GUI client |
| prl_disp_service | Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service | ~17MB | License engine (root) |
| prl_vm_app | Contents/MacOS/Parallels VM.app/Contents/MacOS/prl_vm_app | ~28MB | VM hypervisor |
| libPrlGui.3.dylib | Contents/Frameworks/libPrlGui.3.dylib | ~10MB | GUI message system |
| libPrlXmlModel.1.dylib | Contents/Frameworks/libPrlXmlModel.1.dylib | ~23MB | License data model |

---

## The Defense Layers — Full Detail (15 binary patch layers + code signing)

For each layer: what it does, how to find it in a new version, what the patch does, and what breaks without it.

### Layer 1: JLIC Cryptographic Signature (prl_disp_service)

**What:** RSA signature verification on the JSON license data. The dispatcher loads `/Library/Preferences/Parallels/licenses.json`, parses the `"license"` JSON string and `"signature"` field, verifies the signature cryptographically.

**String anchor:** `"Signature check failed for license info"`

**How to find:**
```bash
otool -arch arm64 -tV prl_disp_service | grep -B30 'Signature check failed'
```
Look for `tbz w0, #0, <target>` right before the error string load. The `tbz` is the gate — if bit 0 is 0, it skips the error (signature valid). Change `tbz` to unconditional `b`.

**Patch:** `tbz w0, #0, +offset` → `b +offset` (same target, unconditional)

**Without it:** Dispatcher rejects license data entirely. Nothing works.

**v26.2.2 offsets:** ARM64 `0x2BDA68`, x86_64 `0x29FE5A` (je→nop) + `0x29FE87` (second je→nop for parse check)

---

### Layer 2+3: VM Start License Gate (prl_disp_service)

**What:** Two sequential checks when starting a VM. First: `cbz w0` checks if license status is 0 (valid). Second: `tbnz w22, #0` is a final gate flag.

**String anchor:** `"Failed to start VM due license has some non valid status: .%8X %s %s"`

**How to find:**
```bash
otool -arch arm64 -tV prl_disp_service | grep -B20 'non valid status'
```
The `cbz w0` is ~30 instructions before the error string. The `tbnz w22` is further down in the same function.

**Patches:**
- `cbz w0, +offset` → `b +offset` (always take valid path)
- `tbnz w22, #0, +offset` → `nop` (never take error path)

**Without them:** "由於臨界誤差，不能啟動虛擬機器" error. KB article 9231.

**v26.2.2 offsets:** ARM64 `0x29FAA0` (cbz), `0x29FB28` (tbnz). x86_64 `0x285078` (jne→jmp).

---

### Layer 4: VM Lifetime Expiration (prl_disp_service)

**What:** Compares current time against `main_period_ends_at` from license data. Two separate code paths: online (server-verified) and offline (local timer).

**String anchors:**
- `"Vm lifetime is expired. %s >= %s"` (online)
- `"Vm lifetime is expired (offline case): %s >= %s"` (offline)

**How to find:**
```bash
otool -arch arm64 -tV prl_disp_service | grep -B60 'Vm lifetime is expired\.'
otool -arch arm64 -tV prl_disp_service | grep -B60 'offline case'
```
Each has a `cbz w8, <target>` before the log message. w8 is loaded from the lifetime check function result.

**Patches:** Both `cbz w8` → `b` (always skip to "not expired" path)

**Without them:** VMs killed mid-session when lifetime expires.

**v26.2.2 offsets:** ARM64 online `0x291028`, offline `0x290A90`. x86_64 online `0x2765C5`, offline `0x276085`.

---

### Layer 5: Dispatcher Client Connection Check (prl_disp_service)

**What:** When prl_vm_app connects to the dispatcher via IPC, the dispatcher validates the client's code signature. Rejects ad-hoc signed clients.

**String anchor:** `"Error : Connected client '%s' check failed, disconnecting the client."`

**How to find:**
```bash
otool -arch arm64 -tV prl_disp_service | grep -B40 'check failed, disconnecting'
```
The function containing this string has entry `sub sp, sp, #0x30` followed by checks. Find the function ENTRY and replace with `mov w0, #1; ret`.

**Patch:** Function entry → `mov w0, #1; ret` (always accept)

**Without it:** "Connection to dispatcher failed" — VM process can't communicate with dispatcher.

**v26.2.2 offsets:** ARM64 `0xA0B8C` + `0xA0B90`. x86_64 `0x99D60` + `0x99D64`.

---

### Layer 6: SecStaticCodeCheckValidity (prl_disp_service)

**What:** macOS Security.framework API call to verify binary integrity.

**How to find:**
```bash
otool -arch arm64 -tV prl_disp_service | grep -B15 'SecStaticCodeCheckValidity'
```
Find `bl _SecStaticCodeCheckValidity` and replace with `mov w0, #0`.

**v26.2.2 offsets:** ARM64 `0x5C7D84`. x86_64 `0x58DE47`.

---

### Layer 7: MasterKey Piracy Handler (prl_client_app)

**What:** Client-side business logic that processes MasterKey phone-home responses. The MasterKey system is a periodic timer in the dispatcher that contacts Parallels servers to verify license validity. The response is forwarded to the client, where this handler processes it.

**IMPORTANT:** This handler has side effects beyond just showing a dialog — it can set persistent flags and modify license state. That's why it must be patched separately from the UI suppression in libPrlGui.

**String anchors:** Search for these in prl_client_app:
- `"blacklisted master key"`
- `"invalid master key"`
- `"expired master key"`
These are string comparisons in the handler function.

**How to find:**
```bash
otool -arch arm64 -tV prl_client_app | grep -B80 'blacklisted master key' | grep 'sub sp, sp'
```
Find the function that contains the string comparison cascade. Its entry is a large `sub sp, sp, #0x90` or similar.

**Patch:** Function entry → `ret`

**v26.2.2 offsets:** ARM64 `0x6847FC`. x86_64 `0x639DE0`.

---

### Layer 8: Client Codesign Verification (prl_client_app)

**What:** Three-layer verification of app bundle code signature:
1. `SecStaticCodeCheckValidity` (Security.framework API)
2. Certificate chain validation (`SecCodeCopySigningInformation`)
3. `fork` + `exec /usr/bin/codesign --verify` (external CLI)

Failure shows "無法啟動 Parallels Desktop" (GUI_ERR_APP_NEED_REINSTALL).

**String anchors:**
- `"/usr/bin/codesign"` (the CLI tool path)
- `"=anchor apple generic and certificate leaf[subject.OU] = \"%s\""` (requirement string)

**How to find:**
```bash
otool -arch arm64 -tV prl_client_app | grep -B15 'SecStaticCodeCheckValidity'
```
This leads to the inner check. The OUTER function (which orchestrates all 3 layers) is found by:
```bash
otool -arch arm64 -tV prl_client_app | grep -B5 'com.parallels.desktop.dispatcher'
```
Look for the function with the `fork` call. Its entry has `stp x26, x25, [sp, #-0x50]!`.

**Patch:** Function entry → `mov w0, #1; ret` (always return "valid")

**v26.2.2 offsets:** ARM64 `0x7ADB34` + `0x7ADB38`. x86_64 `0x77A0A0`.

---

### Layer 9: License Wizard Display (prl_client_app)

**What:** `showWizard` dispatch function — THE single chokepoint for all license wizard display. Called from 13 different places (startup, timer, license change, registration dialogs, etc.).

**IMPORTANT:** The wizard is driven by `CLicenseWrap::LicenseInfo` struct fields (license type integer), NOT by `isTrial()`. That's why patching `isTrial()` alone doesn't remove the trial page.

**String anchor:** `"Create license wizard model. Detached: %d. Modal: %d."`

**How to find:**
```bash
otool -arch arm64 -tV prl_client_app | grep -B20 'Create license wizard model'
```
Trace callers. All 13 callers funnel through one dispatch function. Find it and patch entry → `mov w0, #0; ret`.

**v26.2.2 offsets:** ARM64 `0x457E88` + `0x457E8C`. x86_64 `0x428150`.

---

### Layer 10: VM Peer Validation (prl_vm_app)

**What:** VM process validates dispatcher's code signature before connecting. Uses `SecStaticCodeCheckValidity` with requirement string matching Parallels OU.

**String anchors:**
- `"Validating peer PID"`
- `"Failed to validate peer"`
- `"com.parallels.desktop.dispatcher"` (requirement identifier)

**How to find:**
```bash
otool -arch arm64 -tV prl_vm_app | grep -B30 'Failed to validate peer'
```
Find `cbz w0, <target>` after the validation call. Change to unconditional `b`.

**v26.2.2 offsets:** ARM64 `0x434F8`. x86_64 `0x40B78`.

---

### Layer 11: Team ID Verification (prl_vm_app)

**What:** After peer validation passes, the VM does a SECOND check using `SecCodeCopyGuestWithAttributes` → `SecCodeCopySigningInformation` → reads `kSecCodeInfoTeamIdentifier` → `CFStringCompare` against expected Team ID `4C6364ACXT`. Ad-hoc signing has no Team ID, so this always fails.

The failure causes the VM to send `PRL_ERR_TRIGGERED` to the dispatcher, which forwards it to the client as a piracy dialog.

**String anchor:** Search for `kSecCodeInfoTeamIdentifier` usage:
```bash
otool -arch arm64 -tV prl_vm_app | grep -B20 'kSecCodeInfoTeamIdentifier'
```

**How to find:** There is exactly ONE `SecCodeCopySigningInformation` call and ONE `kSecCodeInfoTeamIdentifier` reference in prl_vm_app. Find the function containing them (look for `SecCodeCopyGuestWithAttributes` nearby). Patch function entry → `mov w0, #0; ret`.

**v26.2.2 offsets:** ARM64 `0x8B1F18` + `0x8B1F1C`. x86_64 `0x9B74E0`.

---

### Layers 12-14: Message Display Suppression (libPrlGui.3.dylib)

**What:** The piracy detection system (`PRL_ERR_TRIGGERED`) has MULTIPLE redundant trigger paths in the dispatcher. We spent many iterations trying to patch them individually (P16-P26 in early versions) but they kept coming back — the error code is computed/loaded through paths we couldn't fully trace in static analysis.

**The definitive fix:** Patch the UI EXIT POINTS instead of the generation points.

**Three functions, each essential for a different reason:**

| Function | Symbol | Why Essential |
|----------|--------|---------------|
| `CMessageProcessor::showMessage` | `__ZN17CMessageProcessor11showMessageEP12CMessageInfob` | Central display — kills initial dialog show |
| `showMessageFromServer` | `__ZN15CMessageManager21showMessageFromServerE...` | Prevents server messages from being CACHED (if only showMessage is patched, the message gets cached and re-raised later) |
| `raiseSpecificMessageBox` | `__ZN15CMessageManager23raiseSpecificMessageBoxERK7QString11_PRL_RESULT` | Prevents cached dialogs from being RE-RAISED when user switches window focus |

**How to find:**
```bash
nm -arch arm64 libPrlGui.3.dylib | grep 'showMessage\|raiseSpecific'
```
These are exported symbols — `nm` gives you the exact offsets directly.

**Patch:** All three → `ret` at function entry.

**IMPORTANT DISCOVERY:** During debugging, we also patched all 7 `CMessageManager::showMessageBox` overloads, but the piracy dialog STILL appeared. That's because it goes through `CMessageProcessor::showMessage`, which is a DIFFERENT class in a different code path. The `showMessageBox` overloads are for user-initiated dialogs; `showMessage` is for system/event-driven messages.

**v26.2.2 offsets:**

| Function | ARM64 | x86_64 |
|----------|-------|--------|
| showMessage | `0xE3434` | `0xD9220` |
| showMessageFromServer | `0xE74E4` | `0xDD1A0` |
| raiseSpecificMessageBox | `0xE8740` | `0xDE290` |

---

### Layer 15: isTrial() (libPrlXmlModel.1.dylib)

**What:** `CDownloadedKeyInfo::isTrial()` reads the trial flag at object offset `0xB4`. Very simple function: `ldr w8, [x0, #0xb4]; cmp w8, #0; cset w0, ne; ret`.

**How to find:**
```bash
nm -arch arm64 libPrlXmlModel.1.dylib | grep 'isTrialEv'
```
Exported symbol — `nm` gives exact offset.

**Patch:** `ldr; cmp` → `mov w0, #0; ret`

**v26.2.2 offsets:** ARM64 `0x7B19B4` + `0x7B19B8`. x86_64 `0x768A6B`.

---

## Code Signing — The Correct Procedure

This was the second hardest part (after piracy detection). Many subtle failure modes.

### Signing Order (MUST be inside-out)

```
1. Scripts: parallels_wrapper, watchdog, prlcopy, prlexec, inittool
2. ALL Mach-O binaries (find + file + codesign)
3. XPCMounter.xpc inside Parallels VM.app
4. Parallels VM.app WITH --entitlements (hypervisor)
5. Other inner bundles WITHOUT entitlements
6. Main app bundle LAST
```

### Entitlement Rules

```xml
<!-- ONLY this entitlement on Parallels VM.app -->
<key>com.apple.security.hypervisor</key>
<true/>
```

- **NEVER add `com.apple.security.cs.disable-library-validation`** — causes AMFI SIGKILL on ad-hoc signed binaries. We spent a long time debugging this; the VM process was killed by signal 9 before dyld even loaded.
- **NEVER use `--deep` with `--entitlements`** — applies entitlements to ALL nested binaries including kexts and appex plugins, which AMFI rejects.
- **NEVER sign individual binaries AFTER signing their parent bundle** — breaks the bundle seal, causes "無法打開應用程式" error.

### Provisioning Profiles

**MUST remove** `embedded.provisionprofile` from:
- `Parallels VM.app/Contents/`
- `Parallels Mac VM.app/Contents/`
- `Contents/` (main app)

These profiles bind entitlements to the original Developer ID (Team: 4C6364ACXT). With ad-hoc signing, Team ID is "not set", causing entitlement mismatch.

---

## Piracy Detection Deep Dive (PRL_ERR_TRIGGERED)

This was by far the hardest part. The piracy dialog appeared ~8-10 minutes after app launch and persisted across focus switches.

### What We Tried (and Why It Failed)

| Attempt | What | Why It Failed |
|---------|------|---------------|
| Patch `isTrial()` | Make data model return false | Piracy dialog not driven by isTrial() |
| Modify `licenses.json` | Set `is_trial: false` | Dispatcher overwrites file on startup |
| Patch dispatcher's `isGenuineClient()` | Make genuine check return true | PRL_ERR_TRIGGERED generated elsewhere |
| NOP `mov w8, #-0x2b48` in dispatcher | Replace error code literal with 0 | Error code computed/loaded, not from literal |
| NOP 2x `QObject::connect` for MasterKey | Disconnect signal/slot pipeline | More than 2 connections, or alternate path |
| Block /etc/hosts | Prevent phone-home | Detection is LOCAL, not network-dependent |
| NOP `DspCmdVmStorageSetValue` handler | Block k=2b44 storage | Timer fires independently of stored value |
| Patch all 7 `showMessageBox` overloads | Suppress all CMessageManager dialogs | Dialog uses CMessageProcessor::showMessage, not CMessageManager |

### What Actually Fixed It

Patching THREE functions in `libPrlGui.3.dylib`:
1. `CMessageProcessor::showMessage` — kills initial display
2. `showMessageFromServer` — prevents message caching
3. `raiseSpecificMessageBox` — prevents focus-switch re-raise

### The Full Trigger Chain (for reference)

```
prl_vm_app: Team ID check fails (ad-hoc has no Team ID)
  → VM sends DspCmdVmStorageSetValue(k=2b44) to dispatcher
  → VM also sends PET_DSP_EVT_VM_MESSAGE with PRL_ERR_TRIGGERED
  → Dispatcher receives and stores k=2b44
  → Dispatcher has internal timer (~8 min delay)
  → Timer fires → reads stored value → generates PRL_ERR_TRIGGERED event
  → Event sent to client → CMessageProcessor::showMessage → piracy dialog
  → Dialog gets CACHED by CMessageManager
  → On window focus switch → raiseSpecificMessageBox replays cached dialog
```

Multiple redundant paths generate the same error. Blocking the UI exit points is the only reliable approach.

---

## Debugging Techniques

### Log Files

```bash
# Dispatcher + client log (most useful)
tail -f /Library/Logs/parallels.log

# VM process log
tail -f ~/Parallels/"<VM Name>.pvm"/parallels.log

# Filter for specific events
grep -iE 'license|error|fail|trigger|genuine|blacklist|peer|validate' /Library/Logs/parallels.log
```

### Key Log Patterns

| Log Pattern | Meaning |
|-------------|---------|
| `Task_StartVm.*PRL_ERR_SUCCESS` | VM start license check passed |
| `isProcessAlive: pid N exit status 0 (status 9)` | VM process killed by SIGKILL (code signing issue) |
| `hv_vm_create: 0xfae94007` | HV_DENIED — missing hypervisor entitlement |
| `Failed to validate peer` | VM rejects dispatcher (peer validation) |
| `check failed, disconnecting` | Dispatcher rejects client (client check) |
| `creds are invalid` | Dispatcher rejects VM credentials |
| `k=2b44` | VM storing JLIC error → triggers piracy later |
| `PRL_ERR_TRIGGERED` | Piracy dialog about to show |
| `Wrong type of client` | Dispatcher genuine GUI check failed |
| `Vm lifetime is expired` | License expiration timer fired |

### Process Management

```bash
# Dispatcher runs as ROOT — needs sudo to kill
sudo pkill -9 prl_disp_service

# Check if old dispatcher is still running (common gotcha!)
ps aux | grep prl_disp | grep -v grep

# The dispatcher auto-restarts when client launches
# Always kill + verify after patching
```

### Binary Analysis

```bash
# Disassemble ARM64
otool -arch arm64 -tV <binary> | grep -B20 '<string>'

# Find exported symbols (exact offsets for libPrlGui, libPrlXmlModel)
nm -arch arm64 <library> | grep '<function>'

# String offsets for cross-referencing
strings -t x -arch arm64 <binary> | grep '<string>'

# Verify patch bytes in fat binary
# ARM64 slice offset from: lipo -detailed_info <binary>
# File offset = slice_offset + function_offset
xxd -s $((slice_offset + func_offset)) -l 4 <binary>

# Parse fat header programmatically
python3 -c "
import struct
with open('<binary>','rb') as f:
    d=f.read(48)
    n=struct.unpack('>I',d[4:8])[0]
    for i in range(n):
        b=8+i*20
        ct,_,off,sz,_=struct.unpack('>IIIII',d[b:b+20])
        arch='arm64' if ct==0x0100000c else 'x86_64' if ct==0x01000007 else hex(ct)
        print(f'{arch}: offset=0x{off:x} size={sz}')
"
```

---

## Known Limitation: VM Networking (vmnet)

### The Problem

VMs start and run successfully but have **no network connectivity**. The error `PRL_NET_PRLNET_OPEN_FAILED` ("網路初始化失敗") appears in logs (suppressed from UI by our `showMessage→ret` patch).

### Root Cause

Parallels uses Apple's `vmnet` framework (`ApplevisorNet` wrapper) for VM networking on Apple Silicon. This requires the `com.apple.vm.networking` entitlement, which **cannot be used with ad-hoc signing** — AMFI sends SIGKILL (status 9), same as `com.apple.security.cs.disable-library-validation`.

The error chain:
```
prl_vm_app → vmnet_start_interface()
  → macOS checks entitlement → missing com.apple.vm.networking
    → callback returns error 1001
      → "Sending warning PRL_NET_PRLNET_OPEN_FAILED"
        → VM runs without network
```

### Why It Can't Be Fixed with Binary Patching

The `com.apple.security.hypervisor` entitlement is the **only** restricted entitlement that works with ad-hoc signing on Apple Silicon. Apple specifically allowed this for open-source hypervisors (QEMU, etc.). The `com.apple.vm.networking` entitlement was NOT given the same exception — it requires an Apple-approved provisioning profile tied to a real Developer ID.

### What We Tried

| Attempt | Result |
|---------|--------|
| Add `com.apple.vm.networking` to entitlements | AMFI SIGKILL — VM won't start at all |
| AMFIExemption kext (osy/GitHub) | Requires OpenCore bootloader — Apple Silicon real Mac can't use it |
| `amfi_get_out_of_my_way=1` boot-arg | Requires SIP disabled + reboot — disables all AMFI security |
| Patch vmnet_start_interface error handling | Suppresses warning but doesn't give actual network |

### How Other VM Software Handles This

| Software | Without entitlement | Mechanism |
|----------|-------------------|-----------|
| **UTM (App Store)** | Has entitlement | Apple-approved Developer ID + provisioning profile |
| **UTM (GitHub/self-built)** | Falls back to **Emulated VLAN** (slirp) | QEMU built-in userspace TCP/IP stack — no entitlement needed |
| **QEMU (Homebrew)** | No vmnet networking (same as us) | Ad-hoc signed, can't get entitlement |
| **VMware Fusion** | Has entitlement | Apple-approved Developer ID |
| **Parallels (official)** | Has entitlement | Apple-approved Developer ID |

**Key insight:** UTM/QEMU have a **slirp userspace networking fallback** that operates entirely in userspace without any macOS entitlements. Parallels has **no such fallback** on Apple Silicon — it's vmnet-only (`ApplevisorNet`).

### Current State

- VM runs normally without network (this is acceptable for the CTF)
- The `PRL_NET_PRLNET_OPEN_FAILED` dialog is suppressed by `CMessageProcessor::showMessage→ret`
- Error is logged in `/Library/Logs/parallels.log` and `~/Parallels/<VM>.pvm/parallels.log`

---

## Version Info

```
CFBundleVersion: 57373
CFBundleShortVersionString: 26.2.2
CFBundleIdentifier: com.parallels.desktop.console
Team ID: 4C6364ACXT (Parallels International GmbH)
Signature: Developer ID Application
Build date: Fri, 30 Jan 2026 16:42:51
LSMinimumSystemVersion: 13.3
```
