# Parallels Desktop 26.2.2 License Bypass — CTF Research Report

> **Target**: Question1(PD-Desktop).app — Parallels Desktop 26.2.2 (Build 57373)
> **Platform**: macOS (Universal Binary: x86_64 + arm64)
> **Category**: Reverse Engineering / Software Protection Analysis

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Research Methodology](#2-research-methodology)
3. [Application Architecture Analysis](#3-application-architecture-analysis)
4. [License Key Format Reverse Engineering](#4-license-key-format-reverse-engineering)
5. [License Validation Architecture (Three-Layer Model)](#5-license-validation-architecture-three-layer-model)
6. [JLIC Signature Verification Deep Dive](#6-jlic-signature-verification-deep-dive)
7. [Vulnerability Analysis](#7-vulnerability-analysis)
8. [Bypass Implementation](#8-bypass-implementation)
9. [Persistence Mechanism (Surviving Updates)](#9-persistence-mechanism-surviving-updates)
10. [Anti-Detection Measures](#10-anti-detection-measures)
11. [Script Usage Guide](#11-script-usage-guide)
12. [Additional Security Findings](#12-additional-security-findings)
13. [Appendix](#13-appendix)

---

## 1. Executive Summary

This report documents the complete reverse engineering process of the Parallels Desktop 26.2.2 license validation system. Through static binary analysis, disassembly, cross-reference tracing, and cryptographic analysis, a critical vulnerability was identified in the JLIC (JSON License) signature verification flow within the `prl_disp_service` daemon.

**Key Finding**: The RSA-2048 signature verification result is checked by a single conditional branch instruction in both x86_64 and arm64 architectures. By replacing this instruction with a NOP (No Operation), the signature check is effectively bypassed while maintaining full application stability.

**Bypass Method**: Binary Patch (2 bytes for x86_64, 4 bytes for arm64) + License File Modification + LaunchDaemon Persistence

---

## 2. Research Methodology

### 2.1 Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Binary format identification |
| `otool -tV` | Mach-O disassembly (ARM64/x86_64) |
| `otool -l` | Mach-O load command inspection |
| `otool -L` | Linked library enumeration |
| `nm` | Symbol table extraction |
| `strings` | Embedded string extraction |
| `xxd` | Hex dump / byte-level inspection |
| `lipo` | Fat binary slice analysis |
| `codesign` | Code signature inspection and ad-hoc signing |
| `python3` | Cross-reference analysis, patch scripting, RSA verification |
| `/usr/libexec/PlistBuddy` | Property list inspection |

### 2.2 Research Phases

The research was conducted in six systematic phases:

```
Phase 1: Reconnaissance     → Identify application structure, key binaries, frameworks
Phase 2: String Analysis     → Extract license-related strings, error codes, class names
Phase 3: Symbol Analysis     → Map C++ class hierarchy and method signatures
Phase 4: Disassembly         → Reverse critical functions (signature verification)
Phase 5: Cross-Reference     → Trace from error strings back to conditional branches
Phase 6: Exploit Development → Develop and verify binary patches
```

### 2.3 Phase 1: Reconnaissance

The first step was understanding the application bundle structure:

```
Question1(PD-Desktop).app/
├── Contents/
│   ├── Info.plist                          ← App metadata (v26.2.2, build 57373)
│   ├── MacOS/
│   │   ├── prl_client_app                  ← Main GUI (57.5 MB, universal binary)
│   │   ├── Parallels Service.app/
│   │   │   └── Contents/MacOS/
│   │   │       └── prl_disp_service        ← ★ License validation daemon
│   │   ├── prlsrvctl                       ← CLI license management tool
│   │   └── prlctl                          ← VM control tool
│   └── Frameworks/
│       ├── libPrlGui.3.dylib               ← GUI license classes (10.1 MB)
│       ├── libDaApiWrap.1.dylib            ← Data API wrapper (3.7 MB)
│       ├── libPrlXmlModel.1.dylib          ← XML/license data model (21.8 MB)
│       └── ParallelsVirtualizationSDK.framework/
│           └── libprl_sdk.11.dylib         ← SDK license APIs
```

**Critical insight**: The GUI application (`prl_client_app`) merely sends license keys to the background service (`prl_disp_service`) via IPC. All actual validation happens in the service daemon.

### 2.4 Phase 2: String Mining

Systematic string extraction was performed on all binaries using targeted regex patterns:

```bash
strings prl_client_app | grep -iE 'license|serial|activ|valid|key|trial|expire'
strings prl_disp_service | grep -iE 'license|signature|jlic|loaded|failed'
strings libPrlGui.3.dylib | grep -iE 'CLicense|Activation|CheckKey'
```

This yielded three categories of intelligence:

**a) C++ Class/Method Names** (via name mangling):
- `CLicenseKeyFormatter` — Client-side key formatting
- `CLicenseManager` / `CLicenseManagerPrivate` — License state management
- `CTaskValidateLicense` / `CTaskValidatePrlLicense` — Validation task objects
- `CTaskCheckForProductUpdate` — Update-time license checking
- `CLicenseWrap` / `CLicenseWizardModel` — License data wrappers

**b) Error Messages**:
- `"Signature check failed for license info"` — RSA verification failure
- `"unable to parse license info"` — JSON parsing failure
- `"loaded license state: [%s], %s (%#x)"` — License loading debug log

**c) Error Code Constants** (90+ license-related codes identified):
- `PRL_ERR_JLIC_SIGNATURE_CHECK_ERROR` — Signature validation failed
- `PRL_ERR_LICENSE_BLACKLISTED` — Key on blacklist
- `PRL_ERR_ACTIVATION_SERVER_HWIDS_AMOUNT_REACHED` — Hardware ID limit
- `PRL_ERR_LICENSE_NOT_VALID` — General validation failure

---

## 3. Application Architecture Analysis

### 3.1 Component Interaction Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                        User Interface                               │
│  ┌──────────────────┐   ┌────────────────┐   ┌──────────────────┐  │
│  │ prl_client_app   │   │ CLicenseKey    │   │ ActivationPage   │  │
│  │ (Main GUI)       │──▶│ Formatter      │──▶│ .qml             │  │
│  │                  │   │ [Format Only]  │   │ [UI Input]       │  │
│  └──────┬───────────┘   └────────────────┘   └──────────────────┘  │
│         │ IPC (PrlSrv_UpdateLicenseEx)                              │
├─────────┼───────────────────────────────────────────────────────────┤
│         ▼                     Service Layer                         │
│  ┌──────────────────┐   ┌────────────────┐   ┌──────────────────┐  │
│  │ prl_disp_service │   │ DspLicense     │   │ JLIC Engine      │  │
│  │ (Dispatcher)     │──▶│ (License State)│──▶│ [RSA-2048 Verify]│  │
│  │                  │   │                │   │ [SHA-256 Hash]   │  │
│  └──────┬───────────┘   └────────────────┘   └──────────────────┘  │
│         │ HTTPS/SOAP                                                │
├─────────┼───────────────────────────────────────────────────────────┤
│         ▼                     Server Layer                          │
│  ┌──────────────────┐   ┌────────────────┐                         │
│  │ Protexis Web     │   │ Parallels Web  │                         │
│  │ Service (SOAP)   │   │ Portal (REST)  │                         │
│  │ [Download Auth]  │   │ [Key Activate] │                         │
│  └──────────────────┘   └────────────────┘                         │
├─────────────────────────────────────────────────────────────────────┤
│                        Storage Layer                                │
│  /Library/Preferences/Parallels/licenses.json                       │
│  ┌─────────────────────────────────────────┐                       │
│  │ { "license": "<JSON>", "signature": "<RSA-2048 Base64>" }      │
│  └─────────────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 Binary Architecture Details

```
prl_disp_service: Mach-O universal binary with 2 architectures
  ├── x86_64 slice: offset 0x4000, size 8,493,872 bytes
  └── arm64 slice:  offset 0x820000, size 8,646,208 bytes

Code signing: Developer ID Application: Parallels International GmbH (4C6364ACXT)
Flags: library-validation, runtime (Hardened Runtime)
```

### 3.3 License File Location and Format

**Path**: `/Library/Preferences/Parallels/licenses.json`

```json
{
    "license": "<JSON string — signed content>",
    "signature": "<Base64-encoded RSA-2048 signature>"
}
```

The `license` field is a JSON-encoded string containing all license metadata. The `signature` field is the RSA digital signature of this exact string (256 bytes = 2048-bit RSA, Base64-encoded).

---

## 4. License Key Format Reverse Engineering

### 4.1 CLicenseKeyFormatter Analysis

The license key input formatting is handled by `CLicenseKeyFormatter` in `libPrlGui.3.dylib`. Through disassembly of the constructor (`0x53344`) and `onTextChanged` method (`0x53D00`):

**Constructor** (`CLicenseKeyFormatterC2`):
```asm
; Load KeyParams struct (numGroups, charsPerGroup)
0x53384: ldr  x8, [x21]          ; x8 = *(KeyParams*) = {numGroups, charsPerGroup}
0x53388: str  x8, [x0, #0x18]    ; Store at this+0x18

; Calculate max input length
0x534AC: ldp  w8, w9, [x19, #0x18] ; w8 = numGroups, w9 = charsPerGroup
0x534B0: madd w8, w8, w9, w8       ; maxLen = numGroups * charsPerGroup + numGroups
0x534B4: sub  w1, w8, #0x1         ; maxLen -= 1 (dashes between groups, not after last)
0x534B8: bl   QLineEdit::setMaxLength
```

**Formula**: `maxLength = numGroups × charsPerGroup + numGroups − 1`

For the standard Parallels key: `6 × 5 + 6 − 1 = 35` characters → `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`

### 4.2 Input Sanitization

The paste/input sanitization subroutine (at `0x53B30`) performs:

1. `QString::trimmed_helper()` — Trim whitespace
2. `QString::toUpper_helper()` — Convert to uppercase
3. Strip non-alphanumeric characters using regex `[^A-Z0-9]`
4. Replace all matches with empty string

**Allowed character set**: `A-Z` (26) + `0-9` (10) = **36-character alphabet**

### 4.3 Key Format Summary

| Property | Value |
|----------|-------|
| Groups | 6 |
| Characters per group | 5 |
| Separator | Dash (`-`) |
| Total length | 35 characters (30 alphanum + 5 dashes) |
| Character set | `[A-Z0-9]` |
| Example | `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` |

---

## 5. License Validation Architecture (Three-Layer Model)

### 5.1 Layer 1 — Client-Side Format Validation (Local)

**Binary**: `libPrlGui.3.dylib` → `CLicenseKeyFormatter`

This layer performs **format-only validation**:
- Character whitelist enforcement (`[A-Z0-9]`)
- Group count and group size enforcement via `KeyParams`
- Auto-formatting with dash insertion
- No cryptographic validation whatsoever

**Signal flow**:
```
QLineEdit::textChanged → CLicenseKeyFormatter::onTextChanged
  → sanitize → insert dashes → emit keyChanged(QString)
  → if full length reached: emit lastSymbolEntered()
```

### 5.2 Layer 2 — Service-Side Validation (Local Daemon)

**Binary**: `prl_disp_service` → JLIC Engine

When the GUI submits a key, it calls `PrlSrv_UpdateLicenseEx()` (exported from `libprl_sdk.11.dylib`), which sends the key to the dispatcher service via IPC.

The dispatcher:
1. Contacts the Parallels activation server via HTTPS
2. Receives a signed license response
3. Writes the response to `/Library/Preferences/Parallels/licenses.json`
4. Verifies the RSA-2048 signature locally

**License loading flow** (from strings):
```
"loaded license: %s"
"loaded license state: [%s], %s (%#x)"
"License has been changed. New license = %s"
"License status has been changed."
```

### 5.3 Layer 3 — Server-Side Validation (Remote)

**Protocol**: SOAP over HTTPS (Protexis web services)

Embedded SOAP template found in binary:
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:web="http://protexis.com/webservices">
   <soapenv:Header/>
   <soapenv:Body>
      <web:DownloadAuthorizationRequest>
         <web:DownloadToken>%1</web:DownloadToken>
         <web:MachineId>%2</web:MachineId>
         <web:DownloadId/>
         <web:DecryptionKeyRequired>false</web:DecryptionKeyRequired>
      </web:DownloadAuthorizationRequest>
   </soapenv:Body>
</soapenv:Envelope>
```

The server validates:
- Key authenticity and blacklist status
- Hardware ID (HWID) binding and activation limits
- Product version, platform, and edition compatibility
- Subscription status and expiration dates

### 5.4 Four Authorization Key Types

Found via string analysis:

| Key Type | Field Name | Purpose |
|----------|------------|---------|
| Master License Key | `AuthorizationMasterLicKey` | Primary permanent license |
| Temporary Key | `AuthorizationTemporaryLicKey` | Time-limited license |
| KA PDE Key | `AuthorizationKaPdeKey` | Key Activation system key |
| Instance Key Number | `AuthorizationKaPdeInstanceKeyNumber` | Per-installation identifier |

### 5.5 Server Response Structure (CDownloadedKeyInfo)

Found by examining mandatory XML tags in `libPrlXmlModel.1.dylib`:

```
Required fields (20 total):
  Key, HwId, ProductName, LicenseEdition, LicenseProduct, LicenseVersion,
  ExpirationDate, RegistrationDate, GracePeriodStartDate, AutoRenewable,
  Trial, Enterprise, Upgrade, Lite, ActiveHere, HwidLimitReached,
  SubscriptionUuid, LicenseCount, AppstoreProductId, AppstoreGroupNumber
```

---

## 6. JLIC Signature Verification Deep Dive

### 6.1 License File Cryptographic Analysis

**Signature algorithm**: RSA-2048 with PKCS#1 v1.5 padding and SHA-256 hash

```python
# Verification:
signature = base64.b64decode(signature_b64)
len(signature)  # → 256 bytes (2048-bit RSA)

# The signed data is the raw UTF-8 bytes of the "license" JSON string value
sha256 = hashlib.sha256(license_str.encode('utf-8')).hexdigest()
# → "f6fbd56dfebf984f7ab2387c9bc2704fc69cb55b094bbbc1ef5ebe28f7c3778b"
```

### 6.2 Locating the Signature Verification Function

**Step 1**: Find the error string in the binary.

```bash
strings -t x prl_disp_service | grep 'Signature check failed'
# arm64 slice: file offset 0xEE1708 (slice offset 0x6C1708)
```

**Step 2**: Calculate the virtual address.

```
__cstring section: file_offset = 0x6A6F28, virtual_addr = 0x1006A6F28
String virtual address = 0x1006A6F28 + (0x6C1708 - 0x6A6F28) = 0x1006C1708
```

**Step 3**: Find cross-references using ADRP+ADD pattern matching.

In ARM64, string references use a two-instruction pattern:
```asm
ADRP Xn, page                ; Load page address (4KB-aligned)
ADD  Xn, Xn, #page_offset    ; Add page offset
```

A Python script scanned all ARM64 code for ADD instructions with immediate `0x708` (the page offset of our string), then verified the preceding ADRP instruction produces page `0x1006C1`:

```
CONFIRMED: xref at arm64 offset 0x2BDA84 (ADRP) + 0x2BDA88 (ADD)
  → References 0x1006C1708 = 'Signature check failed for license info'
```

**Step 4**: Trace back to find the conditional branch.

Disassembling backwards from the error string reference revealed the complete verification flow:

### 6.3 Complete Verification Function (ARM64)

```asm
; ═══════════════════════════════════════════════════════════
; License Verification Function — arm64
; Address: 0x1002BD92C
; Parameters: x0=this, x1=license_json, x2=signature, x3=flags
; ═══════════════════════════════════════════════════════════

; ─── Function Prologue ───
0x1002BD92C: sub  sp, sp, #0x80
0x1002BD930: stp  x24, x23, [sp, #0x40]
0x1002BD934: stp  x22, x21, [sp, #0x50]
0x1002BD938: stp  x20, x19, [sp, #0x60]
0x1002BD93C: stp  x29, x30, [sp, #0x70]
0x1002BD940: add  x29, sp, #0x70

; ─── Save Parameters ───
0x1002BD944: mov  x22, x3            ; x22 = flags
0x1002BD948: mov  x20, x2            ; x20 = signature data
0x1002BD94C: mov  x21, x1            ; x21 = license JSON string
0x1002BD950: mov  x19, x0            ; x19 = this pointer

; ─── CALL RSA SIGNATURE VERIFICATION ───
0x1002BD954: mov  x0, x1             ; arg0 = license JSON
0x1002BD958: mov  x1, x2             ; arg1 = signature
0x1002BD95C: bl   0x1004D5294        ; ★ RSA-2048 verification function

; ═══════════════════════════════════════════════════════════
; ★★★ CRITICAL BRANCH — THE PATCH POINT ★★★
; ═══════════════════════════════════════════════════════════
0x1002BD960: tbz  w0, #0, 0x1002BDA74
;            ^^^  ^^^  ^^  ^^^^^^^^^^^^
;            │    │    │   └─ Target: "Signature check failed" error handler
;            │    │    └───── Test bit 0
;            │    └────────── w0 = return value from RSA verification
;            └─────────────── TBZ = Test Bit and Branch if Zero
;
; If w0 bit 0 == 0 (verification FAILED) → branch to error at 0xBDA74
; If w0 bit 0 == 1 (verification PASSED) → fall through to success path

; ─── SUCCESS PATH: Parse License JSON ───
0x1002BD964: add  x24, sp, #0x18
0x1002BD968: add  x0, sp, #0x18
0x1002BD96C: bl   QJsonObjectC1Ev    ; Construct QJsonObject
    ...
0x1002BD988: bl   0x1003548F8        ; Parse license JSON into fields
0x1002BD98C: tbz  w0, #0, 0x1002BDA9C  ; If parse fails → "unable to parse"
0x1002BD990: tbz  w22, #1, 0x1002BD9F8  ; Check flags bit 1
    ...                                  ; Check "offline" field
    ...                                  ; Check "is_trial" field

; ─── ERROR PATH: Signature Check Failed ───
0x1002BDA74: adrp x0, ...             ; Load "" (empty string)
0x1002BDA78: add  x0, x0, #0xF28
0x1002BDA7C: adrp x1, ...             ; Load "disp"
0x1002BDA80: add  x1, x1, #0xF29
0x1002BDA84: adrp x3, ...             ; Load "Signature check failed..."
0x1002BDA88: add  x3, x3, #0x708
0x1002BDA8C: mov  w2, #0x0
0x1002BDA90: bl   log_function        ; Log the error
0x1002BDA94: mov  w20, #-0xDEAA       ; w20 = 0xFFFF2156 = PRL_ERR_JLIC_SIGNATURE_CHECK_ERROR
```

### 6.4 Complete Verification Function (x86_64)

```asm
; ═══════════════════════════════════════════════════════════
; License Verification Function — x86_64
; Address: 0x10029FE30
; ═══════════════════════════════════════════════════════════

; ─── Function Prologue ───
0x10029FE30: pushq  %rbp
0x10029FE31: movq   %rsp, %rbp
0x10029FE34: pushq  %r15
0x10029FE36: pushq  %r14
0x10029FE38: pushq  %r13
0x10029FE3A: pushq  %r12
0x10029FE3C: pushq  %rbx
0x10029FE3D: subq   $0x48, %rsp

; ─── Save Parameters ───
0x10029FE41: movl   %ecx, %r12d       ; r12d = flags
0x10029FE44: movq   %rdx, %r14        ; r14 = signature
0x10029FE47: movq   %rsi, %r15        ; r15 = license JSON
0x10029FE4A: movq   %rdi, %rbx        ; rbx = this

; ─── CALL RSA SIGNATURE VERIFICATION ───
0x10029FE4D: movq   %rsi, %rdi        ; arg0 = license JSON
0x10029FE50: movq   %rdx, %rsi        ; arg1 = signature
0x10029FE53: callq  0x1004A2D00       ; ★ RSA-2048 verification function

; ═══════════════════════════════════════════════════════════
; ★★★ CRITICAL BRANCH — THE PATCH POINT ★★★
; ═══════════════════════════════════════════════════════════
0x10029FE58: testb  %al, %al          ; Test return value (low byte)
0x10029FE5A: je     0x10029FED1       ; ★ If al==0 (FAILED) → jump to error
;                                     ;   If al!=0 (PASSED) → fall through

; ─── SUCCESS PATH ───
0x10029FE5C: leaq   -0x68(%rbp), %r13
    ...                                ; Parse JSON, check fields

; ─── ERROR PATH ───
0x10029FED1: movl   $0xFFFF2156, %r13d ; PRL_ERR_JLIC_SIGNATURE_CHECK_ERROR
0x10029FED7: leaq   ...(%rip), %rdi    ; ""
0x10029FEDE: leaq   ...(%rip), %rsi    ; "disp"
0x10029FEE5: leaq   ...(%rip), %rcx    ; "Signature check failed for license info"
```

### 6.5 RSA Implementation Details

The RSA verification function (arm64: `0x1004D5294`, x86_64: `0x1004A2D00`) is a statically linked implementation:
- Uses Montgomery multiplication for modular exponentiation
- SHA-256 implementation with SSE PSHUFB optimization (x86_64)
- PKCS#1 v1.5 padding verification (00 01 FF..FF 00 DigestInfo)
- Public exponent e = 65537 (0x10001)

---

## 7. Vulnerability Analysis

### 7.1 Primary Vulnerability — Single-Point Signature Check

The entire RSA-2048 signature verification result is controlled by a **single conditional branch instruction**:

| Architecture | Instruction | Bytes | Effect |
|---|---|---|---|
| ARM64 | `TBZ W0, #0, 0x1002BDA74` | `A0 08 00 36` | Branch to error if bit 0 = 0 |
| x86_64 | `JE 0x10029FED1` | `74 75` | Jump to error if ZF = 1 |

By replacing these with NOP instructions, the verification function is still called (avoiding crashes from missing function calls), but its return value is **completely ignored**.

### 7.2 Secondary Vulnerability — Stubbed Update Check Functions

Two critical functions in `libPrlGui.3.dylib` are already stubbed out:

```asm
; CTaskCheckForProductUpdate::isNeedCheckLicense() — Always returns FALSE
0x000CD644: mov  w0, #0x0    ; return false
0x000CD648: ret

; CTaskCheckForProductUpdate::checkLicense() — Returns skip code 0x3BFA
0x000CD6D4: mov  w0, #0x3BFA ; return 15354 (skip code)
0x000CD6D8: ret
```

This means the **product update flow never triggers a license revalidation**. Even if Parallels Desktop checks for updates, the license is never re-examined.

### 7.3 Tertiary Vulnerability — Hardcoded OAuth Secret

A Google OAuth client secret was found in plaintext in `libPrlGui.3.dylib`:

```
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
```

Associated with OAuth endpoints:
```
https://accounts.google.com/o/oauth2/v2/auth
https://www.googleapis.com/oauth2/v4/token
https://www.googleapis.com/oauth2/v3/userinfo
```

### 7.4 Vulnerability Severity Matrix

| Vulnerability | Severity | Exploitability | Impact |
|---|---|---|---|
| Single-branch signature check | Critical | High (2-4 byte patch) | Complete bypass |
| Stubbed update check | High | Already exploitable | Update persistence |
| Hardcoded OAuth secret | Medium | Direct credential use | Account compromise |
| No client-side crypto | Medium | Format-only validation | Easy key crafting |

---

## 8. Bypass Implementation

### 8.1 Patch Definition

The bypass requires modifying exactly **6 bytes** across the entire application:

**Patch #1 — x86_64** (2 bytes):
```
File offset: 0x2A3E5A
Original:    74 75          (JE +0x75 → error handler)
Patched:     90 90          (NOP NOP)
```

**Patch #2 — ARM64** (4 bytes):
```
File offset: 0xADD960
Original:    A0 08 00 36    (TBZ W0, #0, +0x114 → error handler)
Patched:     1F 20 03 D5    (NOP)
```

### 8.2 Why NOP Instead of Other Approaches

| Approach | Pros | Cons |
|---|---|---|
| **NOP the branch** ✓ | Minimal change; RSA function still called | Must re-apply after binary update |
| Patch RSA function to return 1 | Also minimal | Changes function semantics |
| Replace public key | License file looks valid | Must find key in Montgomery format |
| DYLD_INSERT_LIBRARIES hook | No binary changes | Blocked by Hardened Runtime |
| MITM activation server | No file changes | Requires network interception |

The NOP approach was chosen because:
1. **Smallest possible change** (6 bytes total)
2. **RSA function is still called** — no crash risk from missing function calls
3. **Original signature is preserved** in the license file
4. **Binary structure is maintained** — no section size changes

### 8.3 License File Modification

After disabling signature verification, the license JSON can be freely modified:

| Field | Original | Modified | Purpose |
|---|---|---|---|
| `main_period_ends_at` | `2027-02-28 11:51:38` | `2036-03-12 11:46:35` | Extend 10 years |
| `grace_period_ends_at` | `2027-03-07 11:51:38` | `2036-03-19 11:46:35` | Extend 10 years |
| `is_expired` | `false` | `false` | Ensure not expired |
| `is_trial` | `false` | `false` | Ensure not trial |
| `is_suspended` | `false` | `false` | Ensure not suspended |
| `edition` | `3` | `3` | Pro edition |
| `limit` | `1` | `999` | Increase activation limit |
| `cpu_limit` | `32` | `128` | Increase CPU limit |
| `ram_limit` | `131072` | `524288` | Increase to 512 GB |

The `signature` field is left unchanged (the original valid signature from the activation server). Since the signature check is NOPed, any signature value will be accepted.

### 8.4 Code Re-signing

After modifying the binary, the original Apple Developer ID signature becomes invalid. The binary must be re-signed:

```bash
# 1. Remove the original Parallels International GmbH signature
codesign --remove-signature prl_disp_service

# 2. Apply ad-hoc signature (signed with local identity "-")
codesign -fs - prl_disp_service

# 3. Re-sign the enclosing app bundles (deep signing)
codesign -fs - --deep "Parallels Service.app"
codesign -fs - --deep "Question1(PD-Desktop).app"
```

**Note**: Ad-hoc signing allows macOS to load the binary locally. The `library-validation` flag in the original code signature required libraries to be signed by the same team, but ad-hoc signing bypasses this requirement for local execution.

---

## 9. Persistence Mechanism (Surviving Updates)

### 9.1 Why Updates Don't Reset the License

The license bypass is designed with three persistence layers:

**Layer A — License File Persistence**:
- The license file (`/Library/Preferences/Parallels/licenses.json`) is stored outside the app bundle
- Application updates replace the `.app` bundle but **do not touch system preferences**
- The modified license file with extended dates survives any app update

**Layer B — Stubbed Update Check**:
- `CTaskCheckForProductUpdate::isNeedCheckLicense()` returns `false`
- `CTaskCheckForProductUpdate::checkLicense()` returns `0x3BFA` (skip)
- Even during an update check, the license is **never re-validated**
- These stubs are in `libPrlGui.3.dylib`, which may or may not be replaced during updates

**Layer C — Automatic Re-patching (LaunchDaemon)**:

A `WatchPaths` LaunchDaemon monitors the `prl_disp_service` binary for changes:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ctf.parallels.patch.watcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/reapply_patch.sh</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>/path/to/prl_disp_service</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
```

When the binary is replaced (e.g., by an update), macOS triggers the LaunchDaemon, which:
1. Checks if the binary has been reverted to original (`A0 08 00 36`)
2. If so, re-applies both patches
3. Re-signs the binary with ad-hoc signature

### 9.2 Re-patching Script Logic

```bash
#!/bin/bash
# Check if patch needs re-application
ARM64_CHECK=$(xxd -s 0xADD960 -l 4 "$BINARY" | awk '{print $2$3}')

if [ "$ARM64_CHECK" = "a0080036" ]; then
    # Binary updated — re-apply patches
    printf '\x1f\x20\x03\xd5' | dd of="$BINARY" bs=1 seek=$((0xADD960)) conv=notrunc
    printf '\x90\x90' | dd of="$BINARY" bs=1 seek=$((0x2A3E5A)) conv=notrunc
    codesign --remove-signature "$BINARY"
    codesign -fs - "$BINARY"
elif [ "$ARM64_CHECK" = "1f2003d5" ]; then
    # Patch still active
    exit 0
fi
```

---

## 10. Anti-Detection Measures

### 10.1 Why This Bypass is Difficult to Detect

| Detection Method | Status | Explanation |
|---|---|---|
| Binary hash comparison | ⚠️ Detectable | Binary hash differs; mitigated by re-signing |
| Code signature verification | ✅ Passes | Ad-hoc signature is valid on macOS |
| Runtime integrity check | ✅ Evades | RSA function is still called normally |
| License file structure | ✅ Evades | JSON structure, signature format all valid |
| Network traffic analysis | ✅ Evades | No outbound activation traffic generated |
| API return value check | ✅ Evades | Verification function executes normally |
| Stack trace analysis | ✅ Evades | Call stack is identical to normal flow |

### 10.2 Stealth Design Decisions

1. **RSA function is NOT skipped** — We NOP the *result check*, not the function call. The RSA verification still executes fully (modular exponentiation, PKCS#1 padding check, SHA-256 hash comparison). Only the branch that checks `w0`/`al` is removed.

2. **Original signature preserved** — The license file retains the original RSA signature from the legitimate activation server. If any code reads the signature for logging/telemetry purposes, it will find a valid-looking Base64 string.

3. **License JSON structure intact** — All required fields (`Key`, `HwId`, `ProductName`, etc.) are present. The file passes JSON schema validation.

4. **No environment variable hooks** — Unlike `DYLD_INSERT_LIBRARIES` approaches, this bypass doesn't rely on environment variables that could be detected.

5. **No new files in app bundle** — All modifications are to existing files. No new dylibs, plists, or executables are added to the app bundle.

---

## 11. Script Usage Guide

### 11.1 Prerequisites

- macOS 13.3 or later (as required by the app)
- Python 3.8+
- Xcode Command Line Tools (for `codesign`, `otool`)
- Administrator access (for modifying `/Library/Preferences/`)

### 11.2 Files Provided

```
InfoSec-Invitation-Problem/
├── bypass.py                    ← Main bypass automation script
├── reapply_patch.sh             ← Post-update re-patching script
├── licenses_patched.json        ← Modified license file (10-year expiry)
├── REPORT.md                    ← This report
└── Question1(PD-Desktop).app/   ← Target application (modified in-place)
```

### 11.3 Step-by-Step Execution

#### Step 1: Apply Binary Patches and Re-sign (No Root Required)

```bash
cd /Users/jamie/Downloads/InfoSec-Invitation-Problem
python3 bypass.py
```

**Expected output**:
```
[1] Patching binary: prl_disp_service
  [+] x86_64: NOP the JE after signature verification
      Offset 0x2A3E5A: 7475 -> 9090
  [+] arm64: NOP the TBZ W0,#0 after signature verification
      Offset 0xADD960: a0080036 -> 1f2003d5

[3] Re-signing binaries
  [+] prl_disp_service re-signed: OK
  [+] App bundle re-signed: OK

[5] Verification
  [PASS] x86_64: JE -> NOP NOP: 9090
  [PASS] arm64: TBZ -> NOP: 1f2003d5
```

#### Step 2: Apply Modified License (Root Required)

```bash
sudo cp licenses_patched.json /Library/Preferences/Parallels/licenses.json
```

This replaces the license file with one that has:
- Expiration extended to 2036
- Pro edition enabled
- Trial/expired/suspended flags cleared
- CPU/RAM limits increased

#### Step 3: Install Persistence LaunchDaemon (Optional, Root Required)

```bash
# Copy the LaunchDaemon plist
sudo cp com.ctf.parallels.patch.watcher.plist /Library/LaunchDaemons/

# Load the LaunchDaemon
sudo launchctl load /Library/LaunchDaemons/com.ctf.parallels.patch.watcher.plist
```

This will automatically re-apply patches if the binary is replaced by an update.

#### Step 4: Verify the Bypass

```bash
# Check binary patches
xxd -s 0xADD960 -l 4 "Question1(PD-Desktop).app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service"
# Expected: 1f20 03d5 (NOP)

xxd -s 0x2A3E5A -l 2 "Question1(PD-Desktop).app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service"
# Expected: 9090 (NOP NOP)

# Check code signature
codesign --verify "Question1(PD-Desktop).app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service"
# Expected: (no output = valid)

# Check license file
python3 -c "
import json
with open('/Library/Preferences/Parallels/licenses.json') as f:
    d = json.load(f)
inner = json.loads(d['license'])
print(f'Expires: {inner[\"main_period_ends_at\"]}')
print(f'Trial: {inner[\"is_trial\"]}')
print(f'Expired: {inner[\"is_expired\"]}')
"
```

### 11.4 Reverting the Bypass

To restore the original state:

```bash
# Restore original binary
cp "Question1(PD-Desktop).app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service.ctf_backup" \
   "Question1(PD-Desktop).app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service"

# Re-sign with ad-hoc (original Parallels signature can't be restored)
codesign -fs - --deep "Question1(PD-Desktop).app"

# Remove LaunchDaemon
sudo launchctl unload /Library/LaunchDaemons/com.ctf.parallels.patch.watcher.plist
sudo rm /Library/LaunchDaemons/com.ctf.parallels.patch.watcher.plist
```

---

## 12. Additional Security Findings

### 12.1 Complete PRL_ERR License Error Code Catalog

During string analysis, 90+ license-related error codes were extracted. Key categories:

**Activation Errors** (18 codes):
```
PRL_ERR_ACTIVATION_COMMON_SERVER_ERROR
PRL_ERR_ACTIVATION_HTTP_REQUEST_FAILED
PRL_ERR_ACTIVATION_SERVER_ACTIVATION_ID_IS_INVALID
PRL_ERR_ACTIVATION_SERVER_HWIDS_AMOUNT_REACHED
PRL_ERR_ACTIVATION_SERVER_KEY_IS_INVALID
PRL_ERR_ACTIVATION_WRONG_CONFIRMATION_SIGNATURE
PRL_ERR_ACTIVATION_WRONG_SERVER_RESPONSE
...
```

**License Restriction Errors** (20+ codes):
```
PRL_ERR_LICENSE_RESTRICTED_TO_RUNNING_VMS_LIMIT
PRL_ERR_LICENSE_RESTRICTED_TO_SNAPSHOT_CREATE
PRL_ERR_LICENSE_RESTRICTED_GUEST_OS
PRL_ERR_LICENSE_TOO_MANY_VCPUS
PRL_ERR_LICENSE_TOO_MANY_MEMORY
PRL_ERR_LICENSE_VM_HAS_VTD_DEVICES
...
```

**Web Portal Errors** (20+ codes):
```
PRL_ERR_WEB_PORTAL_LIC_MASTER_KEY_BLACKLISTED
PRL_ERR_WEB_PORTAL_LIC_MASTER_KEY_LIMIT_REACHED
PRL_ERR_WEB_PORTAL_LIC_KEY_NOT_FOR_EXTENDING
PRL_ERR_WEB_PORTAL_LIC_SSO_CANT_ACTIVATE_LIC_KEY
...
```

### 12.2 CLI License Management Interface

The `prlsrvctl` binary exposes a command-line license management interface:

```bash
prlsrvctl install-license -k <key> [-n <name>] [-c <company>] [--deferred]
prlsrvctl deferred-license <--install | --remove>
prlsrvctl update-license
prlsrvctl deactivate-license [--skip-network-errors]
prlsrvctl info --license
```

### 12.3 Activation UI Flow

The QML-based activation page (`qrc:/qml/ActivationPage.qml`) uses two key fields:
- `primaryKeyEdit` — Main license key input (with `CLicenseKeyFormatter`)
- `secondaryKeyEdit` — Secondary key input (conditionally visible)

Signal flow:
```
primaryKeyEdit.keyChanged → onPrimaryKeyChanged →
  validateKey (async) → onCheckKeyFinished(PRL_RESULT)
```

---

## 13. Appendix

### 13.1 Hex Dump — Patch Points (Before/After)

**x86_64 — Before (Original)**:
```
002A3E54: A82E 2000 84C0 7475 4C8D 6D98 4C89 EFE8
                         ~~~~
                    testb  JE
                    %al   +0x75 → error
```

**x86_64 — After (Patched)**:
```
002A3E54: A82E 2000 84C0 9090 4C8D 6D98 4C89 EFE8
                         ~~~~
                    testb  NOP
                    %al   NOP
```

**arm64 — Before (Original)**:
```
00ADD95C: 4E5E 0894 A008 0036 F863 0091 E063 0091
                    ~~~~~~~~~
                    TBZ W0, #0, +0x114
```

**arm64 — After (Patched)**:
```
00ADD95C: 4E5E 0894 1F20 03D5 F863 0091 E063 0091
                    ~~~~~~~~~
                    NOP
```

### 13.2 File Offset Calculations

**ARM64**:
```
Fat binary arm64 slice starts at:    0x820000
Instruction virtual address:         0x1002BD960
Instruction offset within slice:     0x2BD960
Absolute file offset:                0x820000 + 0x2BD960 = 0xADD960
```

**x86_64**:
```
Fat binary x86_64 slice starts at:   0x4000
__TEXT.__text section address:        0x10000A440
__TEXT.__text section file offset:    0xA440 (absolute in fat binary)
Instruction virtual address:         0x10029FE5A
Absolute file offset:                0xA440 + (0x10029FE5A - 0x10000A440) = 0x2A3E5A
```

### 13.3 RSA Signature Verification Parameters

```
Algorithm:      RSA-2048 (PKCS#1 v1.5)
Hash:           SHA-256
Key size:       2048 bits (256 bytes)
Public exponent: 65537 (0x10001)
Signature size: 256 bytes (Base64: 344 characters)
Error code:     0xFFFF2156 (-57002) = PRL_ERR_JLIC_SIGNATURE_CHECK_ERROR
```

### 13.4 License JSON Schema

```json
{
  "name":                    "string",
  "uuid":                    "hex string (32 chars)",
  "lic_key":                 "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (partially masked)",
  "product_version":         "string or *",
  "is_upgrade":              "boolean",
  "is_sublicense":           "boolean",
  "parent_key":              "string or null",
  "parent_uuid":             "string or null",
  "main_period_ends_at":     "YYYY-MM-DD HH:MM:SS",
  "grace_period_ends_at":    "YYYY-MM-DD HH:MM:SS",
  "is_auto_renewable":       "boolean",
  "is_nfr":                  "boolean",
  "is_beta":                 "boolean",
  "is_china":                "boolean",
  "is_suspended":            "boolean",
  "is_expired":              "boolean",
  "is_grace_period":         "boolean",
  "is_purchased_online":     "boolean",
  "limit":                   "integer",
  "usage":                   "integer",
  "edition":                 "integer (3=Pro)",
  "platform":                "integer (3=macOS)",
  "product":                 "integer (7=Desktop)",
  "offline":                 "boolean",
  "is_bytebot":              "boolean",
  "cpu_limit":               "integer",
  "ram_limit":               "integer (MB)",
  "is_trial":                "boolean",
  "is_enterprise":           "boolean",
  "hosts": [{
    "name":                  "string (GDPR_HIDDEN)",
    "hw_id":                 "hex string (32 chars, MD5 of system UUID)",
    "product_version":       "string (26.2.2-57373)",
    "activated_at":          "YYYY-MM-DD HH:MM:SS"
  }],
  "started_at":              "YYYY-MM-DD HH:MM:SS",
  "cep_option":              "boolean"
}
```

---

*Report generated for CTF White-Hat Security Competition — Question 1 (Parallels Desktop)*
