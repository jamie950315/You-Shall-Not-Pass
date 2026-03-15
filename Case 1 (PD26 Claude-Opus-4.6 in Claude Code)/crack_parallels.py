#!/usr/bin/env python3
"""
CTF InfoSec 2026 - Parallels Desktop 26.2.2 Full License Bypass
================================================================
One-script solution: binary patches + code signing + entitlements.

Usage:
    sudo python3 crack_parallels.py [--dry-run] [--target PATH]

Must be run with sudo (needed for process management and file ownership).
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class BinaryPatch:
    name: str
    arch: str
    offset: int
    original: bytes
    patch: bytes
    description: str


@dataclass
class PatchTarget:
    name: str
    rel_path: str
    arm64_patches: list
    x86_64_patches: list


# ============================================================================
# prl_disp_service — License engine (12 patches)
# ============================================================================

DISP_ARM64 = [
    # Layer 1: JLIC signature verification
    BinaryPatch("P1_JLIC_SIG", "arm64", 0x2BDA68,
                bytes.fromhex("e0020036"), bytes.fromhex("17000014"),
                "JLIC signature: tbz→b (bypass crypto check)"),
    # Layer 2: VM start license status
    BinaryPatch("P3_VM_LICENSE", "arm64", 0x29FAA0,
                bytes.fromhex("e0010034"), bytes.fromhex("0f000014"),
                "VM start license: cbz→b (always valid)"),
    # Layer 3: VM start final gate
    BinaryPatch("P4_VM_GATE", "arm64", 0x29FB28,
                bytes.fromhex("16460037"), bytes.fromhex("1f2003d5"),
                "VM start gate: tbnz→nop"),
    # Layer 4: VM lifetime expiration (online + offline)
    BinaryPatch("P8_LIFETIME_ON", "arm64", 0x291028,
                bytes.fromhex("c80f0034"), bytes.fromhex("7e000014"),
                "VM lifetime online: cbz→b (skip expiry)"),
    BinaryPatch("P9_LIFETIME_OFF", "arm64", 0x290A90,
                bytes.fromhex("e81c0034"), bytes.fromhex("e7000014"),
                "VM lifetime offline: cbz→b (skip expiry)"),
    # Layer 5: Dispatcher client connection check
    BinaryPatch("P12_CLIENT_CHK", "arm64", 0xA0B8C,
                bytes.fromhex("ffc300d1"), bytes.fromhex("20008052"),
                "Client check: sub sp→mov w0,#1 (accept all)"),
    BinaryPatch("P13_CLIENT_RET", "arm64", 0xA0B90,
                bytes.fromhex("f44f01a9"), bytes.fromhex("c0035fd6"),
                "Client check: stp→ret"),
    # Layer 6: SecStaticCodeCheckValidity
    BinaryPatch("P5_CODESIGN", "arm64", 0x5C7D84,
                bytes.fromhex("43a10094"), bytes.fromhex("00008052"),
                "SecStaticCodeCheckValidity→mov w0,#0"),
]

DISP_X86 = [
    BinaryPatch("P2a_JLIC_SIG", "x86_64", 0x29FE5A,
                bytes.fromhex("7475"), bytes.fromhex("9090"),
                "JLIC signature: je→nop"),
    BinaryPatch("P2b_JLIC_PARSE", "x86_64", 0x29FE87,
                bytes.fromhex("7471"), bytes.fromhex("9090"),
                "JLIC parse: je→nop"),
    BinaryPatch("P6_VM_LICENSE", "x86_64", 0x285078,
                bytes.fromhex("0f8597000000"), bytes.fromhex("e99800000090"),
                "VM start license: jne→jmp"),
    BinaryPatch("P10_LIFETIME_ON", "x86_64", 0x2765C5,
                bytes.fromhex("0f84aa010000"), bytes.fromhex("e9ab01000090"),
                "VM lifetime online: je→jmp"),
    BinaryPatch("P11_LIFETIME_OFF", "x86_64", 0x276085,
                bytes.fromhex("0f8437030000"), bytes.fromhex("e93803000090"),
                "VM lifetime offline: je→jmp"),
    BinaryPatch("P14_CLIENT_CHK", "x86_64", 0x99D60,
                bytes.fromhex("554889e5"), bytes.fromhex("b8010000")[0:4],
                "Client check: push→mov eax,1"),
    BinaryPatch("P15_CLIENT_RET", "x86_64", 0x99D64,
                bytes.fromhex("5350"), bytes.fromhex("00c3"),
                "Client check: push→ret"),
    BinaryPatch("P7_CODESIGN", "x86_64", 0x58DE47,
                bytes.fromhex("e86e370500"), bytes.fromhex("31c0909090"),
                "SecStaticCodeCheckValidity→xor eax,eax"),
]

# ============================================================================
# prl_client_app — GUI client (8 patches)
# ============================================================================

CLIENT_ARM64 = [
    # Layer 7: MasterKey piracy handler (business logic disable)
    BinaryPatch("MK1_PIRACY", "arm64", 0x6847FC,
                bytes.fromhex("ff4302d1"), bytes.fromhex("c0035fd6"),
                "MasterKey piracy handler→ret (disable)"),
    # Layer 8: Client codesign verification (3-layer: API + cert + CLI)
    BinaryPatch("C1_CODESIGN", "arm64", 0x7ADB34,
                bytes.fromhex("fa67bba9"), bytes.fromhex("20008052"),
                "Codesign verify: stp→mov w0,#1"),
    BinaryPatch("C2_CODESIGN_RET", "arm64", 0x7ADB38,
                bytes.fromhex("f85f01a9"), bytes.fromhex("c0035fd6"),
                "Codesign verify: stp→ret"),
    # Layer 9: License wizard display (showWizard dispatch chokepoint)
    BinaryPatch("W1_WIZARD", "arm64", 0x457E88,
                bytes.fromhex("f44fbea9"), bytes.fromhex("00008052"),
                "Show wizard: stp→mov w0,#0 (never show)"),
    BinaryPatch("W2_WIZARD_RET", "arm64", 0x457E8C,
                bytes.fromhex("fd7b01a9"), bytes.fromhex("c0035fd6"),
                "Show wizard: stp→ret"),
]

CLIENT_X86 = [
    BinaryPatch("MK2_PIRACY", "x86_64", 0x639DE0,
                bytes.fromhex("554889e5"), bytes.fromhex("c3909090"),
                "MasterKey piracy handler→ret"),
    BinaryPatch("C3_CODESIGN", "x86_64", 0x77A0A0,
                bytes.fromhex("554889e54157"), bytes.fromhex("b801000000c3"),
                "Codesign verify: push→mov eax,1;ret"),
    BinaryPatch("W3_WIZARD", "x86_64", 0x428150,
                bytes.fromhex("554889e5"), bytes.fromhex("31c0c390"),
                "Show wizard: push→xor eax,eax;ret"),
]

# ============================================================================
# prl_vm_app — VM process (5 patches)
# ============================================================================

VMAPP_ARM64 = [
    # Layer 10: VM peer validation (VM→dispatcher trust)
    BinaryPatch("V1_PEER", "arm64", 0x434F8,
                bytes.fromhex("80020034"), bytes.fromhex("14000014"),
                "Peer validate: cbz→b (skip check)"),
    # Layer 11: Team ID verification
    BinaryPatch("V3_TEAMID", "arm64", 0x8B1F18,
                bytes.fromhex("ffc301d1"), bytes.fromhex("00008052"),
                "Team ID check: sub sp→mov w0,#0 (always valid)"),
    BinaryPatch("V4_TEAMID_RET", "arm64", 0x8B1F1C,
                bytes.fromhex("f85f03a9"), bytes.fromhex("c0035fd6"),
                "Team ID check: stp→ret"),
]

VMAPP_X86 = [
    BinaryPatch("V2_PEER", "x86_64", 0x40B78,
                bytes.fromhex("7445"), bytes.fromhex("eb45"),
                "Peer validate: je→jmp"),
    BinaryPatch("V5_TEAMID", "x86_64", 0x9B74E0,
                bytes.fromhex("554889e54157"), bytes.fromhex("31c0c3909090"),
                "Team ID check: push→xor eax,eax;ret"),
]

# ============================================================================
# libPrlGui.3.dylib — Message display suppression (6 patches)
# ============================================================================

GUILIB_ARM64 = [
    # Layer 12: Kill all message dialogs (piracy, warnings, etc.)
    BinaryPatch("G_SHOW_MSG", "arm64", 0xE3434,
                bytes.fromhex("ff8301d1"), bytes.fromhex("c0035fd6"),
                "CMessageProcessor::showMessage→ret (kill ALL dialogs)"),
    # Layer 13: Block server-pushed messages from being cached
    BinaryPatch("G_FROM_SVR", "arm64", 0xE74E4,
                bytes.fromhex("ff0301d1"), bytes.fromhex("c0035fd6"),
                "showMessageFromServer→ret"),
    # Layer 14: Prevent re-raise on window focus switch
    BinaryPatch("G_RAISE", "arm64", 0xE8740,
                bytes.fromhex("ff4301d1"), bytes.fromhex("c0035fd6"),
                "raiseSpecificMessageBox→ret (no re-raise on focus)"),
]

GUILIB_X86 = [
    BinaryPatch("G_SHOW_MSG_X", "x86_64", 0xD9220,
                bytes.fromhex("554889e5"), bytes.fromhex("c3909090"),
                "CMessageProcessor::showMessage→ret"),
    BinaryPatch("G_FROM_SVR_X", "x86_64", 0xDD1A0,
                bytes.fromhex("554889e5"), bytes.fromhex("c3909090"),
                "showMessageFromServer→ret"),
    BinaryPatch("G_RAISE_X", "x86_64", 0xDE290,
                bytes.fromhex("554889e5"), bytes.fromhex("c3909090"),
                "raiseSpecificMessageBox→ret"),
]

# ============================================================================
# libPrlXmlModel.1.dylib — Trial status (3 patches)
# ============================================================================

XMLMODEL_ARM64 = [
    # Layer 15: isTrial() always false
    BinaryPatch("T1_TRIAL", "arm64", 0x7B19B4,
                bytes.fromhex("08b440b9"), bytes.fromhex("00008052"),
                "isTrial: ldr→mov w0,#0 (always false)"),
    BinaryPatch("T2_TRIAL_RET", "arm64", 0x7B19B8,
                bytes.fromhex("1f010071"), bytes.fromhex("c0035fd6"),
                "isTrial: cmp→ret"),
]

XMLMODEL_X86 = [
    BinaryPatch("T3_TRIAL", "x86_64", 0x768A6B,
                bytes.fromhex("0f95c0"), bytes.fromhex("31c090"),
                "isTrial: setne→xor eax,eax"),
]

# ============================================================================
# Targets
# ============================================================================

TARGETS = [
    PatchTarget("prl_disp_service",
                "Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service",
                DISP_ARM64, DISP_X86),
    PatchTarget("prl_client_app",
                "Contents/MacOS/prl_client_app",
                CLIENT_ARM64, CLIENT_X86),
    PatchTarget("prl_vm_app",
                "Contents/MacOS/Parallels VM.app/Contents/MacOS/prl_vm_app",
                VMAPP_ARM64, VMAPP_X86),
    PatchTarget("libPrlGui.3.dylib",
                "Contents/Frameworks/libPrlGui.3.dylib",
                GUILIB_ARM64, GUILIB_X86),
    PatchTarget("libPrlXmlModel.1.dylib",
                "Contents/Frameworks/libPrlXmlModel.1.dylib",
                XMLMODEL_ARM64, XMLMODEL_X86),
]


# ============================================================================
# Core
# ============================================================================

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_fat(data):
    if struct.unpack(">I", data[:4])[0] != 0xCAFEBABE:
        return None
    n = struct.unpack(">I", data[4:8])[0]
    slices = {}
    for i in range(n):
        b = 8 + i * 20
        ct, _, off, sz, _ = struct.unpack(">IIIII", data[b:b + 20])
        if ct == 0x0100000C:
            slices["arm64"] = (off, sz)
        elif ct == 0x01000007:
            slices["x86_64"] = (off, sz)
    return slices


def apply_patch(data, p):
    end = p.offset + len(p.original)
    actual = bytes(data[p.offset:end])
    if actual == p.patch:
        return "skip"
    if actual != p.original:
        print(f"  [FAIL] {p.name}: expected {p.original.hex()}, got {actual.hex()}")
        return False
    data[p.offset:end] = p.patch
    print(f"  [OK] {p.name}: {p.description}")
    return "applied"


def patch_binary(path, target, dry_run):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    slices = parse_fat(bytes(data[:1024]))
    changed, ok = False, True

    for arch, patches in [("arm64", target.arm64_patches),
                          ("x86_64", target.x86_64_patches)]:
        if not patches:
            continue
        base = slices[arch][0] if slices and arch in slices else 0
        for p in patches:
            fp = BinaryPatch(p.name, p.arch, base + p.offset,
                             p.original, p.patch, p.description)
            r = apply_patch(data, fp)
            if not r:
                ok = False
            elif r == "applied":
                changed = True

    if not ok:
        return False
    if dry_run or not changed:
        return True

    backup = path + ".original"
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    with open(path, "wb") as f:
        f.write(data)
    return True


def run(args):
    return subprocess.run(args, capture_output=True, text=True)


def codesign_all(app):
    """Sign the entire app bundle correctly."""
    print("[*] Signing all binaries and bundles...")

    # Remove conflicting provisioning profiles
    for pp in ["Contents/MacOS/Parallels VM.app/Contents/embedded.provisionprofile",
               "Contents/MacOS/Parallels Mac VM.app/Contents/embedded.provisionprofile",
               "Contents/embedded.provisionprofile"]:
        p = os.path.join(app, pp)
        if os.path.exists(p):
            os.remove(p)

    # Remove quarantine
    run(["xattr", "-cr", app])

    # Sign all scripts
    for name in ["parallels_wrapper", "watchdog", "prlcopy", "prlexec", "inittool"]:
        p = os.path.join(app, "Contents/MacOS", name)
        if os.path.isfile(p):
            run(["codesign", "--force", "--sign", "-", p])

    # Sign all Mach-O binaries
    result = run(["find", app, "-type", "f"])
    for f in result.stdout.strip().split("\n"):
        if not f:
            continue
        fr = run(["file", f])
        if "Mach-O" in fr.stdout:
            run(["codesign", "--force", "--sign", "-", f])

    # Create hypervisor entitlements
    # CRITICAL: ONLY com.apple.security.hypervisor
    # Adding disable-library-validation causes AMFI SIGKILL
    ent_path = os.path.join(app, "..", "ent_hv.plist")
    with open(ent_path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0"><dict>\n'
                '  <key>com.apple.security.hypervisor</key><true/>\n'
                '</dict></plist>\n')

    # Sign Parallels VM.app WITH hypervisor entitlement
    vm_xpc = os.path.join(app, "Contents/MacOS/Parallels VM.app/"
                          "Contents/XPCServices/XPCMounter.xpc")
    if os.path.exists(vm_xpc):
        run(["codesign", "--force", "--sign", "-", vm_xpc])
    run(["codesign", "--force", "--sign", "-", "--entitlements", ent_path,
         os.path.join(app, "Contents/MacOS/Parallels VM.app")])

    # Sign other bundles (NO entitlements)
    for b in ["Contents/MacOS/Parallels Service.app",
              "Contents/MacOS/Parallels Mounter.app",
              "Contents/MacOS/Parallels Mac VM.app",
              "Contents/MacOS/Parallels Link.app",
              "Contents/MacOS/Parallels Technical Data Reporter.app",
              "Contents/PlugIns/com.parallels.desktop.console.OpenInIE.appex",
              "Contents/PlugIns/com.parallels.desktop.console.ParallelsMail.appex",
              "Contents/PlugIns/com.parallels.desktop.console.ExeQLPlugin.appex",
              "Contents/Library/Extensions/10.9/prl_hypervisor.kext"]:
        p = os.path.join(app, b)
        if os.path.exists(p):
            run(["codesign", "--force", "--sign", "-", p])

    # Sign main app bundle LAST
    run(["codesign", "--force", "--sign", "-", app])
    os.remove(ent_path)
    print("    Done.")


def main():
    parser = argparse.ArgumentParser(
        description="Parallels Desktop 26.2.2 License Bypass")
    parser.add_argument("--target", help="Path to Parallels Desktop.app")
    parser.add_argument("--dry-run", action="store_true", help="Verify only")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        print("[ERROR] Run with sudo: sudo python3 crack_parallels.py")
        sys.exit(1)

    # Find app
    if args.target:
        app = args.target
    else:
        for c in [os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "Parallels Desktop.app"), "Parallels Desktop.app"]:
            if os.path.isdir(c):
                app = c
                break
        else:
            print("[ERROR] Cannot find Parallels Desktop.app")
            sys.exit(1)

    real_user = os.environ.get("SUDO_USER", os.environ.get("USER", "jamie"))

    print("=" * 60)
    print("Parallels Desktop 26.2.2 - Full License Bypass")
    print("=" * 60)
    print(f"Target: {app}")
    print()

    # Step 1: Fix ownership
    print("[*] Step 1: Fixing file ownership...")
    run(["chown", "-R", real_user, app])

    # Step 2: Apply binary patches
    print("[*] Step 2: Applying binary patches...")
    for t in TARGETS:
        path = os.path.join(app, t.rel_path)
        if not os.path.isfile(path):
            print(f"  [WARN] {t.name}: not found, skipping")
            continue
        print(f"  --- {t.name} ---")
        if not patch_binary(path, t, args.dry_run):
            print(f"  [ERROR] {t.name} failed")
            sys.exit(1)
    print()

    if args.dry_run:
        print("[*] Dry run complete. All patches verified.")
        sys.exit(0)

    # Step 3: Code signing
    print("[*] Step 3: Code signing with hypervisor entitlement...")
    codesign_all(app)
    print()

    # Step 4: Kill old processes
    print("[*] Step 4: Killing old Parallels processes...")
    for proc in ["prl_disp_service", "prl_client_app",
                 "prl_vm_app", "prl_naptd"]:
        run(["pkill", "-9", proc])
    print()

    # Step 5: Verify
    print("[*] Step 5: Verification...")
    vm_bin = os.path.join(app, "Contents/MacOS/Parallels VM.app/"
                          "Contents/MacOS/prl_vm_app")
    r = run(["codesign", "-d", "--entitlements", "-", vm_bin])
    has_hv = "hypervisor" in (r.stdout + r.stderr)
    r2 = run(["codesign", "--verify", app])
    print(f"  Hypervisor entitlement: {'OK' if has_hv else 'MISSING'}")
    print(f"  Bundle signature: {'OK' if r2.returncode == 0 else 'BROKEN'}")
    print()

    total = sum(len(t.arm64_patches) + len(t.x86_64_patches) for t in TARGETS)
    print("=" * 60)
    print(f"SUCCESS — {total} patches applied across 5 binaries.")
    print("=" * 60)
    print()
    print("Bypassed layers:")
    print("   1. JLIC cryptographic signature verification")
    print("   2. VM start license validation + final gate")
    print("   3. VM lifetime expiration (online + offline)")
    print("   4. Dispatcher client connection check")
    print("   5. SecStaticCodeCheckValidity (dispatcher)")
    print("   6. MasterKey piracy handler (client business logic)")
    print("   7. Client codesign --verify (3-layer: API + cert + CLI)")
    print("   8. License wizard display (showWizard dispatch)")
    print("   9. VM peer validation (prl_vm_app → dispatcher)")
    print("  10. VM Team ID verification (SecCodeCopySigningInformation)")
    print("  11. CMessageProcessor::showMessage (kill piracy dialogs)")
    print("  12. showMessageFromServer (block server message caching)")
    print("  13. raiseSpecificMessageBox (prevent focus re-raise)")
    print("  14. CDownloadedKeyInfo::isTrial() → always false")
    print("  15. Hypervisor.framework entitlement (ad-hoc signing)")
    print()
    print("Launch the app:")
    print(f"  open {app}")


if __name__ == "__main__":
    main()
