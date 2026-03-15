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
    offset: int        # Offset within thin (single-arch) slice
    original: bytes
    patch: bytes
    description: str
    va: int


@dataclass
class PatchTarget:
    name: str
    rel_path: str
    arm64_patches: list
    x86_64_patches: list


# ============================================================================
# All Patch Definitions (23 patches across 4 binaries)
# ============================================================================

DISP_ARM64 = [
    BinaryPatch("P1_JLIC_SIG", "arm64", 0x2BDA68,
                bytes.fromhex("e0020036"), bytes.fromhex("17000014"),
                "JLIC signature check: tbz→b (bypass)", 0x1002BDA68),
    BinaryPatch("P3_VM_LICENSE", "arm64", 0x29FAA0,
                bytes.fromhex("e0010034"), bytes.fromhex("0f000014"),
                "VM start license: cbz→b (always valid)", 0x10029FAA0),
    BinaryPatch("P4_VM_GATE", "arm64", 0x29FB28,
                bytes.fromhex("16460037"), bytes.fromhex("1f2003d5"),
                "VM start gate: tbnz→nop", 0x10029FB28),
    BinaryPatch("P8_LIFETIME_ON", "arm64", 0x291028,
                bytes.fromhex("c80f0034"), bytes.fromhex("7e000014"),
                "VM lifetime online: cbz→b (skip expiry)", 0x100291028),
    BinaryPatch("P9_LIFETIME_OFF", "arm64", 0x290A90,
                bytes.fromhex("e81c0034"), bytes.fromhex("e7000014"),
                "VM lifetime offline: cbz→b (skip expiry)", 0x100290A90),
    BinaryPatch("P12_CLIENT_CHK", "arm64", 0xA0B8C,
                bytes.fromhex("ffc300d1"), bytes.fromhex("20008052"),
                "Client check: sub sp→mov w0,#1 (accept all)", 0x1000A0B8C),
    BinaryPatch("P13_CLIENT_RET", "arm64", 0xA0B90,
                bytes.fromhex("f44f01a9"), bytes.fromhex("c0035fd6"),
                "Client check: stp→ret", 0x1000A0B90),
    BinaryPatch("P5_CODESIGN", "arm64", 0x5C7D84,
                bytes.fromhex("43a10094"), bytes.fromhex("00008052"),
                "SecStaticCodeCheckValidity→mov w0,#0", 0x1005C7D84),
]

DISP_X86 = [
    BinaryPatch("P2a_JLIC_SIG", "x86_64", 0x29FE5A,
                bytes.fromhex("7475"), bytes.fromhex("9090"),
                "JLIC signature: je→nop", 0x10029FE5A),
    BinaryPatch("P2b_JLIC_PARSE", "x86_64", 0x29FE87,
                bytes.fromhex("7471"), bytes.fromhex("9090"),
                "JLIC parse: je→nop", 0x10029FE87),
    BinaryPatch("P6_VM_LICENSE", "x86_64", 0x285078,
                bytes.fromhex("0f8597000000"), bytes.fromhex("e99800000090"),
                "VM start license: jne→jmp", 0x100285078),
    BinaryPatch("P10_LIFETIME_ON", "x86_64", 0x2765C5,
                bytes.fromhex("0f84aa010000"), bytes.fromhex("e9ab01000090"),
                "VM lifetime online: je→jmp", 0x1002765C5),
    BinaryPatch("P11_LIFETIME_OFF", "x86_64", 0x276085,
                bytes.fromhex("0f8437030000"), bytes.fromhex("e93803000090"),
                "VM lifetime offline: je→jmp", 0x100276085),
    BinaryPatch("P14_CLIENT_CHK", "x86_64", 0x99D60,
                bytes.fromhex("554889e5"), bytes.fromhex("b8010000")[0:4],
                "Client check: push rbp→mov eax,1", 0x100099D60),
    BinaryPatch("P15_CLIENT_RET", "x86_64", 0x99D64,
                bytes.fromhex("5350"), bytes.fromhex("00c3"),
                "Client check: push→ret", 0x100099D64),
    BinaryPatch("P7_CODESIGN", "x86_64", 0x58DE47,
                bytes.fromhex("e86e370500"), bytes.fromhex("31c0909090"),
                "SecStaticCodeCheckValidity→xor eax,eax", 0x10058DE47),
]

CLIENT_ARM64 = [
    BinaryPatch("C1_CODESIGN", "arm64", 0x7ADB34,
                bytes.fromhex("fa67bba9"), bytes.fromhex("20008052"),
                "Codesign verify: stp→mov w0,#1", 0x1007ADB34),
    BinaryPatch("C2_CODESIGN_RET", "arm64", 0x7ADB38,
                bytes.fromhex("f85f01a9"), bytes.fromhex("c0035fd6"),
                "Codesign verify: stp→ret", 0x1007ADB38),
    BinaryPatch("W1_WIZARD", "arm64", 0x457E88,
                bytes.fromhex("f44fbea9"), bytes.fromhex("00008052"),
                "Show wizard: stp→mov w0,#0 (never show)", 0x100457E88),
    BinaryPatch("W2_WIZARD_RET", "arm64", 0x457E8C,
                bytes.fromhex("fd7b01a9"), bytes.fromhex("c0035fd6"),
                "Show wizard: stp→ret", 0x100457E8C),
]

CLIENT_X86 = [
    BinaryPatch("C3_CODESIGN", "x86_64", 0x77A0A0,
                bytes.fromhex("554889e54157"), bytes.fromhex("b801000000c3"),
                "Codesign verify: push→mov eax,1;ret", 0x10077A0A0),
    BinaryPatch("W3_WIZARD", "x86_64", 0x428150,
                bytes.fromhex("554889e5"), bytes.fromhex("31c0c390"),
                "Show wizard: push→xor eax,eax;ret", 0x100428150),
]

VMAPP_ARM64 = [
    BinaryPatch("V1_PEER", "arm64", 0x434F8,
                bytes.fromhex("80020034"), bytes.fromhex("14000014"),
                "Peer validate: cbz→b (skip check)", 0x1000434F8),
]

VMAPP_X86 = [
    BinaryPatch("V2_PEER", "x86_64", 0x40B78,
                bytes.fromhex("7445"), bytes.fromhex("eb45"),
                "Peer validate: je→jmp", 0x100040B78),
]

XMLMODEL_ARM64 = [
    BinaryPatch("T1_TRIAL", "arm64", 0x7B19B4,
                bytes.fromhex("08b440b9"), bytes.fromhex("00008052"),
                "isTrial: ldr→mov w0,#0 (always false)", 0x7B19B4),
    BinaryPatch("T2_TRIAL_RET", "arm64", 0x7B19B8,
                bytes.fromhex("1f010071"), bytes.fromhex("c0035fd6"),
                "isTrial: cmp→ret", 0x7B19B8),
]

XMLMODEL_X86 = [
    BinaryPatch("T3_TRIAL", "x86_64", 0x768A6B,
                bytes.fromhex("0f95c0"), bytes.fromhex("31c090"),
                "isTrial: setne→xor eax,eax", 0x768A6B),
]

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
        ct, _, off, sz, _ = struct.unpack(">IIIII", data[b:b+20])
        if ct == 0x0100000C:
            slices["arm64"] = (off, sz)
        elif ct == 0x01000007:
            slices["x86_64"] = (off, sz)
    return slices


def apply_patch(data, patch):
    end = patch.offset + len(patch.original)
    actual = bytes(data[patch.offset:end])
    if actual == patch.patch:
        return "skip"
    if actual != patch.original:
        print(f"  [FAIL] {patch.name}: expected {patch.original.hex()}, got {actual.hex()}")
        return False
    data[patch.offset:end] = patch.patch
    print(f"  [OK] {patch.name}: {patch.description}")
    return "applied"


def patch_binary(path, target, dry_run):
    with open(path, "rb") as f:
        data = bytearray(f.read())
    slices = parse_fat(bytes(data[:1024]))
    changed = False
    ok = True

    for arch, patches in [("arm64", target.arm64_patches), ("x86_64", target.x86_64_patches)]:
        if not patches:
            continue
        base = slices[arch][0] if slices and arch in slices else 0
        for p in patches:
            fp = BinaryPatch(p.name, p.arch, base + p.offset, p.original, p.patch, p.description, p.va)
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


def run(args, check=False):
    return subprocess.run(args, capture_output=True, text=True, check=check)


def codesign_all(app_path):
    """Sign the entire app bundle correctly."""
    print("[*] Signing all binaries and bundles...")

    # 1. Remove conflicting provisioning profiles
    for pp in [
        "Contents/MacOS/Parallels VM.app/Contents/embedded.provisionprofile",
        "Contents/MacOS/Parallels Mac VM.app/Contents/embedded.provisionprofile",
        "Contents/embedded.provisionprofile",
    ]:
        p = os.path.join(app_path, pp)
        if os.path.exists(p):
            os.remove(p)

    # 2. Remove quarantine
    run(["xattr", "-cr", app_path])

    # 3. Sign all scripts
    for name in ["parallels_wrapper", "watchdog", "prlcopy", "prlexec", "inittool"]:
        p = os.path.join(app_path, "Contents/MacOS", name)
        if os.path.isfile(p):
            run(["codesign", "--force", "--sign", "-", p])

    # 4. Sign all Mach-O binaries
    result = run(["find", app_path, "-type", "f"])
    for f in result.stdout.strip().split("\n"):
        if not f:
            continue
        fr = run(["file", f])
        if "Mach-O" in fr.stdout:
            run(["codesign", "--force", "--sign", "-", f])

    # 5. Create hypervisor entitlements
    ent_path = os.path.join(app_path, "..", "ent_hv.plist")
    with open(ent_path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n')
        f.write('<plist version="1.0"><dict>\n')
        f.write('  <key>com.apple.security.hypervisor</key><true/>\n')
        f.write('</dict></plist>\n')

    # 6. Sign Parallels VM.app WITH hypervisor entitlement
    #    (MUST use ONLY com.apple.security.hypervisor - adding
    #     disable-library-validation causes AMFI to SIGKILL the process)
    vm_xpc = os.path.join(app_path, "Contents/MacOS/Parallels VM.app/Contents/XPCServices/XPCMounter.xpc")
    if os.path.exists(vm_xpc):
        run(["codesign", "--force", "--sign", "-", vm_xpc])
    run(["codesign", "--force", "--sign", "-", "--entitlements", ent_path,
         os.path.join(app_path, "Contents/MacOS/Parallels VM.app")])

    # 7. Sign other bundles (NO entitlements)
    bundles = [
        "Contents/MacOS/Parallels Service.app",
        "Contents/MacOS/Parallels Mounter.app",
        "Contents/MacOS/Parallels Mac VM.app",
        "Contents/MacOS/Parallels Link.app",
        "Contents/MacOS/Parallels Technical Data Reporter.app",
        "Contents/PlugIns/com.parallels.desktop.console.OpenInIE.appex",
        "Contents/PlugIns/com.parallels.desktop.console.ParallelsMail.appex",
        "Contents/PlugIns/com.parallels.desktop.console.ExeQLPlugin.appex",
        "Contents/Library/Extensions/10.9/prl_hypervisor.kext",
    ]
    for b in bundles:
        p = os.path.join(app_path, b)
        if os.path.exists(p):
            run(["codesign", "--force", "--sign", "-", p])

    # 8. Sign main app bundle LAST
    run(["codesign", "--force", "--sign", "-", app_path])

    os.remove(ent_path)
    print("    Done.")


def kill_parallels():
    """Kill all running Parallels processes (requires root)."""
    for proc in ["prl_disp_service", "prl_client_app", "prl_vm_app", "prl_naptd"]:
        run(["pkill", "-9", proc])


def main():
    parser = argparse.ArgumentParser(description="Parallels Desktop 26.2.2 License Bypass")
    parser.add_argument("--target", help="Path to Question1.app")
    parser.add_argument("--dry-run", action="store_true", help="Verify only")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.dry_run:
        print("[ERROR] Run with sudo: sudo python3 crack_parallels.py")
        sys.exit(1)

    # Find app
    if args.target:
        app = args.target
    else:
        for c in [os.path.join(os.path.dirname(os.path.abspath(__file__)), "Question1.app"),
                   "Question1.app"]:
            if os.path.isdir(c):
                app = c
                break
        else:
            print("[ERROR] Cannot find Question1.app")
            sys.exit(1)

    # Get real user for chown
    real_user = os.environ.get("SUDO_USER", "jamie")

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
    kill_parallels()
    print()

    # Step 5: Verify
    print("[*] Step 5: Verification...")
    vm_bin = os.path.join(app, "Contents/MacOS/Parallels VM.app/Contents/MacOS/prl_vm_app")
    r = run(["codesign", "-d", "--entitlements", "-", vm_bin])
    has_hv = "hypervisor" in (r.stdout + r.stderr)
    r2 = run(["codesign", "--verify", app])
    bundle_ok = r2.returncode == 0
    print(f"  Hypervisor entitlement: {'OK' if has_hv else 'MISSING'}")
    print(f"  Bundle signature: {'OK' if bundle_ok else 'BROKEN'}")
    print()

    print("=" * 60)
    print("SUCCESS - All patches applied.")
    print("=" * 60)
    print()
    print("Bypassed layers:")
    print("  1. JLIC cryptographic signature verification")
    print("  2. VM start license validation + final gate")
    print("  3. VM lifetime expiration (online + offline)")
    print("  4. Dispatcher client connection check")
    print("  5. SecStaticCodeCheckValidity (dispatcher)")
    print("  6. Client codesign --verify (3-layer: API + cert + CLI)")
    print("  7. License wizard display (showWizard dispatch)")
    print("  8. CDownloadedKeyInfo::isTrial() → always false")
    print("  9. VM peer validation (prl_vm_app → dispatcher)")
    print(" 10. Hypervisor.framework entitlement (ad-hoc signing)")
    print()
    print("Launch the app:")
    print(f"  open {app}")


if __name__ == "__main__":
    main()
