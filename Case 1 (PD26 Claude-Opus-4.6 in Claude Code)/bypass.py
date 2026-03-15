#!/usr/bin/env python3
"""
Parallels Desktop 26.2.2 License Bypass - CTF Challenge Solution
================================================================
This script bypasses the JLIC signature verification in prl_disp_service
by NOP-ing the conditional branch that checks the RSA signature result.

Technique: Binary Patch + License File Modification + Code Re-signing
Target: prl_disp_service (Parallels Service daemon)

Attack Vector:
  The function at arm64:0x1002BD95C / x86_64:0x10029FE53 performs RSA-2048
  signature verification (PKCS#1 v1.5 + SHA-256) on the license JSON.
  The result is checked by a conditional branch:
    - arm64:  TBZ W0, #0, <error>  (if bit 0 == 0, signature invalid)
    - x86_64: JE <error>           (if ZF == 1, al == 0, signature invalid)
  We NOP these branches so the result is ignored.

Persistence:
  - The license file (/Library/Preferences/Parallels/licenses.json) is
    modified with extended expiration dates and survives app updates.
  - The binary patch must be re-applied after binary updates, which is
    handled by the companion persistence mechanism.
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

# ============================================================================
# Configuration
# ============================================================================

APP_PATH = Path(__file__).parent / "Question1(PD-Desktop).app"
DISP_SERVICE_REL = "Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service"
LICENSE_FILE = Path("/Library/Preferences/Parallels/licenses.json")
BACKUP_SUFFIX = ".ctf_backup"

# Patch definitions: (file_offset, original_bytes, patched_bytes, description)
PATCHES = [
    # x86_64: JE short (signature check failed branch)
    (0x2A3E5A, bytes.fromhex("7475"), bytes.fromhex("9090"),
     "x86_64: NOP the JE after signature verification (testb %al,%al; je -> nop nop)"),

    # arm64: TBZ W0, #0, <error> (signature check failed branch)
    (0xADD960, bytes.fromhex("a0080036"), bytes.fromhex("1f2003d5"),
     "arm64: NOP the TBZ W0,#0 after signature verification"),
]


def backup_file(filepath):
    """Create a backup of the original file."""
    backup = Path(str(filepath) + BACKUP_SUFFIX)
    if not backup.exists():
        try:
            shutil.copy2(filepath, backup)
            print(f"  [+] Backed up: {filepath.name} -> {backup.name}")
        except PermissionError:
            subprocess.run(["sudo", "cp", "-p", str(filepath), str(backup)], check=True)
            print(f"  [+] Backed up (sudo): {filepath.name} -> {backup.name}")
    else:
        print(f"  [*] Backup already exists: {backup.name}")


def patch_binary(binary_path):
    """Apply binary patches to disable signature verification."""
    print(f"\n[1] Patching binary: {binary_path.name}")

    backup_file(binary_path)

    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    for offset, orig, patch, desc in PATCHES:
        current = bytes(data[offset : offset + len(orig)])
        if current == orig:
            data[offset : offset + len(patch)] = patch
            print(f"  [+] {desc}")
            print(f"      Offset 0x{offset:X}: {orig.hex()} -> {patch.hex()}")
        elif current == patch:
            print(f"  [*] Already patched: {desc}")
        else:
            print(f"  [!] UNEXPECTED bytes at 0x{offset:X}: {current.hex()}")
            print(f"      Expected: {orig.hex()}")
            print(f"      This binary version may differ. Skipping this patch.")
            continue

    with open(binary_path, "wb") as f:
        f.write(data)

    print(f"  [+] Binary patched successfully")


def modify_license():
    """Modify the license file with extended expiration dates."""
    print(f"\n[2] Modifying license file: {LICENSE_FILE}")

    if not LICENSE_FILE.exists():
        print(f"  [!] License file not found. Creating a new one.")
        create_new_license()
        return

    backup_file(LICENSE_FILE)

    with open(LICENSE_FILE, "r") as f:
        lic_data = json.load(f)

    # Parse the inner license JSON
    license_info = json.loads(lic_data["license"])

    # Extend expiration dates far into the future
    now = datetime.now()
    future = now + timedelta(days=3650)  # 10 years
    grace_future = future + timedelta(days=7)

    original_main_end = license_info.get("main_period_ends_at", "N/A")
    original_grace_end = license_info.get("grace_period_ends_at", "N/A")

    license_info["main_period_ends_at"] = future.strftime("%Y-%m-%d %H:%M:%S")
    license_info["grace_period_ends_at"] = grace_future.strftime("%Y-%m-%d %H:%M:%S")
    license_info["is_expired"] = False
    license_info["is_grace_period"] = False
    license_info["is_trial"] = False
    license_info["is_suspended"] = False
    license_info["edition"] = 3  # Pro edition
    license_info["limit"] = 999
    license_info["cpu_limit"] = 128
    license_info["ram_limit"] = 524288  # 512GB

    print(f"  [+] Extended main_period_ends_at: {original_main_end} -> {license_info['main_period_ends_at']}")
    print(f"  [+] Extended grace_period_ends_at: {original_grace_end} -> {license_info['grace_period_ends_at']}")
    print(f"  [+] Set is_expired=false, is_trial=false, is_suspended=false")
    print(f"  [+] Set edition=3 (Pro), limit=999, cpu_limit=128, ram_limit=512GB")

    # Write back the modified license
    # Keep the original signature (it won't be checked after our binary patch)
    lic_data["license"] = json.dumps(license_info, separators=(",", ": "))

    try:
        with open(LICENSE_FILE, "w") as f:
            json.dump(lic_data, f, indent=4)
    except PermissionError:
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(lic_data, tmp, indent=4)
        tmp.close()
        subprocess.run(["sudo", "cp", tmp.name, str(LICENSE_FILE)], check=True)
        os.unlink(tmp.name)

    print(f"  [+] License file modified successfully")


def create_new_license():
    """Create a new license file from scratch."""
    import uuid
    import hashlib

    now = datetime.now()
    future = now + timedelta(days=3650)
    grace_future = future + timedelta(days=7)

    # Generate hardware ID from system UUID
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True
        )
        for line in result.stdout.split("\n"):
            if "IOPlatformUUID" in line:
                sys_uuid = line.split('"')[-2]
                hw_id = hashlib.md5(sys_uuid.encode()).hexdigest().upper()
                break
        else:
            hw_id = hashlib.md5(uuid.uuid4().bytes).hexdigest().upper()
    except Exception:
        hw_id = hashlib.md5(uuid.uuid4().bytes).hexdigest().upper()

    license_info = {
        "name": "",
        "uuid": uuid.uuid4().hex,
        "lic_key": "CTF00-BYPAS-SKEY0-00000-CTF00",
        "product_version": "*",
        "is_upgrade": False,
        "is_sublicense": False,
        "parent_key": None,
        "parent_uuid": None,
        "main_period_ends_at": future.strftime("%Y-%m-%d %H:%M:%S"),
        "grace_period_ends_at": grace_future.strftime("%Y-%m-%d %H:%M:%S"),
        "is_auto_renewable": False,
        "is_nfr": False,
        "is_beta": False,
        "is_china": False,
        "is_suspended": False,
        "is_expired": False,
        "is_grace_period": False,
        "is_purchased_online": False,
        "limit": 999,
        "usage": 1,
        "edition": 3,
        "platform": 3,
        "product": 7,
        "offline": False,
        "is_bytebot": False,
        "cpu_limit": 128,
        "ram_limit": 524288,
        "is_trial": False,
        "is_enterprise": False,
        "hosts": [{
            "name": "GDPR_HIDDEN",
            "hw_id": hw_id,
            "product_version": "26.2.2-57373",
            "activated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        }],
        "started_at": now.strftime("%Y-%m-%d %H:%M:%S"),
        "cep_option": False,
    }

    # Create with a dummy signature (won't be checked after binary patch)
    import base64
    dummy_sig = base64.b64encode(os.urandom(256)).decode()

    lic_data = {
        "license": json.dumps(license_info, separators=(",", ": ")),
        "signature": dummy_sig,
    }

    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LICENSE_FILE, "w") as f:
            json.dump(lic_data, f, indent=4)
    except PermissionError:
        import tempfile
        subprocess.run(["sudo", "mkdir", "-p", str(LICENSE_FILE.parent)], check=True)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(lic_data, tmp, indent=4)
        tmp.close()
        subprocess.run(["sudo", "cp", tmp.name, str(LICENSE_FILE)], check=True)
        os.unlink(tmp.name)

    print(f"  [+] Created new license file with HWID: {hw_id}")


def resign_binary(binary_path):
    """Re-sign the modified binary with ad-hoc signature."""
    print(f"\n[3] Re-signing binaries")

    # Re-sign the dispatcher service
    print(f"  [+] Removing old signature from {binary_path.name}...")
    subprocess.run(
        ["codesign", "--remove-signature", str(binary_path)],
        capture_output=True
    )

    print(f"  [+] Ad-hoc signing {binary_path.name}...")
    result = subprocess.run(
        ["codesign", "-fs", "-", "--deep", "--no-strict", str(binary_path)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"  [+] Binary re-signed successfully")
    else:
        print(f"  [!] Signing warning: {result.stderr.strip()}")

    # Re-sign the Parallels Service app
    service_app = binary_path.parent.parent.parent
    print(f"  [+] Re-signing {service_app.name}...")
    subprocess.run(
        ["codesign", "-fs", "-", "--deep", "--no-strict", str(service_app)],
        capture_output=True, text=True
    )

    # Re-sign the main app bundle
    print(f"  [+] Re-signing main app bundle...")
    result = subprocess.run(
        ["codesign", "-fs", "-", "--deep", "--no-strict", str(APP_PATH)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"  [+] App bundle re-signed successfully")
    else:
        print(f"  [!] Warning: {result.stderr.strip()}")


def setup_persistence():
    """Create a persistence mechanism for surviving updates."""
    print(f"\n[4] Setting up update persistence")

    # Create a watcher script that can re-apply patches after updates
    watcher_script = APP_PATH.parent / "reapply_patch.sh"
    binary_path = APP_PATH / DISP_SERVICE_REL

    script_content = f"""#!/bin/bash
# Parallels Desktop License Patch Re-applicator
# Run this after a Parallels Desktop update to re-apply the bypass

BINARY="{binary_path}"
BACKUP="${{BINARY}}.ctf_backup"

echo "[*] Checking if patch needs re-application..."

# Check arm64 patch point
ARM64_CHECK=$(xxd -s 0xADD960 -l 4 "$BINARY" | awk '{{print $2$3}}')
if [ "$ARM64_CHECK" = "a0080036" ]; then
    echo "[!] Binary has been updated - re-applying patches..."

    # Backup new binary
    cp "$BINARY" "${{BINARY}}.pre_patch"

    # Apply arm64 patch
    printf '\\x1f\\x20\\x03\\xd5' | dd of="$BINARY" bs=1 seek=$((0xADD960)) conv=notrunc 2>/dev/null
    echo "[+] ARM64 patch applied"

    # Apply x86_64 patch
    printf '\\x90\\x90' | dd of="$BINARY" bs=1 seek=$((0x2A3E5A)) conv=notrunc 2>/dev/null
    echo "[+] x86_64 patch applied"

    # Re-sign
    codesign --remove-signature "$BINARY" 2>/dev/null
    codesign -fs - --deep --no-strict "$BINARY" 2>/dev/null
    codesign -fs - --deep --no-strict "{APP_PATH}" 2>/dev/null
    echo "[+] Binary re-signed"

elif [ "$ARM64_CHECK" = "1f2003d5" ]; then
    echo "[+] Patch is still active - no action needed"
else
    echo "[!] Unknown binary state: $ARM64_CHECK"
    echo "    Manual intervention may be required"
fi
"""
    with open(watcher_script, "w") as f:
        f.write(script_content)
    os.chmod(watcher_script, 0o755)
    print(f"  [+] Created re-application script: {watcher_script}")

    # Create a LaunchDaemon plist for automatic re-patching
    launch_daemon_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ctf.parallels.patch.watcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>{watcher_script}</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>{binary_path}</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>"""

    plist_path = APP_PATH.parent / "com.ctf.parallels.patch.watcher.plist"
    with open(plist_path, "w") as f:
        f.write(launch_daemon_content)
    print(f"  [+] Created LaunchDaemon plist: {plist_path}")
    print(f"      Install with: sudo cp {plist_path} /Library/LaunchDaemons/")
    print(f"      Load with:    sudo launchctl load /Library/LaunchDaemons/{plist_path.name}")


def verify_patches(binary_path):
    """Verify that all patches were applied correctly."""
    print(f"\n[5] Verifying patches")

    with open(binary_path, "rb") as f:
        data = f.read()

    all_ok = True
    for offset, _, expected_patch, desc in PATCHES:
        current = bytes(data[offset : offset + len(expected_patch)])
        if current == expected_patch:
            print(f"  [+] PASS: {desc}")
        else:
            print(f"  [!] FAIL: {desc}")
            print(f"      Expected: {expected_patch.hex()}, Got: {current.hex()}")
            all_ok = False

    # Verify license file
    if LICENSE_FILE.exists():
        with open(LICENSE_FILE, "r") as f:
            lic = json.load(f)
        inner = json.loads(lic["license"])
        exp_date = inner.get("main_period_ends_at", "")
        is_expired = inner.get("is_expired", True)
        print(f"  [+] License expires: {exp_date}")
        print(f"  [+] is_expired: {is_expired}")
        if not is_expired and exp_date > datetime.now().strftime("%Y-%m-%d"):
            print(f"  [+] PASS: License is valid and not expired")
        else:
            print(f"  [!] FAIL: License appears expired or invalid")
            all_ok = False
    else:
        print(f"  [!] FAIL: License file not found")
        all_ok = False

    # Verify code signature
    result = subprocess.run(
        ["codesign", "--verify", str(binary_path)],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"  [+] PASS: Binary code signature valid")
    else:
        print(f"  [!] WARN: Code signature issue: {result.stderr.strip()}")

    return all_ok


def main():
    print("=" * 70)
    print("Parallels Desktop 26.2.2 License Bypass")
    print("CTF Security Competition - White Hat Challenge")
    print("=" * 70)

    binary_path = APP_PATH / DISP_SERVICE_REL
    if not binary_path.exists():
        print(f"\n[!] Binary not found: {binary_path}")
        sys.exit(1)

    print(f"\nTarget: {APP_PATH.name}")
    print(f"Binary: {binary_path.name}")
    print(f"License: {LICENSE_FILE}")

    # Step 1: Patch the binary
    patch_binary(binary_path)

    # Step 2: Modify the license file
    modify_license()

    # Step 3: Re-sign the binary
    resign_binary(binary_path)

    # Step 4: Setup persistence
    setup_persistence()

    # Step 5: Verify
    success = verify_patches(binary_path)

    print(f"\n{'=' * 70}")
    if success:
        print("SUCCESS: All patches applied and verified!")
        print("\nThe bypass works by:")
        print("  1. NOP-ing the RSA signature verification branch in prl_disp_service")
        print("  2. Modifying license dates to far future (10 years)")
        print("  3. Re-signing binaries with ad-hoc signature")
        print("  4. WatchPaths LaunchDaemon re-applies patch after updates")
    else:
        print("PARTIAL SUCCESS: Some checks failed - review output above")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
