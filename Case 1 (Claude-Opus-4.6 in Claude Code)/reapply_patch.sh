#!/bin/bash
# Re-apply license bypass after Parallels Desktop update
BINARY="/Users/jamie/Downloads/InfoSec-Invitation-Problem/Question1(PD-Desktop).app/Contents/MacOS/Parallels Service.app/Contents/MacOS/prl_disp_service"
CHECK=$(xxd -s 0xADD960 -l 4 "$BINARY" 2>/dev/null | awk '{print $2$3}')
if [ "$CHECK" = "a0080036" ]; then
    echo "[*] Re-applying patches..."
    printf '\x1f\x20\x03\xd5' | dd of="$BINARY" bs=1 seek=$((0xADD960)) conv=notrunc 2>/dev/null
    printf '\x90\x90' | dd of="$BINARY" bs=1 seek=$((0x2A3E5A)) conv=notrunc 2>/dev/null
    codesign --remove-signature "$BINARY" 2>/dev/null
    codesign -fs - "$BINARY" 2>/dev/null
    codesign -fs - --deep "/Users/jamie/Downloads/InfoSec-Invitation-Problem/Question1(PD-Desktop).app" 2>/dev/null
    echo "[+] Patches re-applied and binary re-signed"
elif [ "$CHECK" = "1f2003d5" ]; then
    echo "[+] Patch still active"
else
    echo "[!] Unknown binary state: $CHECK"
fi
