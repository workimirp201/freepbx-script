#!/bin/bash
# Download one immutable GitHub commit into a separate, verified release folder.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root on the node.' >&2; exit 2; }
REF=${1:-}
[[ $REF =~ ^[a-fA-F0-9]{40}$ ]] || { echo 'Usage: bash download-r9.sh FULL_40_CHARACTER_GITHUB_COMMIT_SHA'; exit 2; }
BASE="https://raw.githubusercontent.com/workimirp201/freepbx-script/$REF"
DEST="/root/freepbx-care-r9-$REF"
[[ ! -L $DEST ]] || { echo 'Refusing symlink release directory.' >&2; exit 1; }
umask 077
mkdir -p -- "$DEST"
FILES=(freepbx-care.sh freepbx-voicemail.py freepbx-voicemail-ami.py
       proxmox-care-scheduler.sh proxmox-update-freepbx.sh proxmox-install-freepbx.sh
       cleanup-legacy-freepbx.sh proxmox-cleanup-freepbx.sh proxmox-verify-freepbx.sh
       proxmox-experimental-freepbx.sh proxmox-install-host-tools.sh download-r9.sh)
for NAME in RUNTIME-SHA256SUMS "${FILES[@]}"; do
  curl --proto '=https' --tlsv1.2 -fSL --retry 3 "$BASE/$NAME" -o "$DEST/$NAME.partial"
  mv -- "$DEST/$NAME.partial" "$DEST/$NAME"
done
cd -- "$DEST"
sha256sum --check --strict RUNTIME-SHA256SUMS
for NAME in "${FILES[@]}"; do
  if [[ $NAME == *.sh ]]; then bash -n "$NAME"; fi
  chmod 700 -- "$NAME"
done
printf 'Verified release folder: %s\n' "$DEST"
echo 'Download only: no timer, service, container or installed script was changed.'
