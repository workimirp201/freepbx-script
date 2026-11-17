#!/bin/bash
set -euo pipefail
exec python3 -c "$(cat <<'PYTHON'
import sys
if sys.argv[0]=='-c':sys.argv=sys.argv[1:]
"""Replace the old node helper entrypoints from a verified r9 download, with backup."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

NAMES=['proxmox-install-freepbx.sh','proxmox-update-freepbx.sh','proxmox-cleanup-freepbx.sh',
       'proxmox-verify-freepbx.sh','proxmox-experimental-freepbx.sh']

def atomic(path,raw,mode):
    fd,temp=tempfile.mkstemp(dir=path.parent,prefix='.r9-host-')
    try:
        with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def main():
    if os.geteuid()!=0 or not shutil.which('pct'):raise RuntimeError('Requires root on the local Proxmox node')
    if len(sys.argv)!=1:raise RuntimeError('This helper takes no arguments')
    source=Path(sys.argv[0]).resolve().parent
    hashes={name:digest for digest,name in (line.split('  ',1) for line in (source/'RUNTIME-SHA256SUMS').read_text().splitlines())}
    for name in NAMES:
        p=source/name;target=Path('/root')/name
        if p.is_symlink() or target.is_symlink():raise RuntimeError('Refusing symlink helper path')
        if hashlib.sha256(p.read_bytes()).hexdigest()!=hashes[name]:raise RuntimeError('Helper checksum mismatch')
    os.umask(0o077)
    backup=Path('/var/lib/proxmox-care')/('host-tools-backup-'+str(time.time_ns()))
    backup.mkdir(mode=0o700,parents=True)
    manifest=[]
    for name in NAMES:
        target=Path('/root')/name;entry=dict(name=name,exists=target.exists())
        if target.exists():
            if not target.is_file():raise RuntimeError('Unrecognized helper path')
            st=target.stat();entry.update(mode=st.st_mode&0o777,uid=st.st_uid,gid=st.st_gid)
            atomic(backup/name,target.read_bytes(),0o600)
        manifest.append(entry)
    atomic(backup/'manifest.json',json.dumps(manifest,indent=2).encode(),0o600)
    try:
        for name in NAMES:atomic(Path('/root')/name,(source/name).read_bytes(),0o700)
    except BaseException:
        for entry in manifest:
            target=Path('/root')/entry['name']
            if entry['exists']:
                atomic(target,(backup/entry['name']).read_bytes(),entry['mode']);os.chown(target,entry['uid'],entry['gid'])
            else:target.unlink(missing_ok=True)
        raise
    print('Node helpers replaced; previous helpers backed up at '+str(backup))
    print('Scheduler is installed separately; no CT, SMTP, native PBX service or timer was changed.')

if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError,KeyError):
        print('Host helper installation refused/failed; inspect private backup manifest.',file=sys.stderr);sys.exit(1)

PYTHON
)" "$0" "$@"
