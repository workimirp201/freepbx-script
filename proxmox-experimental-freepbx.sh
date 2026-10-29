#!/bin/bash
set -euo pipefail
command -v python3 >/dev/null || { echo 'python3 is required'; exit 1; }
exec python3 -c "$(cat <<'PYTHON'
"""Opt existing Debian 13 FreePBX containers into experimental alert-only Care."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request

if sys.argv[0] == '-c': sys.argv = sys.argv[1:]
URL = 'https://raw.githubusercontent.com/workimirp201/freepbx-script/refs/heads/main/freepbx-care.sh'
EXPECTED_SHA256 = 'f25ad96323c0c53f8c63840f0d4b0525e8dac7dc2b928a6bd4754ee7e4bed1d2'

PAYLOAD = r'''
import datetime, hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile
data = json.load(sys.stdin)
raw = data['script'].encode('utf-8')
if hashlib.sha256(raw).hexdigest() != data['sha256']:
    raise RuntimeError('Payload hash mismatch')
os.umask(0o077)
script = pathlib.Path('/root/freepbx-care.sh')
settings = pathlib.Path('/etc/freepbx-care/config.json')
service = pathlib.Path('/etc/systemd/system/freepbx-care.service')
timer = pathlib.Path('/etc/systemd/system/freepbx-care.timer')
if os.geteuid() != 0 or not pathlib.Path('/etc/freepbx.conf').is_file():
    raise RuntimeError('Requires root inside FreePBX')
for path in [script, settings, service, timer]:
    if path.is_symlink(): raise RuntimeError('Refusing installation-path symlink')
    if path.exists() and not path.is_file(): raise RuntimeError('Installation path is not a regular file')
if not script.is_file() or not settings.is_file():
    raise RuntimeError('Existing Care script and saved config required; initial SMTP setup is separate')
if b'def tick(c):' not in script.read_bytes():
    raise RuntimeError('Unrecognized existing Care script')
if service.exists() and 'ExecStart=/bin/bash /root/freepbx-care.sh check' not in service.read_text():
    raise RuntimeError('Custom service requires manual review')
code = data['script'].split("<<'PYTHON'\n", 1)[1].rsplit('\nPYTHON\n', 1)[0]
sys.argv = ['/root/freepbx-care.sh']
ns = {'__name__': 'experimental_validation'}
exec(compile(code, 'care-experimental', 'exec'), ns)
info = ns['parse_os_release'](pathlib.Path('/etc/os-release').read_text())
if info.get('ID') != 'debian' or info.get('VERSION_ID') != '13':
    print('EXPERIMENTAL_RESULT=skipped (not Debian 13)')
    sys.exit(0)
ns['EXPERIMENTAL_DEBIAN13'] = True
def validate():
    if ns['fwconsole_busy'](): raise RuntimeError('fwconsole operation running; retry later')
    if pathlib.Path('/var/lib/freepbx-care/module-change-pending.json').exists():
        raise RuntimeError('Pending module change requires review')
    ns['preflight']()
    for cmd in ['fwconsole', 'asterisk', 'php', 'systemctl', 'crontab', 'pgrep']:
        if not shutil.which(cmd): raise RuntimeError('Missing required command: ' + cmd)
    if not pathlib.Path('/usr/sbin/sendmail').exists():
        raise RuntimeError('Existing SMTP/sendmail setup required; no packages will be installed')
def apply():
    validate()
    backup_root = pathlib.Path('/var/lib/freepbx-care')
    backup_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup = pathlib.Path(tempfile.mkdtemp(prefix='experimental-backup-', dir=backup_root))
    present = []
    for path in [script, settings, service, timer]:
        if path.exists():
            shutil.copy2(path, backup / path.name)
            os.chmod(backup / path.name, 0o600)
            present.append(str(path))
    result = subprocess.run(['systemctl', 'is-enabled', 'freepbx-care.timer'], capture_output=True, text=True)
    active = subprocess.run(['systemctl', 'is-active', 'freepbx-care.timer'], capture_output=True, text=True)
    (backup / 'manifest.json').write_text(json.dumps(dict(present=present,
        previous_timer_enabled=result.stdout.strip(), previous_timer_active=active.stdout.strip()), indent=2))
    print('BACKUP=' + str(backup), flush=True)
    fd, stage = tempfile.mkstemp(prefix='.freepbx-care-experimental-', dir='/root')
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o700)
            stream.write(raw)
        for directory in [ns['ETC'], ns['STATE'], ns['LOG']]:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        # The parent owns Care's operation lock; call the loaded installer directly
        # instead of launching another process that would contend for that lock.
        ns['__file__'] = stage
        ns['install']()
        subprocess.run(['systemctl', 'is-enabled', 'freepbx-care.timer'], check=True, timeout=15)
        subprocess.run(['systemctl', 'is-active', 'freepbx-care.timer'], check=True, timeout=15)
        ns['status']()
    except Exception:
        print('Installation failed or verification incomplete; inspect backup and timer state. No automatic rollback.', flush=True)
        raise
    finally:
        if os.path.exists(stage): os.unlink(stage)
if data['apply']:
    with ns['operation_lock'](): apply()
    print('EXPERIMENTAL_RESULT=installed-alert-only')
else:
    validate()
    print('EXPERIMENTAL_RESULT=preview-alert-only')
'''

def run(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=kwargs.pop('timeout', 30), **kwargs)
    if result.returncode: raise RuntimeError((result.stdout + '\n' + result.stderr)[-3500:])
    return result.stdout.strip()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experimental-debian13', action='store_true', required=True)
    parser.add_argument('--all-running-freepbx', action='store_true')
    parser.add_argument('--apply', action='store_true', help='install and enable alert-only monitoring; preview is default')
    parser.add_argument('ctids', nargs='*')
    args = parser.parse_args()
    if os.geteuid() != 0 or not shutil.which('pct'): parser.error('Run as root on a Proxmox host')
    if args.all_running_freepbx and args.ctids: parser.error('Choose all-running OR CTIDs')
    if any(not re.fullmatch(r'[0-9]+', ctid) for ctid in args.ctids): parser.error('CTIDs must be numeric')
    if not args.all_running_freepbx and not args.ctids: parser.error('Specify CTIDs or --all-running-freepbx')
    listing = run(['pct', 'list'])
    ctids = [row[0] for line in listing.splitlines()[1:] if len(row := line.split()) >= 2
             and row[0].isdigit() and row[1] == 'running'] if args.all_running_freepbx else list(dict.fromkeys(args.ctids))
    with urllib.request.urlopen(URL, timeout=45) as response: raw = response.read(131073)
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError('Download differs from reviewed version; publish matching main and helper')
    run(['bash', '-n'], input=raw.decode('utf-8'))
    failed = []
    print('APPLY: enabling experimental alert-only timers' if args.apply else 'PREVIEW: no installation changes')
    for ctid in ctids:
        print('===== CT ' + ctid + ' =====', flush=True)
        try:
            if run(['pct', 'status', ctid], timeout=15) != 'status: running':
                print('SKIP: stopped'); continue
            if re.search(r'(?m)^lock:', run(['pct', 'config', ctid], timeout=15)):
                raise RuntimeError('Container locked; retry later')
            probe = subprocess.run(['pct', 'exec', ctid, '--', 'test', '-f', '/etc/freepbx.conf'], timeout=15)
            if probe.returncode: print('SKIP: FreePBX not detected'); continue
            print(run(['pct', 'exec', ctid, '--', 'python3', '-c', PAYLOAD], timeout=420,
                      input=json.dumps(dict(script=raw.decode('utf-8'), sha256=EXPECTED_SHA256, apply=args.apply))))
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
            print('FAILED CT ' + ctid + ': ' + str(e), flush=True)
            failed.append(ctid)
    print('Failed CTs:', ', '.join(failed) or 'none')
    return 1 if failed else 0

if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
PYTHON
)" "$0" "$@"
