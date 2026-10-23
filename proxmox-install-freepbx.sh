#!/bin/bash
set -euo pipefail
command -v python3 >/dev/null || { echo 'python3 is required on the Proxmox host'; exit 1; }
exec python3 -c "$(cat <<'PYTHON'
"""Configure SMTP and install FreePBX Care across running local LXC containers."""
import argparse
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request

if sys.argv[0] == '-c': sys.argv = sys.argv[1:]
URL = 'https://raw.githubusercontent.com/workimirp201/freepbx-script/refs/heads/main/freepbx-care.sh'
# Refuse changed downloads until a new version has been reviewed.
EXPECTED_SHA256 = '2083706807073be42699e36f44c8b1f973357acc0a493b8fad4bd264404ac031'
PASSWORD = ''


def run(args, timeout=60, data=None):
    p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        detail = (p.stdout + '\n' + p.stderr)[-3000:]
        if PASSWORD: detail = detail.replace(PASSWORD, '[REDACTED]')
        raise RuntimeError(f'{args[0]} exited {p.returncode}: {detail.strip()}')
    return p.stdout.strip()


def select_ctids(listing):
    result = []
    for line in listing.splitlines()[1:]:
        row = line.split()
        if len(row) >= 2 and row[0].isdigit() and row[1] == 'running':
            result.append(row[0])
    return result


def ask(label, default=''):
    value = input(label + (f' [{default}]' if default else '') + ': ').strip()
    return value or default


def shared_settings():
    global PASSWORD
    print('Enter shared settings once. Credentials will not be written to this host script.')
    host = ask('SMTP relay certificate DNS hostname')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host): raise ValueError('Invalid relay hostname')
    port = int(ask('SMTP port', '587'))
    if not 1 <= port <= 65535: raise ValueError('Invalid port')
    tls = ask('TLS mode: starttls or implicit', 'implicit' if port == 465 else 'starttls')
    if tls not in ['starttls', 'implicit']: raise ValueError('Invalid TLS mode')
    username = ask('SMTP username')
    PASSWORD = getpass.getpass('SMTP password: ')
    if not username or re.search(r'[\s:]', username) or not PASSWORD or re.search(r'[\r\n]', PASSWORD):
        raise ValueError('Invalid SMTP credentials')
    sender = ask('Sender email address')
    recipient = ask('Alert recipient', 'monitor@famecomputers.com')
    for email in [sender, recipient]:
        if not re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', email):
            raise ValueError('Invalid email address')
    answer = ask('Enable automatic Asterisk recovery on these containers? y/n', 'n').lower()
    if answer not in ['y', 'n']: raise ValueError('Answer y or n')
    return (dict(host=host, port=port, tls=tls, username=username, password=PASSWORD, sender=sender),
            dict(email=recipient, sender=sender, auto_restart=answer == 'y'))


PREPARE = r'''
import datetime, json, os, pathlib, shutil, sys, tempfile
data = json.load(sys.stdin)
os.umask(0o077)
configpath = pathlib.Path('/etc/freepbx-care/config.json')
scriptpath = pathlib.Path('/root/freepbx-care.sh')
for path in [configpath, scriptpath]:
    if path.is_symlink(): raise RuntimeError('Refusing a symlink at an installation path')
configpath.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
backup = pathlib.Path('/var/lib/freepbx-care') / ('install-backup-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
backup.mkdir(mode=0o700, parents=True)
for path in [configpath, scriptpath]:
    if path.exists():
        shutil.copy2(path, backup / path.name)
        os.chmod(backup / path.name, 0o600)
config = json.loads(configpath.read_text()) if configpath.exists() else {}
config.update(data['settings'])
config.pop('properties', None)
def write(path, value, mode):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), mode)
            f.write(value)
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)
write(scriptpath, data['script'], 0o700)
write(configpath, json.dumps(config, indent=2) + '\n', 0o600)
fd, name = tempfile.mkstemp(prefix='.freepbx-care-smtp-', suffix='.json', dir='/root')
with os.fdopen(fd, 'w') as f:
    os.fchmod(f.fileno(), 0o600)
    json.dump(data['smtp'], f)
print(name)
'''


def deploy(ctid, script, smtp, settings):
    profile = None
    try:
        profile = run(['pct', 'exec', ctid, '--', 'python3', '-c', PREPARE],
                      data=json.dumps(dict(script=script, smtp=smtp, settings=settings)))
        if not re.fullmatch(r'/root/\.freepbx-care-smtp-[A-Za-z0-9_-]+\.json', profile):
            raise RuntimeError('Unexpected SMTP staging filename; no setup command was run')
        base = ['pct', 'exec', ctid, '--', '/bin/bash', '/root/freepbx-care.sh']
        run(base + ['smtp', '--smtp-config', profile], timeout=900)
        run(base + ['install'], timeout=180)
        run(base + ['test-mail'], timeout=60)
        print(f'CT {ctid}: installed; test email accepted by the local queue. Confirm receipt.')
    finally:
        if profile and re.fullmatch(r'/root/\.freepbx-care-smtp-[A-Za-z0-9_-]+\.json', profile):
            try:
                run(['pct', 'exec', ctid, '--', 'python3', '-c',
                     'import os,sys; os.unlink(sys.argv[1])', profile])
            except Exception:
                print(f'CT {ctid}: remove the root-only temporary profile manually when reachable: {profile}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all-running-freepbx', action='store_true')
    parser.add_argument('ctids', nargs='*')
    args = parser.parse_args()
    if os.geteuid() != 0 or not shutil.which('pct'):
        parser.error('Run as root on a Proxmox host')
    if args.all_running_freepbx and args.ctids: parser.error('Choose all or explicit CTIDs')
    if any(not x.isdigit() for x in args.ctids): parser.error('CTIDs must be numeric')
    ctids = select_ctids(run(['pct', 'list'])) if args.all_running_freepbx else list(dict.fromkeys(args.ctids))
    if not ctids: parser.error('Specify CTIDs or --all-running-freepbx')
    targets, skipped, failed = [], [], []
    for ctid in ctids:
        try:
            if run(['pct', 'status', ctid], timeout=15) != 'status: running':
                skipped.append(ctid); continue
            config = run(['pct', 'config', ctid], timeout=15)
            if re.search(r'(?m)^lock:', config):
                print(f'CT {ctid}: locked; retry after backup/migration finishes.')
                failed.append(ctid); continue
            probe = subprocess.run(['pct', 'exec', ctid, '--', 'test', '-f', '/etc/freepbx.conf'], timeout=15)
            if probe.returncode:
                print(f'CT {ctid}: FreePBX not detected or probe failed; skipped.')
                skipped.append(ctid); continue
            targets.append(ctid)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
            print(f'CT {ctid}: {e}'); failed.append(ctid)
    print('FreePBX targets on this node:', ', '.join(targets) or 'none')
    if not targets: return 1 if failed else 0
    with urllib.request.urlopen(URL, timeout=45) as response:
        raw = response.read(131073)
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError('Downloaded main script differs from the reviewed version; update/review the installer first')
    smtp, settings = shared_settings()
    successful = []
    for ctid in targets:
        print(f'===== CT {ctid} =====', flush=True)
        try:
            # Recheck lock/state immediately before writing into this container.
            if run(['pct', 'status', ctid], timeout=15) != 'status: running' or re.search(
                    r'(?m)^lock:', run(['pct', 'config', ctid], timeout=15)):
                raise RuntimeError('Container stopped or became locked; retry later')
            deploy(ctid, raw.decode('utf-8'), smtp, settings)
            successful.append(ctid)
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            detail = str(e).replace(PASSWORD, '[REDACTED]') if PASSWORD else str(e)
            print(f'FAILED CT {ctid}: {detail}', flush=True)
            failed.append(ctid)
    print(f'Summary: installed={successful}; skipped={skipped}; failed={failed}')
    print('Existing settings/scripts were backed up inside each CT under /var/lib/freepbx-care/install-backup-*')
    print('No cleanup was rerun. Confirm received emails; failed CTs may have completed some setup steps.')
    return 1 if failed else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
PYTHON
)" "$0" "$@"
