#!/bin/bash
set -euo pipefail
command -v python3 >/dev/null || { echo 'python3 is required on the Proxmox host'; exit 1; }
exec python3 -c "$(cat <<'PYTHON'
"""Update existing FreePBX Care scripts. Preview by default; no SMTP or cleanup."""
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
EXPECTED_SHA256 = '4e79638140ad98efe3ec3e433e6fe6473806a631979ac92c2dbe87cbd2276a76'

PAYLOAD = r'''
import datetime, fcntl, hashlib, json, os, pathlib, shutil, subprocess, sys, tempfile
data = json.load(sys.stdin)
source = data['script']
raw = source.encode('utf-8')
if hashlib.sha256(raw).hexdigest() != data['sha256']:
    raise RuntimeError('Payload hash mismatch')
if os.geteuid() != 0 or not pathlib.Path('/etc/freepbx.conf').is_file():
    raise RuntimeError('Requires root inside FreePBX')
os.umask(0o077)
script = pathlib.Path('/root/freepbx-care.sh')
settings = pathlib.Path('/etc/freepbx-care/config.json')
service = pathlib.Path('/etc/systemd/system/freepbx-care.service')
timer = pathlib.Path('/etc/systemd/system/freepbx-care.timer')
if any(path.is_symlink() for path in [script, settings, service, timer]):
    raise RuntimeError('Refusing symlink at an update path')
if any(path.exists() and not path.is_file() for path in [script, settings, service, timer]):
    raise RuntimeError('Refusing non-file at an update path')
needs_install = not service.is_file() or not timer.is_file()
if not script.is_file() or not settings.is_file() or (needs_install and not data.get('install_missing', False)):
    print('FREEPBX_UPDATE_RESULT=' + json.dumps(dict(result='skipped', reason='Incomplete Care installation; --install-missing requires an existing script/config, otherwise use initial setup')))
    sys.exit(0)
if service.is_file() and 'ExecStart=/bin/bash /root/freepbx-care.sh check' not in service.read_text():
    raise RuntimeError('Unrecognized/custom monitoring service; review manually')
if timer.is_file() and 'Unit=freepbx-care.service' not in timer.read_text():
    raise RuntimeError('Unrecognized/custom monitoring timer; review manually')
original = script.read_bytes()
if b'def tick(c):' not in original or b'freepbx-care' not in original:
    raise RuntimeError('Unrecognized current script; review manually')
if pathlib.Path('/var/lib/freepbx-care/module-change-pending.json').exists():
    raise RuntimeError('A module change is pending review; finish it before updating')
code = source.split("<<'PYTHON'\n", 1)[1].rsplit('\nPYTHON\n', 1)[0]
sys.argv = ['/root/freepbx-care.sh']
namespace = {'__name__': 'care_update_validation'}
exec(compile(code, 'freepbx-care.sh:update-validation', 'exec'), namespace)
def validate():
    if namespace['fwconsole_busy']():
        raise RuntimeError('fwconsole operation running; retry later')
    namespace['preflight']()  # OS, legacy cron, local DB, CLI and AMI; no install/recovery.
def atomic(path, contents, mode):
    fd, name = tempfile.mkstemp(prefix='.freepbx-care-update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)
def update():
    validate()
    if script.read_bytes() != original:
        raise RuntimeError('Script changed during inspection; retry')
    if original == raw and not needs_install:
        return dict(result='current', version=namespace['VERSION'])
    if not data['apply']:
        return dict(result='preview', version=namespace['VERSION'], install_missing_units=needs_install)
    backup = pathlib.Path('/var/lib/freepbx-care') / ('update-backup-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    backup.mkdir(mode=0o700, parents=True)
    shutil.copy2(script, backup / 'freepbx-care.sh')
    shutil.copy2(settings, backup / 'config.json')
    for unit in [service, timer]:
        if unit.is_file(): shutil.copy2(unit, backup / unit.name)
    (backup / 'manifest.json').write_text(json.dumps(dict(
        install_missing_units=needs_install, service_existed=service.is_file(), timer_existed=timer.is_file()), indent=2))
    for file in backup.iterdir(): os.chmod(file, 0o600)
    mode = script.stat().st_mode & 0o777
    try:
        atomic(script, raw, 0o700)
        if hashlib.sha256(script.read_bytes()).hexdigest() != data['sha256']:
            raise RuntimeError('Installed hash verification failed')
    except Exception:
        atomic(script, original, mode)
        raise
    if needs_install:
        try:
            # The updater already holds Care's operation lock. Run the loaded
            # installer directly, preserving the existing saved configuration.
            for directory in [settings.parent, backup.parent, pathlib.Path('/var/log/freepbx-care')]:
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(directory, 0o700)
            namespace['install']()
            subprocess.run(['systemctl', 'is-enabled', 'freepbx-care.timer'], check=True, timeout=15)
            subprocess.run(['systemctl', 'is-active', 'freepbx-care.timer'], check=True, timeout=15)
        except Exception:
            print(f'Installation incomplete; inspect script/config/units and {backup}. No automatic installation rollback.')
            raise
    return dict(result='installed' if needs_install else 'updated', version=namespace['VERSION'], backup=str(backup))
if data['apply']:
    fd = os.open('/run/freepbx-care.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Care check/recovery/configuration is running; retry later') from None
        result = update()
else:
    result = update()
print('FREEPBX_UPDATE_RESULT=' + json.dumps(result))
'''


def run(args, timeout=60, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: {(result.stdout + result.stderr)[-2500:].strip()}')
    return result.stdout.strip()


def cluster_nodes(rows):
    nodes = [row for row in rows if row.get('type') == 'node']
    if not nodes or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', str(n.get('name', ''))) for n in nodes):
        raise RuntimeError('Invalid cluster node inventory')
    if len({n['name'] for n in nodes}) != len(nodes) or sum(bool(n.get('local')) for n in nodes) != 1:
        raise RuntimeError('Cannot identify one local cluster node')
    return nodes


def update_cluster(apply, install_missing=False, exclude=()):
    nodes = cluster_nodes(json.loads(run(['pvesh', 'get', '/cluster/status', '--output-format', 'json'])))
    source = Path(sys.argv[0]).read_text()
    failed = []
    for node in nodes:
        name = node['name']
        print(f'===== NODE {name} =====', flush=True)
        if not node.get('online'):
            print(f'NODE {name}: OFFLINE; not updated.', flush=True)
            failed.append(name)
            continue
        if node.get('local'):
            try:
                options = {}
                if install_missing: options['install_missing'] = True
                if exclude: options['exclude'] = exclude
                rc = update_local([], True, apply, **options)
            except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
                print(f'NODE {name}: {e}', flush=True)
                rc = 1
        else:
            command = 'bash -s -- --all-running-freepbx' + (' --apply' if apply else '')
            if install_missing: command += ' --install-missing'
            for ctid in exclude: command += ' --exclude-ctid ' + ctid
            try:
                # Execute this reviewed helper in memory; no peer host script/credentials are installed.
                rc = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                     '-o', 'ConnectTimeout=10', 'root@' + name, command],
                                    input=source, text=True, timeout=21600).returncode
            except (OSError, subprocess.TimeoutExpired) as e:
                print(f'NODE {name}: {e}', flush=True)
                rc = 1
        if rc: failed.append(name)
    print('Cluster nodes requiring attention:', ', '.join(failed) or 'none')
    return 1 if failed else 0


def update_local(explicit, all_running, apply, install_missing=False, exclude=()):
    listing = run(['pct', 'list'], timeout=30)
    ctids = list(dict.fromkeys(explicit)) if not all_running else [
        row[0] for line in listing.splitlines()[1:] if len(row := line.split()) >= 2
        and row[0].isdigit() and row[1] == 'running']
    ctids = [ctid for ctid in ctids if ctid not in set(exclude)]
    if exclude: print('Explicitly excluded CTIDs:', ', '.join(exclude), flush=True)
    print('Mode:', 'APPLY' if apply else 'PREVIEW; add --apply to update', flush=True)
    with urllib.request.urlopen(URL, timeout=45) as response:
        raw = response.read(131073)
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError('Downloaded main script differs from the reviewed version; publish matching updater/main files')
    source = raw.decode('utf-8')
    run(['bash', '-n'], data=source)
    totals = {key: [] for key in ['updated', 'installed', 'current', 'preview', 'skipped', 'failed']}
    for ctid in ctids:
        print(f'===== CT {ctid} =====', flush=True)
        try:
            config = run(['pct', 'config', ctid], timeout=15)
            if re.search(r'(?m)^lock:', config):
                raise RuntimeError('Container locked; retry after backup/migration finishes')
            if run(['pct', 'status', ctid], timeout=15) != 'status: running':
                print('Stopped/unavailable; not started.')
                totals['skipped'].append(ctid)
                continue
            probe = subprocess.run(['pct', 'exec', ctid, '--', 'test', '-f', '/etc/freepbx.conf'], timeout=15)
            if probe.returncode:
                print('FreePBX not detected/probe failed; skipped.')
                totals['skipped'].append(ctid)
                continue
            # Recheck immediately before entering the update payload.
            if re.search(r'(?m)^lock:', run(['pct', 'config', ctid], timeout=15)) or run(
                    ['pct', 'status', ctid], timeout=15) != 'status: running':
                raise RuntimeError('Container stopped or became locked; retry later')
            out = run(['pct', 'exec', ctid, '--', 'python3', '-c', PAYLOAD], timeout=420 if install_missing else 120,
                      data=json.dumps(dict(script=source, sha256=EXPECTED_SHA256, apply=apply, install_missing=install_missing)))
            print(out, flush=True)
            markers = [line.split('=', 1)[1] for line in out.splitlines() if line.startswith('FREEPBX_UPDATE_RESULT=')]
            if len(markers) != 1:
                raise RuntimeError('Missing/ambiguous update result; inspect this container manually')
            result = json.loads(markers[0])
            if result.get('result') not in totals or result['result'] == 'failed':
                raise RuntimeError('Unexpected update result; inspect this container manually')
            totals[result['result']].append(ctid)
        except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            print(f'FAILED CT {ctid}: {e}', flush=True)
            totals['failed'].append(ctid)
    print('Summary:', json.dumps(totals), flush=True)
    print('Existing SMTP, pauses, recovery settings, extension groups and modules are preserved. No cleanup or test mail was run.')
    print('Existing complete installations retain their timer state.')
    print('Missing service/timer units may be installed and enabled only with --install-missing --apply.')
    print('Stopped containers were not selected in all-running mode; update them later when normally running.')
    return 1 if totals['failed'] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--cluster', action='store_true', help='visit all online cluster nodes using existing trusted root SSH')
    group.add_argument('--all-running-freepbx', action='store_true', help='existing Care installations on this node')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--install-missing', action='store_true',
                        help='also complete missing Care service/timer for an existing script/config, preserving saved settings')
    parser.add_argument('--exclude-ctid', action='append', default=[], help='skip this numeric CTID; repeat to exclude more')
    parser.add_argument('ctids', nargs='*')
    args = parser.parse_args()
    if os.geteuid() != 0 or not shutil.which('pct'): parser.error('Run as root on a Proxmox host')
    if any(not re.fullmatch(r'[0-9]+', ctid) for ctid in args.ctids + args.exclude_ctid): parser.error('CTIDs must be numeric')
    if args.ctids and (args.cluster or args.all_running_freepbx): parser.error('Choose explicit CTIDs OR an all/cluster mode')
    if not args.ctids and not (args.cluster or args.all_running_freepbx): parser.error('Specify CTIDs, --all-running-freepbx or --cluster')
    if args.cluster:
        return update_cluster(args.apply, install_missing=args.install_missing, exclude=args.exclude_ctid)
    return update_local(args.ctids, args.all_running_freepbx, args.apply,
                        install_missing=args.install_missing, exclude=args.exclude_ctid)


if __name__ == '__main__':
    try: sys.exit(main())
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
PYTHON
)" "$0" "$@"
