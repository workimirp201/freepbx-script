#!/bin/bash
set -euo pipefail
command -v python3 >/dev/null || { echo 'python3 is required'; exit 1; }
exec python3 -c "$(cat <<'PYTHON'
"""Sequential, host-pressure-aware scheduler for existing FreePBX Care services."""
import argparse
import email.message
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import re
import subprocess
import sys
import time

if sys.argv[0] == '-c': sys.argv = sys.argv[1:]
ROOT = Path('/var/lib/proxmox-care')
UNIT = 'freepbx-care.service'
TIMER = 'freepbx-care.timer'

def run(args, timeout=15):
    # Only control/probe clients run here. Recovery belongs to the CT systemd unit.
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode: raise RuntimeError(f'{args[0]} returned {p.returncode}: {p.stderr[-500:]}')
    return p.stdout.strip()

def ct(ctid, *args):
    return run(['pct', 'exec', ctid, '--', *args], timeout=45 if args == ('python3', '-c', MANAGE) else 15)

def save(name, value):
    tmp = ROOT / (name + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    os.chmod(tmp, 0o600)
    os.replace(tmp, ROOT / name)

def load(name, default):
    p = ROOT / name
    return json.loads(p.read_text()) if p.exists() else default

def alert(config, state, key, detail):
    print(detail, flush=True)
    now = time.time()
    if now - state.setdefault('alerts', {}).get(key, 0) < 3600: return
    msg = email.message.EmailMessage()
    msg['To'] = config['email']
    msg['Subject'] = f'Proxmox Care {socket.gethostname()}: {key}'
    msg.set_content(detail + '\nReview host journal and container Care diagnostics. No CT was rebooted or killed.')
    try:
        p = subprocess.run(['/usr/sbin/sendmail', '-oi', '-t'], input=msg.as_string(),
                           text=True, capture_output=True, timeout=15)
        if p.returncode: raise RuntimeError('sendmail rejected message')
        state['alerts'][key] = now
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        print(f'EMAIL NOT ACCEPTED: {e}', flush=True)

def pressure(config):
    mem = dict((k.rstrip(':'), int(v.split()[0])) for k, v in
               (line.split(None, 1) for line in Path('/proc/meminfo').read_text().splitlines()))
    if mem['MemAvailable'] / mem['MemTotal'] < config['min_memory_percent'] / 100:
        return 'Low available host memory'
    if os.getloadavg()[0] / (os.cpu_count() or 1) > config['max_load_per_cpu']:
        return 'High host load (CPU or blocked I/O)'
    for kind in ['memory', 'io', 'cpu']:
        p = Path('/proc/pressure') / kind
        if p.exists():
            for line in p.read_text().splitlines():
                fields = dict(item.split('=') for item in line.split()[1:])
                if float(fields['avg10']) > config['max_pressure_percent']:
                    return f'High host {kind} pressure'
    return ''

# Executed in the CT: recognize the existing installation before changing scheduling.
PROBE = r'''
from pathlib import Path
import subprocess
p = Path('/etc/systemd/system')
required = ['/root/freepbx-care.sh', '/etc/freepbx-care/config.json', '/etc/freepbx.conf']
if not all(Path(x).is_file() and not Path(x).is_symlink() for x in required):
    print('missing'); raise SystemExit()
s, t = p/'freepbx-care.service', p/'freepbx-care.timer'
if not all(x.is_file() and not x.is_symlink() for x in [s,t]):
    print('missing'); raise SystemExit()
if ('ExecStart=/bin/bash /root/freepbx-care.sh check' not in s.read_text()
    or 'KillMode=process' not in s.read_text() or 'Unit=freepbx-care.service' not in t.read_text()):
    raise RuntimeError('Custom/unrecognized Care units')
print('recognized')
'''

MANAGE = r'''
import json, os
from pathlib import Path
import subprocess
p = Path('/etc/freepbx-care/node-managed.json')
if p.is_symlink(): raise RuntimeError('Refusing symlink marker')
if not p.exists():
    def value(prop):
        return subprocess.check_output(['systemctl','show','freepbx-care.timer','-p',prop,'--value'], text=True, timeout=10).strip()
    data = dict(enabled=value('UnitFileState'), active=value('ActiveState'))
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f: json.dump(data, f)
subprocess.run(['systemctl','disable','--now','freepbx-care.timer'], check=True, timeout=15)
print(p.read_text())
'''

def inventory():
    return [r.split()[0] for r in run(['pct', 'list']).splitlines()[1:]
            if len(r.split()) >= 2 and r.split()[0].isdigit() and r.split()[1] == 'running'
            and r.split()[0] != '600']

def eligible(ctid):
    if run(['pct', 'status', ctid]) != 'status: running': return False
    if any(x.startswith('lock:') for x in run(['pct', 'config', ctid]).splitlines()): return False
    return ct(ctid, 'python3', '-c', PROBE) == 'recognized'

def adopt(ctid, state, apply, include_inactive=False):
    if not eligible(ctid):
        print(f'CT {ctid}: stopped, locked, or Care not installed; skipped'); return
    enabled = ct(ctid, 'systemctl', 'show', TIMER, '-p', 'UnitFileState', '--value')
    active = ct(ctid, 'systemctl', 'show', TIMER, '-p', 'ActiveState', '--value')
    if ctid not in state['managed'] and not include_inactive and (enabled != 'enabled' or active != 'active'):
        print(f'CT {ctid}: local timer intentionally inactive/disabled; skipped'); return
    print(f'CT {ctid}: transfer scheduling to node' + ('' if apply else ' (preview)'))
    if apply:
        # Save enrollment BEFORE disabling: interrupted adoption remains recoverable.
        state['managed'].setdefault(ctid, dict(enabled=enabled, active=active))
        save('state.json', state)
        # Marker also makes future Care installs preserve node ownership.
        original = json.loads(ct(ctid, 'python3', '-c', MANAGE))
        state['managed'][ctid] = original
        save('state.json', state)

def check(ctid, config, state):
    if not eligible(ctid): return
    ct(ctid, 'python3', '-c', "from pathlib import Path; s=Path('/root/freepbx-care.sh').read_text(); assert 'def unexpected_check_gap(' in s, 'Update Care to r8.4 before central scheduling'")
    # Catch later reinstalls/upgrades re-enabling the local timer.
    ct(ctid, 'systemctl', 'disable', '--now', TIMER)
    state['pending_ct'] = ctid
    save('state.json', state)
    before = ct(ctid, 'systemctl', 'show', UNIT, '-p', 'ActiveState', '--value')
    if before not in ['inactive', 'failed']:
        raise RuntimeError(f'Care already {before}; left untouched')
    ct(ctid, 'systemctl', 'start', '--no-block', UNIT)
    started = time.time()
    deadline = time.monotonic() + config['check_timeout']
    while time.monotonic() < deadline:
        status = ct(ctid, 'systemctl', 'show', UNIT, '-p', 'ActiveState', '-p', 'Result', '-p', 'Job')
        values = dict(line.split('=', 1) for line in status.splitlines())
        if values.get('ActiveState') in ['inactive', 'failed'] and values.get('Job') in [None, '', '0']:
            if values.get('Result') != 'success': raise RuntimeError(f'Care service failed: {status}')
            print(f'CT {ctid}: check completed; PBX alerts/recovery remain handled by Care', flush=True)
            report = json.loads(ct(ctid, 'python3', '-c', REPORT))
            issues = report.get('locks', [])
            if report.get('health_time', 0) >= started - 5 and report.get('healthy') is False:
                issues.append('PBX health check did not pass')
            if issues:
                alert(config, state, f'CT {ctid} health', f'CT {ctid}: ' + '; '.join(issues))
            return
        time.sleep(2)
    raise RuntimeError('Care exceeded scheduler deadline; left running, quarantined for review')

REPORT = r'''
import json
from pathlib import Path
p=Path('/var/lib/freepbx-care/state.json')
s=json.loads(p.read_text()) if p.is_file() else {}
h=s.get('last_health', {})
locks=[name+' recovery requires review' for prefix,name in [('', 'Asterisk'),('database_', 'MariaDB'),('core_fastagi_', 'Core FastAGI')]
       if s.get(prefix+'recovery_blocked') or s.get(prefix+'recovery_inflight')]
print(json.dumps(dict(healthy=h.get('healthy'), health_time=h.get('time',0), locks=locks)))
'''

def prior_finished(state):
    ctid = state.get('pending_ct')
    if not ctid: return True
    if run(['pct', 'status', ctid]) == 'status: stopped':
        state.pop('pending_ct', None); return True
    active = ct(ctid, 'systemctl', 'show', UNIT, '-p', 'ActiveState', '--value')
    if active in ['inactive', 'failed']:
        # A timed-out oneshot can leave a native recovery child running.
        if ct(ctid, 'python3', '-c', BUSY) != 'idle': return False
        state.pop('pending_ct', None); return True
    return False

BUSY = r'''
from pathlib import Path
busy=False
for p in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        if any(a.rsplit(b'/',1)[-1] == b'fwconsole' for a in p.read_bytes().split(b'\0')):
            busy=True; break
    except (OSError, ProcessLookupError): pass
print('busy' if busy else 'idle')
'''

def cluster(args):
    rows = json.loads(run(['pvesh', 'get', '/cluster/status', '--output-format', 'json']))
    nodes = [n for n in rows if n.get('type') == 'node']
    if not nodes or sum(bool(n.get('local')) for n in nodes) != 1:
        raise RuntimeError('Cannot identify local cluster node')
    if any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', str(n.get('name', ''))) for n in nodes):
        raise RuntimeError('Invalid cluster node name')
    source = Path(sys.argv[0]).read_text()
    argv = [args.command]
    if args.apply: argv.append('--apply')
    if args.email: argv += ['--email', args.email]
    argv += args.ctids
    bootstrap = r'''
import json, os, pathlib, subprocess, sys
d=json.load(sys.stdin)
p=pathlib.Path('/root/proxmox-care-scheduler.new.sh')
if p.is_symlink(): raise RuntimeError('Refusing symlink staging path')
fd=os.open(p, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o700)
with os.fdopen(fd,'w') as f: f.write(d['source'])
subprocess.run(['bash','-n',str(p)],check=True,timeout=15)
dest=pathlib.Path('/root/proxmox-care-scheduler.sh')
if dest.is_symlink(): raise RuntimeError('Refusing symlink destination')
os.replace(p,dest)
os.chmod(dest,0o700)
raise SystemExit(subprocess.call(['bash',str(dest)]+d['argv']))
'''
    import shlex
    failures = []
    for node in nodes:
        name = node['name']
        print(f'===== NODE {name} =====', flush=True)
        if not node.get('online'):
            print('OFFLINE; no changes'); failures.append(name); continue
        try:
            if node.get('local'):
                rc = subprocess.run(['bash', sys.argv[0], *argv], timeout=7200).returncode
            else:
                rc = subprocess.run(['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                                     '-o', 'ConnectTimeout=10', 'root@'+name,
                                     'python3 -c ' + shlex.quote(bootstrap)],
                                    input=json.dumps(dict(source=source, argv=argv)), text=True, timeout=7200).returncode
            if rc: failures.append(name)
        except (OSError, subprocess.TimeoutExpired) as e:
            print(f'NODE {name}: {e}', flush=True); failures.append(name)
    print('Nodes requiring attention:', ', '.join(failures) or 'none')
    return 1 if failures else 0

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['install', 'disable-timers', 'adopt', 'run', 'release', 'restore'])
    p.add_argument('ctids', nargs='*')
    p.add_argument('--apply', action='store_true')
    p.add_argument('--email')
    p.add_argument('--cluster', action='store_true', help='apply install/disable-timers on every online cluster node using trusted root SSH')
    p.add_argument('--include-inactive-timers', action='store_true',
                   help='explicitly enroll recognized Care installations whose local timer was stopped/disabled')
    a = p.parse_args()
    if os.geteuid() != 0 or not shutil.which('pct'): p.error('Run as root on a Proxmox node')
    if any(not x.isdigit() or x == '600' for x in a.ctids): p.error('Numeric CTIDs required; CT600 remains excluded')
    if a.cluster:
        if a.command not in ['install', 'disable-timers']: p.error('--cluster supports install or disable-timers')
        return cluster(a)
    os.umask(0o077)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT/'lock').open('w') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('Scheduler already running; no requested changes were made') from None
        state = load('state.json', dict(managed={}, quarantine={}, alerts={}, cursor=''))
        if a.command == 'install':
            if not a.email or '\n' in a.email or '\r' in a.email or '@' not in a.email: p.error('--email required')
            if not Path('/usr/sbin/sendmail').is_file(): p.error('Configure host mail delivery first; sendmail missing')
            config = dict(email=a.email, check_timeout=960, min_memory_percent=15,
                          max_load_per_cpu=1.5, max_pressure_percent=25)
            # Verify queue acceptance before enabling the scheduler.
            alert(config, state, 'installation mail test', 'Confirm receipt before adopting containers.')
            if 'installation mail test' not in state['alerts']: raise RuntimeError('Mail test failed')
            save('config.json', config)
            shutil.copyfile(sys.argv[0], '/root/proxmox-care-scheduler.sh') if Path(sys.argv[0]).resolve() != Path('/root/proxmox-care-scheduler.sh') else None
            os.chmod('/root/proxmox-care-scheduler.sh', 0o700)
            Path('/etc/systemd/system/proxmox-care.service').write_text('[Unit]\nDescription=Sequential FreePBX Care scheduler\n[Service]\nType=oneshot\nExecStart=/bin/bash /root/proxmox-care-scheduler.sh run\nTimeoutStartSec=1200\nNice=10\nIOSchedulingClass=idle\n')
            Path('/etc/systemd/system/proxmox-care.timer').write_text('[Unit]\nDescription=Schedule next PBX check\n[Timer]\nOnBootSec=5min\nOnUnitInactiveSec=10s\nUnit=proxmox-care.service\n[Install]\nWantedBy=timers.target\n')
            run(['systemctl', 'daemon-reload']); run(['systemctl', 'enable', '--now', 'proxmox-care.timer'])
        elif a.command in ['adopt', 'disable-timers']:
            if a.command == 'adopt' and a.apply and not (ROOT/'config.json').is_file():
                raise RuntimeError('Install the host scheduler before transferring timers')
            targets = a.ctids or inventory()
            failed = []
            for ctid in targets:
                if ctid == '600': continue
                try: adopt(ctid, state, a.apply, a.include_inactive_timers or a.command == 'disable-timers')
                except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                    print(f'CT {ctid}: adoption failed: {e}'); failed.append(ctid)
            save('state.json', state)
            if failed: raise RuntimeError('Timer transfer failed for CTs: ' + ', '.join(failed))
        elif a.command in ['release', 'restore']:
            if not a.ctids: p.error('Explicit CTIDs required')
            for ctid in a.ctids:
                if a.command == 'release': state['quarantine'].pop(ctid, None)
                elif ctid in state['managed']:
                    if not eligible(ctid): raise RuntimeError(f'CT {ctid} unavailable; enrollment retained')
                    original = state['managed'][ctid]
                    ct(ctid, 'systemctl', 'enable' if original['enabled'] == 'enabled' else 'disable', TIMER)
                    ct(ctid, 'systemctl', 'start' if original['active'] == 'active' else 'stop', TIMER)
                    ct(ctid, 'rm', '-f', '/etc/freepbx-care/node-managed.json')
                    del state['managed'][ctid]
                    state.setdefault('excluded', []).append(ctid)
                    state['quarantine'].pop(ctid, None)
                    save('state.json', state)
        else:
            config = load('config.json', None)
            if config is None: raise RuntimeError('Install scheduler first')
            try:
                if not prior_finished(state):
                    raise RuntimeError('Previous Care service still running; deferring new checks to preserve sequential execution')
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                alert(config, state, 'pending check', str(e))
                save('state.json', state)
                return
            reason = pressure(config)
            if reason: alert(config, state, 'host pressure', reason + '; no new check launched')
            else:
                # Probe one candidate per invocation, never bootstrap missing Care.
                targets = sorted(set(inventory()) - set(state['quarantine']) - set(state.get('excluded', [])), key=int)
                if targets:
                    ctid = next((x for x in targets if int(x) > int(state['cursor'] or '0')), targets[0])
                    state['cursor'] = ctid
                    # Persist uncertain work before launch; host restart requires review.
                    state['quarantine'][ctid] = 'Check interrupted or pending'
                    save('state.json', state)
                    try:
                        adopt(ctid, state, True, include_inactive=True)
                        check(ctid, config, state)
                        state.pop('pending_ct', None)
                        del state['quarantine'][ctid]
                    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                        state['quarantine'][ctid] = str(e)
                        alert(config, state, f'CT {ctid}', f'CT {ctid}: {e}; next scheduler invocation moves to the next CT')
            for ctid, reason in state['quarantine'].items():
                alert(config, state, f'CT {ctid}', f'CT {ctid} quarantined: {reason}')
        save('state.json', state)

if __name__ == '__main__':
    try: sys.exit(main() or 0)
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
        print(f'ERROR: {e}', file=sys.stderr); sys.exit(1)
PYTHON
)" "$0" "$@"
