#!/bin/bash
set -euo pipefail
command -v python3 >/dev/null || { echo 'Install python3 first: apt-get install python3'; exit 1; }
exec python3 -c "$(cat <<'PYTHON'
"""Single-file FreePBX 17 administrator and bounded watchdog. Run with bash."""
import argparse
import copy
from contextlib import contextmanager
import datetime
import email.message
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

if sys.argv[0] == '-c':
    sys.argv = sys.argv[1:]
__file__ = sys.argv[0]

os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
ETC = Path('/etc/freepbx-care')
STATE = Path('/var/lib/freepbx-care')
LOG = Path('/var/log/freepbx-care')
SELF = Path('/root/freepbx-care.sh')
VERSION = '2026.10.23-extensions-r4'
DEFAULT = dict(email='monitor@famecomputers.com', sender='', auto_restart=True,
               failures=3, cooldown=1800, max_restarts_hour=2, boot_grace=300,
               resume_grace=180, defer_active_calls=True, ami={},
               extension_monitor=dict(enabled=False, failures=3, groups=[]))


def run(args, timeout=15, data=None, kill_group=True):
    """No shell. Recovery preserves daemons that fwconsole may have started."""
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = p.communicate(data, timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired as expired:
        if not kill_group:
            # Do not kill a newly launched Asterisk/PM2 daemon with its parent.
            # Avoid communicate(): descendants may still hold the pipe open.
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=3)
            out = expired.output or ''
            err = expired.stderr or ''
            if isinstance(out, bytes): out = out.decode(errors='replace')
            if isinstance(err, bytes): err = err.decode(errors='replace')
            p.stdout.close()
            p.stderr.close()
            return 124, out, err + '\ncommand timed out; recovery requires operator review'
        os.killpg(p.pid, signal.SIGTERM)
        try:
            out, err = p.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            out, err = p.communicate()
        return 124, out, err + '\ncommand timed out'


def checked(args, timeout=60):
    rc, out, err = run(args, timeout)
    if rc:
        raise RuntimeError(f'{args[0]} failed (exit {rc}); {err[:300]}')
    return out


def atomic(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w', newline='\n') as f:
            os.fchmod(f.fileno(), mode)
            f.write(value)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save(path, value):
    atomic(path, json.dumps(value, indent=2) + '\n')


def readjson(path, default):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return copy.deepcopy(default)


def config():
    c = copy.deepcopy(DEFAULT)
    c.update(readjson(ETC / 'config.json', {}))
    c.pop('properties', None)  # Old property data is not enabled without technician review.
    validate(c)
    return c


def address(s):
    return bool(re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', s))


def validate(c):
    if not address(c['email']) or (c['sender'] and not address(c['sender'])):
        raise ValueError('Invalid notification email or sender')
    for key, low, high in [('failures', 2, 60), ('cooldown', 300, 86400),
                           ('max_restarts_hour', 1, 6), ('boot_grace', 60, 3600),
                           ('resume_grace', 60, 900)]:
        if type(c[key]) is not int or not low <= c[key] <= high:
            raise ValueError(f'Invalid {key}: expected {low}..{high}')
    for key in ['auto_restart', 'defer_active_calls']:
        if type(c[key]) is not bool:
            raise ValueError(f'{key} must be boolean')
    validate_extensions(c['extension_monitor'])


def validate_extensions(settings):
    if not isinstance(settings, dict) or type(settings.get('enabled')) is not bool:
        raise ValueError('Invalid extension monitoring settings')
    if type(settings.get('failures')) is not int or not 2 <= settings['failures'] <= 60:
        raise ValueError('Extension failed checks must be 2..60')
    groups = settings.get('groups')
    if not isinstance(groups, list) or len(groups) > 100 or (settings['enabled'] and not groups):
        raise ValueError('Enabled extension monitoring needs 1..100 groups')
    names = set()
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError('Invalid extension group')
        name = group.get('name')
        if (not isinstance(name, str) or not name.strip() or len(name) > 100 or
                any(ord(ch) < 32 or ord(ch) == 127 for ch in name) or name.casefold() in names):
            raise ValueError('Use unique property names, 1..100 characters, without control characters')
        names.add(name.casefold())
        extensions = group.get('extensions')
        if (not isinstance(extensions, list) or not 1 <= len(extensions) <= 500 or
                any(not isinstance(ext, str) or not re.fullmatch(r'[0-9]{1,20}', ext) for ext in extensions) or
                len(set(extensions)) != len(extensions)):
            raise ValueError('Each group needs 1..500 unique numeric PJSIP extension/AOR IDs')
        if group.get('mode') not in ['all', 'any']:
            raise ValueError('Extension alert mode must be all or any')


def log(message):
    print(f'{datetime.datetime.now().astimezone().isoformat()} {message}', flush=True)


def notify(c, subject, body):
    msg = email.message.EmailMessage()
    msg['To'] = c['email']
    msg['From'] = c['sender'] or ('root@' + socket.getfqdn())
    msg['Subject'] = f'FreePBX {socket.gethostname()}: {subject}'
    msg.set_content(body)
    try:
        rc, _, _ = run(['/usr/sbin/sendmail', '-oi', '-f', str(msg['From']), '--', c['email']],
                       data=msg.as_string())
        if rc:
            log(f'Email queue submission failed ({rc})')
        return rc == 0
    except OSError:
        log('sendmail unavailable; email was not queued')
        return False


def transition(c, state, key, status, body):
    previous = state.setdefault('notified', {}).get(key)
    # Initial healthy checks do not generate recovery messages.
    if previous is None and status == 'healthy':
        state['notified'][key] = status
    elif previous != status:
        log(f'{key}: {status}; {body}')
        if notify(c, f'{key}: {status}', body):
            state['notified'][key] = status


def cli(command):
    return run(['asterisk', '-rx', command])


def pjsip_rows(text, label):
    """Reject incomplete/unknown CLI output instead of interpreting it as offline."""
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*' + label + r':\s+(.*)$', line)
        if match and not match[1].startswith('<'):
            rows.append(match[1].split())
    footer = re.search(r'(?m)^\s*Objects found:\s*(\d+)\s*$', text)
    empty = re.search(r'(?m)^\s*No objects found\.\s*$', text)
    if (not footer or int(footer[1]) != len(rows)) and not (empty and not rows):
        raise RuntimeError('Incomplete or unsupported PJSIP CLI output')
    return rows


def extension_report(c):
    """One contact query and one AOR inventory query, shared across all groups."""
    settings = c['extension_monitor']
    if not settings['enabled']:
        return dict(enabled=False, groups=[])
    try:
        outputs = []
        for command in ['pjsip show contacts', 'pjsip list aors']:
            rc, out, _ = cli(command)
            if rc:
                raise RuntimeError('PJSIP CLI query failed or timed out')
            outputs.append(out)
        aors = set()
        for row in pjsip_rows(outputs[1], 'Aor'):
            if len(row) != 2 or not row[1].isdigit():
                raise RuntimeError('Unsupported PJSIP AOR row')
            aors.add(row[0])
        contacts = {}
        for row in pjsip_rows(outputs[0], 'Contact'):
            if len(row) != 4 or '/' not in row[0]:
                raise RuntimeError('Unsupported PJSIP contact row')
            aor = row[0].split('/', 1)[0]
            contacts.setdefault(aor, []).append(row[2])
        groups = []
        for group in settings['groups']:
            states = {}
            for ext in group['extensions']:
                values = contacts.get(ext, [])
                if ext not in aors:
                    states[ext] = 'unknown'  # Typo, deleted AOR or unsupported driver.
                elif 'Avail' in values:
                    states[ext] = 'available'
                elif not values or all(value == 'Unavail' for value in values):
                    states[ext] = 'unavailable'
                else:
                    states[ext] = 'unknown'  # Includes NonQual: present, not proven reachable.
            values = list(states.values())
            if group['mode'] == 'all':
                status = ('healthy' if 'available' in values else
                          'outage' if all(v == 'unavailable' for v in values) else 'unknown')
            else:
                status = ('outage' if 'unavailable' in values else
                          'healthy' if all(v == 'available' for v in values) else 'unknown')
            groups.append(dict(name=group['name'], mode=group['mode'], status=status, extensions=states))
        return dict(enabled=True, groups=groups)
    except (RuntimeError, ValueError, OSError) as e:
        return dict(enabled=True, groups=[], error=str(e))


def reset_extension_debounce(c):
    if not c['extension_monitor']['enabled']:
        return
    path = STATE / 'extensions.json'
    try:
        st = readjson(path, {})
        for value in st.get('groups', {}).values():
            value['failures'] = 0
        st['collection_failures'] = 0
        save(path, st)
    except (ValueError, OSError) as e:
        log(f'Cannot reset extension debounce state: {e}; administrator review needed')


def extensions_tick(c, pbx_healthy):
    """Alert only. This code never invokes recovery or changes PBX health counters."""
    if not c['extension_monitor']['enabled']:
        return
    if not pbx_healthy:
        reset_extension_debounce(c)
        log('Extension checks deferred: PBX health checks have not passed')
        return
    report = extension_report(c)
    path = STATE / 'extensions.json'
    st = readjson(path, {})
    now = time.time()
    groups = st.setdefault('groups', {})
    if now - st.get('last_observed', now) > 300:
        st['collection_failures'] = 0
        for value in groups.values():
            value['failures'] = 0
    st.update(last_observed=now, last_report=report)
    # Bound local sendmail wait time when many properties change at once.
    # Unsent transitions stay pending for subsequent checks.
    remaining = 5
    def announce(target, key, status, body):
        nonlocal remaining
        previous = target.get('notified', {}).get(key)
        if previous != status and not (previous is None and status == 'healthy'):
            if remaining == 0:
                log(f'Extension notification deferred to a later check: {key}')
                return
            remaining -= 1
        transition(c, target, key, status, body)
    unknown = report.get('error') or any(g['status'] == 'unknown' or
        'unknown' in g['extensions'].values() for g in report['groups'])
    if unknown:
        st['collection_failures'] = st.get('collection_failures', 0) + 1
        if st['collection_failures'] >= c['extension_monitor']['failures']:
            announce(st, 'Extension collection', 'outage',
                       'Cannot establish all extension states. Check PJSIP IDs, qualify settings and CLI output.\n' +
                       json.dumps(report, indent=2))
    else:
        st['collection_failures'] = 0
        announce(st, 'Extension collection', 'healthy', 'PJSIP extension state collection restored.')
    if report.get('error'):
        for value in groups.values():
            value['failures'] = 0
        log('Extension collection unavailable: ' + report['error'])
    else:
        active = set()
        for definition, result in zip(c['extension_monitor']['groups'], report['groups']):
            name = definition['name']
            active.add(name)
            signature = json.dumps(definition, sort_keys=True)
            entry = groups.setdefault(name, {})
            if entry.get('definition') != signature:
                entry = groups[name] = dict(definition=signature)
            entry['last_status'] = result['status']
            if result['status'] == 'outage':
                entry['failures'] = entry.get('failures', 0) + 1
                if entry['failures'] >= c['extension_monitor']['failures']:
                    announce(entry, name, 'outage', json.dumps(result, indent=2))
            else:
                entry['failures'] = 0
                if result['status'] == 'healthy':
                    meaning = ('At least one monitored extension is available again.' if definition['mode'] == 'all'
                               else 'All monitored extensions are available again.')
                    announce(entry, name, 'healthy', meaning + '\n' + json.dumps(result, indent=2))
            log(f"Extensions {name}: {result['status']}")
        st['groups'] = {name: value for name, value in groups.items() if name in active}
    save(path, st)


def configure_extensions():
    c = config()
    settings = copy.deepcopy(c['extension_monitor'])
    print('PJSIP extension alerts only; extension outages NEVER restart Asterisk.')
    print('Current groups:', json.dumps(settings['groups'], indent=2))
    answer = ask('Enable extension monitoring? y/n', 'y' if settings['enabled'] else 'n').lower()
    if answer not in ['y', 'n']:
        raise ValueError('Answer y or n')
    if answer == 'n':
        settings['enabled'] = False
    else:
        settings['enabled'] = True
        settings['failures'] = int(ask('Extension consecutive failed checks', str(settings['failures'])))
        edit = ask('Replace property/extension groups? y/n', 'n' if settings['groups'] else 'y').lower()
        if edit not in ['y', 'n']:
            raise ValueError('Answer y or n')
        if edit == 'y':
            count = int(ask('How many properties/groups', '1'))
            if not 1 <= count <= 100:
                raise ValueError('Use 1..100 groups')
            settings['groups'] = []
            for i in range(count):
                name = ask(f'Property/group {i + 1} name')
                exts = re.split(r'[\s,]+', ask('PJSIP extension numbers (spaces or commas)').strip())
                print('all = alert only when ALL selected extensions are unavailable (legacy behavior).')
                print('any = alert when ANY selected extension is unavailable.')
                mode = ask('Outage mode: all or any', 'all').lower()
                settings['groups'].append(dict(name=name, extensions=exts, mode=mode))
    validate_extensions(settings)
    candidate = copy.deepcopy(c)
    candidate['extension_monitor'] = settings
    if settings['enabled']:
        report = extension_report(candidate)
        print('Extension preview (no email/restart):', json.dumps(report, indent=2))
        if (report.get('error') or any('unknown' in g['extensions'].values() for g in report['groups'])):
            raise RuntimeError('Settings NOT saved: resolve unknown PJSIP IDs/NonQual/CLI output, then retry')
    c['extension_monitor'] = settings
    save(ETC / 'config.json', c)
    # Keep notification history for unchanged definitions; edits are reset on the next tick.
    reset_extension_debounce(c)
    print('Extension settings saved. Uses the existing Care timer; install with option 2 if not enabled.')


PHP_CONFIG = r'''
$bootstrap_settings['skip_astman'] = true;
$bootstrap_settings['freepbx_auth'] = false;
$bootstrap_settings['freepbx_error_handler'] = false;
$restrict_mods = true;
ob_start();
require '/etc/freepbx.conf';
ob_end_clean();
echo json_encode(array('host' => $amp_conf['ASTMANAGERHOST'] ?? '127.0.0.1',
 'port' => $amp_conf['ASTMANAGERPORT'] ?? 5038,
 'username' => $amp_conf['AMPMGRUSER'] ?? '',
 'secret' => $amp_conf['AMPMGRPASS'] ?? ''));
'''


def ami_credentials(c):
    if c['ami']:
        a = c['ami']
    else:
        rc, out, _ = run(['php', '-d', 'display_errors=0', '-r', PHP_CONFIG])
        if rc:
            raise ValueError('FreePBX configuration/database bootstrap failed')
        try:
            a = json.loads(out)
        except ValueError:
            raise ValueError('Cannot read FreePBX AMI configuration') from None
    if not a.get('username') or not a.get('secret'):
        raise ValueError('FreePBX AMI credentials missing')
    if any('\n' in str(v) or '\r' in str(v) for v in a.values()):
        raise ValueError('Invalid AMI configuration')
    # Only local plain AMI; never send the FreePBX secret over a remote network.
    if a.get('host', '127.0.0.1') not in ['127.0.0.1', 'localhost', '::1']:
        raise ValueError('AMI host is nonlocal; configure a local AMI override')
    return a


def ami_probe(c):
    try:
        a = ami_credentials(c)
    except (ValueError, OSError):
        return 'config_error'
    try:
        with socket.create_connection((a.get('host', '127.0.0.1'), int(a.get('port', 5038))), 5) as s:
            s.settimeout(5)
            # Unbuffered frame reader, with one deadline for the entire exchange.
            deadline = time.monotonic() + 10
            buf = b''

            def frame():
                nonlocal buf
                while b'\r\n\r\n' not in buf:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    s.settimeout(remaining)
                    chunk = s.recv(4096)
                    if not chunk or len(buf) > 65536:
                        raise OSError('Invalid AMI response')
                    buf += chunk
                raw, buf = buf.split(b'\r\n\r\n', 1)
                return dict(line.split(': ', 1) for line in raw.decode(errors='replace').split('\r\n') if ': ' in line)

            s.sendall(('Action: Login\r\nActionID: login\r\nUsername: ' + a['username'] +
                       '\r\nSecret: ' + a['secret'] + '\r\nEvents: off\r\n\r\n').encode())
            while True:
                f = frame()
                if f.get('ActionID') == 'login':
                    if f.get('Response') != 'Success':
                        return 'auth_error'
                    break
            s.sendall(b'Action: Ping\r\nActionID: care-ping\r\n\r\n')
            while True:
                f = frame()
                if f.get('ActionID') == 'care-ping':
                    return 'healthy' if f.get('Ping') == 'Pong' else 'protocol_error'
    except (OSError, ValueError):
        return 'unreachable'


def health(c):
    rc, out, _ = cli('core show uptime seconds')
    cli_ok = rc == 0 and bool(re.search(r'System uptime:\s*\d+', out))
    ami = ami_probe(c)
    return dict(cli=cli_ok, ami=ami, healthy=cli_ok and ami == 'healthy',
                restartable=(not cli_ok or ami == 'unreachable'))


def fwconsole_busy():
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        if path.parent.name == str(os.getpid()):
            continue
        try:
            args = path.read_bytes().split(b'\0')
            if any(a.rsplit(b'/', 1)[-1] == b'fwconsole' for a in args):
                return True
        except (OSError, ProcessLookupError):
            continue
    return False


def recovery_command(h):
    if not h['cli']:
        rc, _, _ = run(['pgrep', '-x', 'asterisk'])
        if rc == 1:
            return ['fwconsole', 'start']
        if rc != 0:
            return None
    return ['fwconsole', 'restart']


def snapshot(h):
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    dest = LOG / f'incident-{stamp}.log'
    chunks = [json.dumps(h)]
    for cmd in [['asterisk', '-rx', 'core show uptime'],
                ['asterisk', '-rx', 'core show channels count'],
                ['asterisk', '-rx', 'manager show settings'],
                ['systemctl', 'status', 'incron', 'mariadb', 'freepbx', 'apache2', '--no-pager'],
                ['journalctl', '-u', 'incron', '-u', 'mariadb', '-u', 'freepbx',
                 '-u', 'apache2', '-n', '100', '--no-pager'],
                ['tail', '-n', '150', '/var/log/asterisk/full'],
                ['ps', '-eo', 'pid,ppid,user,stat,etimes,comm'],
                ['systemd-detect-virt', '--container'],
                ['cat', '/sys/fs/cgroup/memory.events', '/sys/fs/cgroup/memory.current',
                 '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/cpu.stat'],
                ['df', '-h', '/', '/var'], ['free', '-m'],
                ['journalctl', '-k', '-n', '40', '--no-pager']]:
        rc, out, err = run(cmd, 5)
        chunks.append(f'\n$ {" ".join(cmd)} (exit {rc})\n{out}{err}')
    atomic(dest, '\n'.join(chunks))
    # Bound storage, retaining the most recent twenty incidents.
    for old in sorted(LOG.glob('incident-*.log'))[:-20]:
        old.unlink()
    return dest


def tick(c):
    statepath = STATE / 'state.json'
    st = readjson(statepath, {})
    now = time.time()
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if st.get('boot') != boot:
        st.update(boot=boot, failures=0)
        reset_extension_debounce(c)
    # Long scheduling gaps can follow LXC suspension, backup or host overload.
    gap = now - st.get('last_observed', now)
    if gap > 300:
        st.update(failures=0, settle_until=now + c['resume_grace'])
        reset_extension_debounce(c)
    st['last_observed'] = now
    uptime = float(Path('/proc/uptime').read_text().split()[0])
    paused = (readjson(STATE / 'pause.json', {}).get('until', 0) > now or
              readjson(STATE / 'backup-pause.json', {}).get('until', 0) > now)
    if paused or uptime < c['boot_grace'] or st.get('settle_until', 0) > now or fwconsole_busy():
        st['failures'] = 0
        reset_extension_debounce(c)
        save(statepath, st)
        log('Monitoring skipped: pause, boot/resume grace, or another fwconsole operation')
        return
    h = health(c)
    log(f"Health: CLI={h['cli']} AMI={h['ami']}")
    st['last_health'] = dict(h, time=now)
    if h['healthy']:
        st['failures'] = 0
        transition(c, st, 'PBX', 'healthy', 'CLI and authenticated AMI Ping passed.')
    else:
        st['failures'] = st.get('failures', 0) + 1
        if st['failures'] >= c['failures']:
            transition(c, st, 'PBX', 'outage', json.dumps(h))
            history = [t for t in st.get('restarts', []) if now - t < 3600]
            allowed = (c['auto_restart'] and h['restartable'] and not st.get('recovery_blocked') and
                       now - st.get('last_restart', 0) >= c['cooldown'] and
                       len(history) < c['max_restarts_hour'])
            if allowed and c['defer_active_calls'] and h['cli']:
                rc, out, _ = cli('core show channels count')
                m = re.search(r'(?m)^\s*(\d+) active channels?\b', out)
                if rc or not m or int(m[1]) > 0:
                    allowed = False
                    log('Restart deferred: active channels or channel count unknown')
            if allowed:
                command = recovery_command(h)
                if command is None:
                    log('Recovery deferred: cannot determine Asterisk process state')
                    save(statepath, st)
                    return
                # Capture evidence and persist the attempt BEFORE starting fwconsole.
                evidence = snapshot(h)
                st.update(last_restart=now, restarts=history + [now], failures=0)
                save(statepath, st)
                log(f'Recovery via {" ".join(command)}; evidence: {evidence}')
                rc, out, err = run(command, 600, kill_group=False)
                if rc == 124:
                    st['recovery_blocked'] = True
                    save(statepath, st)
                atomic(LOG / 'last-restart.log', f'exit={rc}\n{out}\n{err}')
                after = health(c)
                failed_evidence = str(snapshot(after)) if rc or not after['healthy'] else None
                st['last_restart_result'] = dict(exit=rc, command=command, health=after, time=time.time(),
                                                failure_evidence=failed_evidence)
                notify(c, 'recovery attempted', f'{" ".join(command)} exit={rc}; post-check={json.dumps(after)}; evidence={evidence}; failure evidence={failed_evidence}')
                log(f'Restart completed: exit={rc}; health={after}')
            elif not h['restartable']:
                log('Configuration/authentication/protocol problem: automatic restart suppressed')
    save(statepath, st)
    # Optional extension checks run after the core watchdog and cannot request recovery.
    try:
        extensions_tick(c, h['healthy'])
    except (RuntimeError, ValueError, OSError) as e:
        log(f'Extension monitoring failed: {e}; core PBX check completed')


def ask(label, default='', secret=False):
    hint = (' [Enter retains current value]' if secret else f' [{default}]') if default else ''
    prompt = label + hint + ': '
    value = getpass.getpass(prompt) if secret else input(prompt)
    return (value if secret else value.strip()) or default


def configure():
    c = config()
    c['email'] = ask('Alert recipient', c['email'])
    c['sender'] = ask('Sender email (blank keeps system default)', c['sender'])
    c['auto_restart'] = ask('Enable automatic recovery? y/n', 'y' if c['auto_restart'] else 'n').lower() == 'y'
    c['defer_active_calls'] = ask('Defer restart while CLI reports active channels? y/n',
                                  'y' if c['defer_active_calls'] else 'n').lower() == 'y'
    for key, label in [('failures', 'Consecutive failed checks'), ('cooldown', 'Restart cooldown seconds'),
                       ('max_restarts_hour', 'Maximum restart attempts per hour')]:
        c[key] = int(ask(label, str(c[key])))
    if ask('AMI settings: auto or manual?', 'auto' if not c['ami'] else 'manual') == 'manual':
        a = c['ami']
        c['ami'] = dict(host=ask('Local AMI host', a.get('host', '127.0.0.1')),
                        port=int(ask('AMI port', str(a.get('port', 5038)))),
                        username=ask('AMI username', a.get('username', '')),
                        secret=ask('AMI secret (blank retains current)', a.get('secret', ''), True))
    else:
        c['ami'] = {}
    validate(c)
    save(ETC / 'config.json', c)
    # Reset debounce counters after edits, retaining incident notification/restart history.
    st = readjson(STATE / 'state.json', {})
    st.update(failures=0)
    save(STATE / 'state.json', st)
    print('Saved configuration. No PBX restart performed.')


def check_legacy_cron():
    rc, out, err = run(['crontab', '-l'])
    if rc:
        if 'no crontab for' in err.lower():
            return
        raise RuntimeError('Cannot inspect root crontab; migration stopped')
    lines = out.splitlines(keepends=True)
    # Only recognize the exact two installed legacy monitor paths, not unrelated jobs.
    legacy = re.compile(r'''(?<![A-Za-z0-9_./-])/usr/local/bin/(?:asterisk-monitor\.sh|extension_monitor\.sh)(?=[\s"';&|<>]|$)''')
    removed = [line for line in lines if not line.lstrip().startswith('#') and legacy.search(line)]
    if removed:
        raise RuntimeError('Legacy monitor jobs remain. Run cleanup-legacy-freepbx.sh --apply first')


def parse_os_release(text):
    info = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        words = shlex.split(value, comments=True)
        info[key.strip()] = ' '.join(words)
    return info


def require_supported_platform():
    info = parse_os_release(Path('/etc/os-release').read_text())
    if info.get('ID') != 'debian' or info.get('VERSION_ID') != '12':
        raise RuntimeError('Requires Debian 12 for this FreePBX 17 installer; detected ' +
                           info.get('ID', 'unknown') + ' ' + info.get('VERSION_ID', 'unknown'))
    return info


def unsafe_apt_suites(text, deb822=False):
    invalid = []
    def inspect(uris, suites):
        if any('debian.org/' in uri or '/debian' in uri or 'deb.freepbx.org/' in uri for uri in uris):
            invalid.extend(s for s in suites if re.match(r'^(stable|oldstable|testing|unstable|sid|trixie)([-/].*)?$', s))
    if deb822:
        for block in re.split(r'\n\s*\n', text):
            fields = {}
            key = None
            for line in block.splitlines():
                if line.lstrip().startswith('#'): continue
                if line[:1].isspace() and key:
                    fields[key] += ' ' + line.strip()
                elif ':' in line:
                    key, value = line.split(':', 1)
                    key = key.lower().strip()
                    fields[key] = value.strip()
            if fields.get('enabled', 'yes').lower() != 'no':
                inspect(fields.get('uris', '').split(), fields.get('suites', '').split())
    else:
        for line in text.splitlines():
            row = shlex.split(line, comments=True)
            if not row or row[0] not in ['deb', 'deb-src']: continue
            index = next((i for i, item in enumerate(row) if re.match(r'^(https?|ftp)://', item)), None)
            if index is not None and index + 1 < len(row): inspect([row[index]], [row[index + 1]])
    return invalid


def check_apt_sources():
    files = [Path('/etc/apt/sources.list')] + sorted(Path('/etc/apt/sources.list.d').glob('*.list')) + \
            sorted(Path('/etc/apt/sources.list.d').glob('*.sources'))
    for path in files:
        if path.exists():
            suites = unsafe_apt_suites(path.read_text(), path.suffix == '.sources')
            if suites:
                raise RuntimeError(f'Unsafe/moving Debian suite in {path}: {", ".join(suites)}. '
                                   'Review sources and pin Debian 12/bookworm; no package operation was started')


def ami_config_report(c):
    try:
        a = ami_credentials(c)
        return dict(readable=True, host=a.get('host', '127.0.0.1'), port=a.get('port', 5038),
                    credentials_present=True)
    except (ValueError, OSError) as e:
        return dict(readable=False, reason=str(e))


def preflight():
    info = require_supported_platform()
    print('OS:', info.get('PRETTY_NAME', 'Debian ' + info['VERSION_ID']))
    check_legacy_cron()
    c = config()
    h = health(c)
    print('Preflight:', json.dumps(h))
    if not h['healthy']:
        if h['ami'] == 'config_error': print('AMI configuration:', json.dumps(ami_config_report(c)))
        raise RuntimeError('Fix CLI/AMI configuration before enabling unattended recovery')


def install():
    require_supported_platform()
    for cmd in ['fwconsole', 'asterisk', 'php', 'systemctl', 'crontab', 'pgrep']:
        if not shutil.which(cmd):
            raise RuntimeError(f'Required command missing: {cmd}')
    if not Path('/etc/freepbx.conf').exists():
        raise RuntimeError('FreePBX configuration not found')
    c = config()
    if not (ETC / 'config.json').exists():
        configure()
        c = config()
    h = health(c)
    print('Preflight:', json.dumps(h))
    if not h['healthy']:
        if h['ami'] == 'config_error': print('AMI configuration:', json.dumps(ami_config_report(c)))
        raise RuntimeError('Preflight failed: fix CLI/AMI configuration before enabling unattended recovery')
    if not Path('/usr/sbin/sendmail').exists():
        raise RuntimeError('Set up SMTP first (menu option 3), then install monitoring')
    check_legacy_cron()
    checked(['systemctl', 'stop', 'freepbx-care.timer']) if Path('/etc/systemd/system/freepbx-care.timer').exists() else None
    if Path(__file__).resolve() != SELF:
        atomic(SELF, Path(__file__).read_text(), 0o700)
    os.chmod(SELF, 0o700)
    atomic('/etc/systemd/system/freepbx-care.service', '''[Unit]
Description=FreePBX Asterisk CLI and AMI health monitor
After=network-online.target mariadb.service freepbx.service

[Service]
Type=oneshot
ExecStart=/bin/bash /root/freepbx-care.sh check
TimeoutStartSec=900
# fwconsole can launch Asterisk/PM2 here; those daemons must survive this check.
KillMode=process
UMask=0077
''', 0o644)
    atomic('/etc/systemd/system/freepbx-care.timer', '''[Unit]
Description=Check FreePBX health every minute

[Timer]
OnBootSec=5min
OnUnitInactiveSec=60s
AccuracySec=5s
RandomizedDelaySec=15s
FixedRandomDelay=yes
Unit=freepbx-care.service

[Install]
WantedBy=timers.target
''', 0o644)
    checked(['systemctl', 'daemon-reload'])
    checked(['systemctl', 'enable', '--now', 'freepbx-care.timer'])
    print('Installed. Rerun: bash /root/freepbx-care.sh')


def smtp():
    smtp_setup()


def smtp_profile(path):
    path = Path(path)
    st = path.lstat()
    if path.is_symlink() or not path.is_file() or st.st_uid != 0 or st.st_mode & 0o077:
        raise ValueError('SMTP profile must be a root-owned regular file with mode 600')
    value = json.loads(path.read_text())
    for key in ['host', 'tls', 'username', 'password', 'sender']:
        if not isinstance(value.get(key), str) or not value[key]:
            raise ValueError(f'SMTP profile requires nonempty {key}')
    if 'port' not in value:
        raise ValueError('SMTP profile requires port')
    if value['password'].startswith('REPLACE_'):
        raise ValueError('Replace the example SMTP profile password before use')
    return value


def smtp_setup(profile=None):
    require_supported_platform()
    c = config()
    host = profile['host'] if profile else ask('SMTP relay DNS hostname (must match its certificate)')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host):
        raise ValueError('Invalid relay hostname')
    port = int(profile['port'] if profile else ask('SMTP port', '587'))
    if not 1 <= port <= 65535:
        raise ValueError('Invalid port')
    mode = profile['tls'] if profile else ask('TLS mode: starttls or implicit (465)', 'implicit' if port == 465 else 'starttls')
    if mode not in ['starttls', 'implicit']:
        raise ValueError('Invalid TLS mode')
    user = profile['username'] if profile else ask('SMTP username')
    password = profile['password'] if profile else ask('SMTP password', secret=True)
    if not user or ':' in user or re.search(r'\s', user) or not password or '\r' in password or '\n' in password:
        raise ValueError('Invalid SMTP credentials')
    sender = profile['sender'] if profile else ask('Monitor sender email', c['sender'])
    if not address(sender):
        raise ValueError('Invalid sender email')
    packages = ['postfix', 'libsasl2-modules', 'ca-certificates']
    missing = [p for p in packages if run(['dpkg-query', '-W', '-f=${Status}', p])[1].strip() != 'install ok installed']
    # Noninteractive installation avoids the Postfix configuration dialog.
    oldenv = os.environ.get('DEBIAN_FRONTEND')
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    try:
        if missing:
            check_apt_sources()
            checked(['apt-get', 'update'], 180)
            checked(['apt-get', 'install', '-y'] + missing, 300)
    finally:
        if oldenv is None:
            os.environ.pop('DEBIAN_FRONTEND', None)
        else:
            os.environ['DEBIAN_FRONTEND'] = oldenv
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup = STATE / ('smtp-backup-' + stamp)
    backup.mkdir(mode=0o700)
    main = Path('/etc/postfix/main.cf')
    sasl = Path('/etc/postfix/freepbx-care-sasl')
    files = [main, sasl, Path(str(sasl) + '.db')]
    existed = {str(p): p.exists() for p in files}
    reset_marker = ETC / 'smtp-reset.json'
    reset = readjson(reset_marker, None)
    for p in files:
        if p.exists():
            shutil.copy2(p, backup / p.name)
            os.chmod(backup / p.name, 0o600)
    save(backup / 'manifest.json', existed)
    try:
        atomic(sasl, f'[{host}]:{port} {user}:{password}\n')
        checked(['postmap', 'hash:' + str(sasl)])
        os.chmod(str(sasl) + '.db', 0o600)
        params = dict(relayhost=f'[{host}]:{port}', smtp_sasl_auth_enable='yes',
                      smtp_sasl_security_options='noanonymous',
                      smtp_sasl_tls_security_options='noanonymous',
                      smtp_sasl_password_maps='hash:' + str(sasl),
                      smtp_tls_security_level='verify',
                      smtp_tls_wrappermode='yes' if mode == 'implicit' else 'no',
                      smtp_tls_CAfile='/etc/ssl/certs/ca-certificates.crt')
        for key, value in params.items():
            checked(['postconf', '-e', f'{key} = {value}'])
        restore_smtp_delivery(reset)
        checked(['postfix', 'check'])
        checked(['systemctl', 'restart', 'postfix'])
    except Exception:
        for p in files:
            if existed[str(p)]:
                shutil.copy2(backup / p.name, p)
            elif p.exists():
                p.unlink()
        run(['systemctl', 'restart', 'postfix'])
        raise
    c['sender'] = sender
    save(ETC / 'config.json', c)
    if reset:
        reset_marker.unlink()
    print(f'SMTP configured; backup: {backup}. Existing sender rewriting rules were preserved.')
    print('Use test-mail and inspect the Postfix queue/logs to confirm delivery.')


def restore_smtp_delivery(reset):
    if not reset:
        return
    current_guard = checked(['postconf', '-h', 'defer_transports']).strip()
    if current_guard != reset.get('guard'):
        raise RuntimeError('SMTP delivery guard was changed externally; review before enabling mail')
    checked(['postconf', '-e', 'defer_transports = ' + reset['previous_defer_transports']])


@contextmanager
def operation_lock():
    with open('/run/freepbx-care.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another operation is running; retry shortly') from None
        yield


def menu_action(choice):
    with operation_lock():
        if choice == '1': configure()
        elif choice == '2': install()
        elif choice == '3': smtp()
        elif choice == '4': status()
        elif choice == '5': testmail()
        elif choice == '6': pause(int(ask('Pause minutes', '60')))
        elif choice == '7': resume()
        elif choice == '8': checked(['systemctl', 'disable', '--now', 'freepbx-care.timer'])
        elif choice == '9': print('Diagnostics saved:', snapshot(health(config())))
        elif choice == '10': configure_extensions()
        elif choice == '11': print('Extension status (no email/restart):', json.dumps(extension_report(config()), indent=2))


def menu():
    while True:
        print(f'\nFreePBX Care {VERSION}\n1 Configure Asterisk monitor\n2 Install/update monitoring\n3 Configure SMTP relay\n4 Read-only health/status\n5 Send test email\n6 Pause monitoring\n7 Resume monitoring\n8 Disable monitoring\n9 Collect diagnostics (no restart)\n10 Configure extension monitoring\n11 Read-only extension status\n0 Exit')
        choice = ask('Choose', '0')
        if choice == '0':
            return
        try:
            menu_action(choice)
        except (RuntimeError, ValueError, OSError) as e:
            print('ERROR:', e)


def status():
    print('Version:', VERSION)
    print('Current health:', json.dumps(health(config()), indent=2))
    print('AMI configuration (no secrets):', json.dumps(ami_config_report(config())))
    print('Saved state:', json.dumps(readjson(STATE / 'state.json', {}), indent=2))
    print('Maintenance:', json.dumps(readjson(STATE / 'pause.json', {})))
    print('Backup pause:', json.dumps(readjson(STATE / 'backup-pause.json', {})))
    print('Extension settings:', json.dumps(config()['extension_monitor'], indent=2))
    print('Saved extension state:', json.dumps(readjson(STATE / 'extensions.json', {}), indent=2))
    rc, out, err = run(['systemctl', 'status', 'freepbx-care.timer', '--no-pager'])
    print(out, err)


def testmail():
    if not notify(config(), 'mail test', 'Test submitted by FreePBX Care.'):
        raise RuntimeError('Mail could not be queued')
    print('Accepted by local sendmail; confirm receipt and check mail logs for relay delivery.')


def pause(minutes):
    if not 1 <= minutes <= 10080:
        raise ValueError('Pause must be 1..10080 minutes')
    save(STATE / 'pause.json', dict(until=time.time() + minutes * 60))
    print(f'Monitoring paused for {minutes} minutes. Pause before planned PBX shutdowns.')


def backup_pause(minutes):
    if not 1 <= minutes <= 10080:
        raise ValueError('Backup pause must be 1..10080 minutes')
    save(STATE / 'backup-pause.json', dict(until=time.time() + minutes * 60))
    print(f'Backup pause expires in {minutes} minutes; manual maintenance pause is unchanged.')


def resume():
    save(STATE / 'pause.json', dict(until=0))
    st = readjson(STATE / 'state.json', {})
    st.update(recovery_blocked=False, failures=0)
    save(STATE / 'state.json', st)
    print('Manual pause and recovery timeout latch cleared. Backup pause remains independent.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='menu', choices=[
        'menu', 'configure', 'install', 'preflight', 'smtp', 'status', 'diagnose', 'check', 'test-mail',
        'pause', 'resume', 'backup-pause', 'backup-resume', 'disable', 'extensions', 'extensions-status'])
    parser.add_argument('--minutes', type=int, default=60)
    parser.add_argument('--smtp-config', help='root-owned mode-600 SMTP profile JSON')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root: sudo bash freepbx-care.sh')
    os.umask(0o077)
    for p in [ETC, STATE, LOG]:
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(p, 0o700)
    if args.command == 'menu':
        menu()
        return
    with operation_lock():
        if args.command == 'check':
            if not (ETC / 'config.json').exists():
                raise RuntimeError('Configure monitoring first')
            tick(config())
        elif args.command == 'configure': configure()
        elif args.command == 'extensions': configure_extensions()
        elif args.command == 'extensions-status': print(json.dumps(extension_report(config()), indent=2))
        elif args.command == 'install': install()
        elif args.command == 'preflight': preflight()
        elif args.command == 'smtp': smtp_setup(smtp_profile(args.smtp_config) if args.smtp_config else None)
        elif args.command == 'status': status()
        elif args.command == 'diagnose': print('Diagnostics saved:', snapshot(health(config())))
        elif args.command == 'test-mail': testmail()
        elif args.command == 'pause': pause(args.minutes)
        elif args.command == 'resume': resume()
        elif args.command == 'backup-pause': backup_pause(args.minutes)
        elif args.command == 'backup-resume': backup_pause(3)
        elif args.command == 'disable': checked(['systemctl', 'disable', '--now', 'freepbx-care.timer'])


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
PYTHON
)" "$0" "$@"
