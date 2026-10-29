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
os.environ['LC_ALL'] = 'C'
ETC = Path('/etc/freepbx-care')
STATE = Path('/var/lib/freepbx-care')
LOG = Path('/var/log/freepbx-care')
SELF = Path('/root/freepbx-care.sh')
VERSION = '2026.10.28-local-care-r8'
KNOWN_SECRETS = set()
DEFAULT = dict(email='monitor@famecomputers.com', sender='', auto_restart=True,
               failures=3, cooldown=1800, max_restarts_hour=2, boot_grace=300,
               resume_grace=180, defer_active_calls=True, ami={},
               extension_monitor=dict(enabled=False, failures=3, groups=[]),
               auto_start_mariadb=True, monitor_fastagi=False,
               database_query_check=False,
               trunk_monitor=dict(enabled=False, failures=3, recovery_checks=2, trunks=[]))

# Only these optional features can be changed through this helper. Absence of
# activity does NOT prove a module is unused. Everything else remains audit-only.
OPTIONAL_MODULES = {
    'sangomacrm': 'CRM integration - disable only when this site confirms it is unused.',
    'zulu': 'Zulu desktop/mobile client - verify no users or integrations use it.',
    'sangomaconnect': 'Sangoma Connect softphones - verify no users use this service.',
    'sangomartapi': 'Sangoma real-time API - verify no connected clients/integrations need it.',
    'restapps': 'Phone applications - verify phones do not use these apps.',
    'ucp': 'User Control Panel - verify users do not use web voicemail, calls or other UCP features.',
    'faxpro': 'Advanced fax features - verify no fax workflows use it.',
    'fax': 'Fax support - verify no inbound/outbound fax workflows use it.',
    'xmpp': 'Chat/messaging integration - verify no users/integrations use it.',
    'recording_report': 'Call recording reports - verify no users use this reporting interface.',
}
MODULE_LABELS = {
    'sangomacrm': 'Sangoma CRM', 'zulu': 'Zulu softphones',
    'sangomaconnect': 'Sangoma Connect softphones', 'sangomartapi': 'Sangoma real-time API',
    'restapps': 'Phone Apps', 'ucp': 'User Control Panel', 'faxpro': 'Advanced Fax',
    'fax': 'Fax support', 'xmpp': 'Chat / messaging', 'recording_report': 'Call Recording Reports',
}


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
    for key in ['auto_restart', 'defer_active_calls', 'auto_start_mariadb', 'monitor_fastagi']:
        if type(c[key]) is not bool:
            raise ValueError(f'{key} must be boolean')
    validate_extensions(c['extension_monitor'])
    validate_trunks(c['trunk_monitor'])
    if type(c['database_query_check']) is not bool:
        raise ValueError('database_query_check must be boolean')


def validate_extensions(settings):
    if not isinstance(settings, dict) or type(settings.get('enabled')) is not bool:
        raise ValueError('Invalid extension monitoring settings')
    if type(settings.get('failures')) is not int or not 2 <= settings['failures'] <= 60:
        raise ValueError('Extension failed checks must be 2..60')
    groups = settings.get('groups')
    if not isinstance(groups, list) or len(groups) > 100 or (settings['enabled'] and not groups):
        raise ValueError('Enabled extension monitoring needs 1..100 groups')
    if type(settings.get('recovery_checks', 1)) is not int or not 1 <= settings.get('recovery_checks', 1) <= 60:
        raise ValueError('Extension recovery checks must be 1..60')
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


def valid_note(value):
    return isinstance(value, str) and 1 <= len(value.strip()) <= 200 and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def redact(value):
    """Best effort secret removal; diagnostic files still require private handling."""
    text = str(value)
    secrets = list(KNOWN_SECRETS)
    try:
        settings = readjson(ETC / 'config.json', {})
        secrets.append(settings.get('ami', {}).get('secret', ''))
        for path in [Path('/etc/postfix/freepbx-care-sasl'), Path('/etc/postfix/sasl/sasl_passwd')]:
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536:
                for line in path.read_text().splitlines():
                    parts = line.split(None, 1)
                    if len(parts) == 2 and ':' in parts[1]:
                        secrets.append(parts[1].split(':', 1)[1])
    except (OSError, ValueError, AttributeError):
        pass
    for secret in sorted({v for v in secrets if isinstance(v, str) and v}, key=len, reverse=True):
        if secret:
            text = (text.replace(secret, '[REDACTED]') if len(secret) >= 4 else
                    re.sub(r'(?<!\w)' + re.escape(secret) + r'(?!\w)', '[REDACTED]', text))
    text = re.sub(r'(?im)(\b(?:secret|password|passwd|authorization|proxy-authorization)["\x27]?\s*[=:]\s*)[^\r\n,}]+',
                  r'\1[REDACTED]', text)
    text = re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^\s/@]+:[^\s/@]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)(--password(?:=|\s+)|\bidentified by\s+)[^\s]+', r'\1[REDACTED]', text)
    return text


def diagnostic_write(path, text):
    atomic(path, redact(text)[:524288] + '\n[Diagnostic output bounded to 512 KiB]\n')


def recovery_notices(c, st):
    """Keep one deduplicated, retryable result for each local recovery type."""
    for key, label, health_key in [('last_restart_result', 'Asterisk recovery', 'health'),
                                    ('last_database_start_result', 'MariaDB start', 'database')]:
        result = st.get(key)
        if result:
            outcome = 'verified' if result['exit'] == 0 and result[health_key]['healthy'] else 'failed'
            token = str(result['time']) + ' ' + outcome
            transition(c, st, label, token, json.dumps(result, indent=2))


def idle_channels():
    rc, out, _ = cli('core show channels count')
    m = re.search(r'(?m)^\s*(\d+) active channels?\b', out)
    return rc == 0 and m is not None and int(m[1]) == 0


def observe_asterisk_restarts(c, st, h, now):
    uptime = h.get('asterisk_uptime')
    if uptime is None:
        return
    previous = st.get('observed_asterisk_uptime')
    events = [t for t in st.get('observed_asterisk_restarts', []) if 0 <= now - t < 3600]
    if previous is not None and uptime + 5 < previous:
        events.append(now)
        log('Asterisk uptime decreased outside a recorded Care recovery; review crash/restart history')
    st.update(observed_asterisk_uptime=uptime, observed_asterisk_restarts=events[-20:])
    if len(events) >= c['max_restarts_hour']:
        st['recovery_blocked'] = True
        st['block_reason'] = 'Repeated observed Asterisk restarts; crash-loop review required'
        transition(c, st, 'Asterisk recovery lock', 'outage', st['block_reason'])


def database_query_health(database):
    """Optional root socket SELECT only; no application credentials or repairs."""
    client = shutil.which('mariadb')
    if not client:
        return dict(database, healthy=False, state='query_probe_unavailable', startable=False)
    rc, out, _ = run([client, '--protocol=socket', '--connect-timeout=3', '--batch',
                      '--skip-column-names', '--execute', 'SELECT 1'], 5)
    return dict(database, healthy=rc == 0 and out.strip() == '1',
                state='healthy' if rc == 0 and out.strip() == '1' else 'query_failed', startable=False)


def verify_database(c):
    result = dict(healthy=False, state='unknown', startable=False)
    for attempt in range(3):
        result = database_health()
        if result['healthy'] and c.get('database_query_check'):
            result = database_query_health(result)
        if result['healthy']:
            return result
        if attempt < 2:
            time.sleep(2)
    return result


def verify_recovery(c):
    """Two consecutive good probes within three attempts; no recovery commands."""
    consecutive = 0
    for attempt in range(3):
        result = health(c)
        consecutive = consecutive + 1 if result['healthy'] else 0
        if consecutive >= 2:
            return result
        if attempt < 2:
            time.sleep(2)
    return dict(result, healthy=False, verification='Two consecutive healthy probes did not pass')


def recovery_unlock():
    c = config()
    if fwconsole_busy() or (STATE / 'module-change-pending.json').exists():
        raise RuntimeError('Finish and review pending fwconsole/module work before unlocking recovery')
    h = health(c)
    if not h['healthy']:
        raise RuntimeError('Restore database/CLI/AMI health before unlocking automatic recovery')
    st = readjson(STATE / 'state.json', {})
    reviewed = {k: st.get(k) for k in ['block_reason', 'database_block_reason',
                 'last_restart_result', 'last_database_start_result']}
    st.update(recovery_blocked=False, database_recovery_blocked=False, failures=0,
              database_failures=0, settle_until=time.time() + c['resume_grace'])
    for key in ['recovery_inflight', 'database_recovery_inflight', 'block_reason', 'database_block_reason']:
        st.pop(key, None)
    # Attempt timestamps remain intact: unlock cannot bypass cooldown/hourly limits.
    save(STATE / 'state.json', st)
    diagnostic_write(LOG / 'last-recovery-unlock.log', json.dumps(dict(
        time=time.time(), user=os.environ.get('SUDO_USER') or os.environ.get('USER', 'root'), reviewed=reviewed)))
    print('Recovery unlocked after healthy review. Cooldowns, attempt history and pauses remain in force.')


def validate_trunks(settings):
    if not isinstance(settings, dict) or type(settings.get('enabled')) is not bool:
        raise ValueError('Invalid trunk settings')
    for key in ['failures', 'recovery_checks']:
        if type(settings.get(key)) is not int or not 2 <= settings[key] <= 60:
            raise ValueError('Trunk debounce values must be 2..60')
    trunks = settings.get('trunks')
    if not isinstance(trunks, list) or len(trunks) > 100 or (settings['enabled'] and not trunks):
        raise ValueError('Enabled trunk monitoring needs 1..100 definitions')
    names = set()
    for item in trunks:
        if not isinstance(item, dict) or not valid_note(item.get('name')) or item['name'].casefold() in names:
            raise ValueError('Use unique trunk names')
        names.add(item['name'].casefold())
        ids = item.get('aors', [])
        registration = item.get('registration', '')
        if (not isinstance(ids, list) or len(ids) > 20 or any(not isinstance(v, str) for v in ids) or
                len(set(ids)) != len(ids) or
                not isinstance(registration, str) or (not ids and not registration)):
            raise ValueError('Trunk requires availability AORs and/or an outbound registration ID')
        for value in ids + ([registration] if registration else []):
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.@+-]{1,100}', value):
                raise ValueError('Use exact PJSIP object IDs (letters, digits, dot, @, +, _, -)')


def parse_registrations(text):
    """Native PJSIP table, exact IDs and complete footer; unknown formats fail closed."""
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    rows = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('<', '=', 'Objects found:', 'No objects found.')):
            continue
        m = re.fullmatch(r'([^\s/]+)/sips?:\S+\s+\S+\s+(Registered|Unregistered|Rejected)(?:\s+.*)?', line)
        if not m or m[1] in rows:
            raise RuntimeError('Unsupported or ambiguous outbound registration output')
        rows[m[1]] = m[2]
    footer = re.search(r'(?m)^\s*Objects found:\s*(\d+)\s*$', text)
    if not ((footer and int(footer[1]) == len(rows)) or (not rows and text.strip() == 'No objects found.')):
        raise RuntimeError('Incomplete outbound registration inventory')
    return rows


def trunk_report(c):
    settings = c['trunk_monitor']
    if not settings['enabled']:
        return dict(enabled=False, trunks=[])
    results = []
    try:
        availability = {}
        definitions = [dict(name=t['name'], extensions=t.get('aors', []), mode='all')
                       for t in settings['trunks'] if t.get('aors')]
        if definitions:
            probe = dict(c, extension_monitor=dict(enabled=True, failures=3, groups=definitions))
            report = extension_report(probe)
            if report.get('error'):
                raise RuntimeError(report['error'])
            availability = {g['name']: g['status'] for g in report['groups']}
        registrations = {}
        if any(t.get('registration') for t in settings['trunks']):
            rc, out, _ = cli('pjsip show registrations')
            if rc:
                raise RuntimeError('Outbound registration query failed')
            registrations = parse_registrations(out)
        for definition in settings['trunks']:
            states = []
            if definition.get('aors'):
                states.append(availability[definition['name']])
            reg = definition.get('registration', '')
            value = registrations.get(reg) if reg else None
            if reg:
                states.append('healthy' if value == 'Registered' else 'outage'
                              if value in ['Rejected', 'Unregistered'] else 'unknown')
            status = 'unknown' if 'unknown' in states else 'outage' if 'outage' in states else 'healthy'
            results.append(dict(name=definition['name'], status=status,
                                availability=availability.get(definition['name']), registration=value))
        return dict(enabled=True, trunks=results)
    except (RuntimeError, ValueError, OSError) as e:
        return dict(enabled=True, trunks=[], error=str(e))


def excluded_names(kind):
    st = readjson(STATE / 'exclusions.json', {})
    return {name for name, until in st.get(kind, {}).items() if until > time.time()}


def reset_trunk_debounce(c):
    if c['trunk_monitor']['enabled']:
        st = readjson(STATE / 'trunks.json', {})
        for entry in st.get('trunks', {}).values():
            entry.update(collection_failures=0, collection_successes=0,
                         availability_failures=0, availability_successes=0)
        save(STATE / 'trunks.json', st)


def trunks_tick(c, pbx_healthy):
    settings = c['trunk_monitor']
    if not settings['enabled']:
        return
    if not pbx_healthy:
        reset_trunk_debounce(c)
        return
    st = readjson(STATE / 'trunks.json', {})
    entries = st.setdefault('trunks', {})
    now = time.time()
    gap = now - st.get('last_observed', now) > 300
    report = trunk_report(c)
    st.update(last_observed=now, last_report=report)
    excluded = excluded_names('trunks')
    definitions = {t['name']: t for t in settings['trunks']}
    by_name = {r['name']: r for r in report['trunks']}
    remaining = 5
    for name, definition in definitions.items():
        signature = json.dumps(definition, sort_keys=True)
        entry = entries.setdefault(name, {})
        if entry.get('definition') != signature:
            entry = entries[name] = dict(definition=signature)
        if gap or name in excluded:
            entry.update(collection_failures=0, collection_successes=0,
                         availability_failures=0, availability_successes=0)
        if name in excluded:
            entry['status'] = 'maintenance'
            continue
        result = by_name.get(name, dict(name=name, status='unknown', error=report.get('error')))
        status = result['status']
        # Unknown is a collection incident, never a false trunk recovery.
        entry['status'] = status
        for key, bad in [('collection', status == 'unknown'), ('availability', status == 'outage')]:
            if key == 'availability' and status == 'unknown':
                entry.update(availability_failures=0, availability_successes=0)
                continue
            counter = key + '_failures'
            successes = key + '_successes'
            entry[counter] = entry.get(counter, 0) + 1 if bad else 0
            entry[successes] = 0 if bad else entry.get(successes, 0) + 1
            if gap:
                entry[counter] = int(bad)
                entry[successes] = int(not bad)
            desired = 'outage' if bad else 'healthy'
            threshold = settings['failures'] if bad else settings['recovery_checks']
            if (entry[counter] if bad else entry[successes]) >= threshold and remaining:
                label = 'Trunk ' + name + (' collection' if key == 'collection' else '')
                previous = entry.get('notified', {}).get(label)
                transition(c, entry, label, desired, json.dumps(result) +
                           '\nAlert only: no restart, reload or registration command was requested.')
                if previous != desired and not (previous is None and desired == 'healthy'):
                    remaining -= 1
    st['trunks'] = {name: entry for name, entry in entries.items() if name in definitions}
    save(STATE / 'trunks.json', st)


def configure_trunks():
    c = config()
    settings = copy.deepcopy(c['trunk_monitor'])
    if ask('Enable optional PJSIP trunk alerts? y/n', 'n').lower() not in ['y', 'yes']:
        settings['enabled'] = False
    else:
        print('Read IDs with pjsip list aors and pjsip show registrations. IP-auth trunks normally have no registration.')
        settings = dict(enabled=True, failures=int(ask('Consecutive failed checks', '3')),
                        recovery_checks=int(ask('Consecutive healthy checks for recovery', '2')), trunks=[])
        count = int(ask('Number of trunks', '1'))
        if not 1 <= count <= 100:
            raise ValueError('Choose 1..100 trunks')
        for _ in range(count):
            settings['trunks'].append(dict(name=ask('Trunk display name'),
                aors=ask('Exact AOR IDs for availability, comma/space separated; blank skips').replace(',', ' ').split(),
                registration=ask('Exact outbound registration ID; blank for IP-auth/no registration')))
    validate_trunks(settings)
    candidate = dict(c, trunk_monitor=settings)
    report = trunk_report(candidate)
    print(json.dumps(report, indent=2))
    if report.get('error') or any(t['status'] == 'unknown' for t in report['trunks']):
        raise RuntimeError('Cannot validate trunk IDs/states; settings were not saved')
    if ask('Save these trunk settings? y/n', 'n').lower() in ['y', 'yes']:
        save(ETC / 'config.json', candidate)
        reset_trunk_debounce(candidate)
        print('Trunk settings saved. Alerts only; qualify/registration do not prove calls work.')


def configure_exclusion():
    c = config()
    kind = ask('Maintenance target: 1 property/extensions, 2 trunk', '1')
    if kind not in ['1', '2']:
        raise ValueError('Choose 1 or 2')
    kind = 'extensions' if kind == '1' else 'trunks'
    definitions = c['extension_monitor']['groups'] if kind == 'extensions' else c['trunk_monitor']['trunks']
    if not definitions:
        print('No configured targets.')
        return
    for index, item in enumerate(definitions, 1):
        print(f'{index}. {item["name"]}')
    index = int(ask('Target number'))
    minutes = int(ask('Exclude minutes; 0 ends this exclusion', '60'))
    if not 1 <= index <= len(definitions) or not 0 <= minutes <= 10080:
        raise ValueError('Invalid target or duration (0..10080 minutes)')
    name = definitions[index - 1]['name']
    st = readjson(STATE / 'exclusions.json', {})
    st.setdefault(kind, {})[name] = time.time() + minutes * 60
    save(STATE / 'exclusions.json', st)
    if kind == 'extensions':
        reset_extension_debounce(c)
    else:
        reset_trunk_debounce(c)
    print(f'{name}: exclusion saved. Core Asterisk/MariaDB checks and other properties remain active.')


def log(message):
    print(f'{datetime.datetime.now().astimezone().isoformat()} {redact(message)}', flush=True)


def notify(c, subject, body):
    msg = email.message.EmailMessage()
    msg['To'] = c['email']
    msg['From'] = c['sender'] or ('root@' + socket.getfqdn())
    msg['Subject'] = f'FreePBX {socket.gethostname()}: {redact(subject)}'
    msg.set_content(redact(body))
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
        retries = state.setdefault('notification_retry', {})
        retry = retries.get(key, {})
        if retry.get('status') == status and retry.get('after', 0) > time.time():
            return
        if notify(c, f'{key}: {status}', body):
            state['notified'][key] = status
            retries.pop(key, None)
        else:
            failures = min(retry.get('failures', 0) + 1, 6) if retry.get('status') == status else 1
            retries[key] = dict(status=status, failures=failures,
                                after=time.time() + min(900, 30 * 2 ** failures))


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
            value['successes'] = 0
        st['collection_failures'] = 0
        st['collection_successes'] = 0
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
    excluded = excluded_names('extensions')
    report['groups'] = [g for g in report['groups'] if g['name'] not in excluded]
    path = STATE / 'extensions.json'
    st = readjson(path, {})
    now = time.time()
    groups = st.setdefault('groups', {})
    for name in excluded:
        if name in groups:
            groups[name].update(failures=0, successes=0)
    if now - st.get('last_observed', now) > 300:
        st['collection_failures'] = 0
        st['collection_successes'] = 0
        for value in groups.values():
            value['failures'] = 0
            value['successes'] = 0
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
    if all(g['name'] in excluded for g in c['extension_monitor']['groups']):
        st.update(collection_failures=0, collection_successes=0)
        save(path, st)
        return
    unknown = report.get('error') or any(g['status'] == 'unknown' or
        'unknown' in g['extensions'].values() for g in report['groups'])
    if unknown:
        st['collection_successes'] = 0
        st['collection_failures'] = st.get('collection_failures', 0) + 1
        if st['collection_failures'] >= c['extension_monitor']['failures']:
            announce(st, 'Extension collection', 'outage',
                       'Cannot establish all extension states. Check PJSIP IDs, qualify settings and CLI output.\n' +
                       json.dumps(report, indent=2))
    else:
        st['collection_failures'] = 0
        st['collection_successes'] = st.get('collection_successes', 0) + 1
        if st['collection_successes'] >= c['extension_monitor'].get('recovery_checks', 1):
            announce(st, 'Extension collection', 'healthy', 'PJSIP extension state collection restored.')
    if report.get('error'):
        for value in groups.values():
            value['failures'] = 0
            value['successes'] = 0
        log('Extension collection unavailable: ' + report['error'])
    else:
        active = set(excluded)
        definitions = {g['name']: g for g in c['extension_monitor']['groups']}
        for result in report['groups']:
            definition = definitions[result['name']]
            name = definition['name']
            active.add(name)
            signature = json.dumps(definition, sort_keys=True)
            entry = groups.setdefault(name, {})
            if entry.get('definition') != signature:
                entry = groups[name] = dict(definition=signature)
            entry['last_status'] = result['status']
            if result['status'] == 'outage':
                entry['successes'] = 0
                entry['failures'] = entry.get('failures', 0) + 1
                if entry['failures'] >= c['extension_monitor']['failures']:
                    announce(entry, name, 'outage', json.dumps(result, indent=2))
            else:
                entry['failures'] = 0
                entry['successes'] = entry.get('successes', 0) + 1 if result['status'] == 'healthy' else 0
                if result['status'] == 'healthy' and entry['successes'] >= c['extension_monitor'].get('recovery_checks', 1):
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
        settings['recovery_checks'] = int(ask('Extension consecutive healthy checks', str(settings.get('recovery_checks', 2))))
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
        KNOWN_SECRETS.add(a.get('secret', ''))
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


def database_health():
    """Check the local dependency without bootstrapping FreePBX or exposing credentials."""
    try:
        rc, out, _ = run(['systemctl', 'show', 'mariadb.service', '--all',
                         '--property=LoadState,ActiveState,UnitFileState,Job'], 5)
        fields = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
        required = {'LoadState', 'ActiveState', 'UnitFileState', 'Job'}
        if rc or not required.issubset(fields) or fields['LoadState'] != 'loaded':
            return dict(healthy=False, state='unknown', startable=False)
        active = fields['ActiveState']
        result = dict(healthy=False, state=active, startable=(
            active in ['inactive', 'failed'] and fields['UnitFileState'] in ['enabled', 'enabled-runtime']
            and fields['Job'] in ['', '0']))
        if active == 'active':
            admin = shutil.which('mariadb-admin') or shutil.which('mysqladmin')
            if not admin:
                result['state'] = 'probe_unavailable'
            else:
                rc, out, _ = run([admin, '--protocol=socket', '--connect-timeout=3', 'ping'], 5)
                result['healthy'] = rc == 0 and bool(re.search(r'\b(?:mysqld|mariadbd) is alive\b', out))
                result['state'] = 'healthy' if result['healthy'] else 'unresponsive'
        return result
    except (OSError, ValueError):
        return dict(healthy=False, state='unknown', startable=False)


def health(c):
    database = database_health()
    if database['healthy'] and c.get('database_query_check'):
        database = database_query_health(database)
    rc, out, _ = cli('core show uptime seconds')
    cli_ok = rc == 0 and bool(re.search(r'System uptime:\s*\d+', out))
    shutting_down = bool(re.search(r'during shutdown|shutting down', out, re.I))
    uptime = re.search(r'System uptime:\s*(\d+)', out)
    ami = ami_probe(c) if database['healthy'] else 'database_unavailable'
    return dict(cli=cli_ok, ami=ami, database=database, shutting_down=shutting_down,
                asterisk_uptime=int(uptime[1]) if uptime else None,
                healthy=database['healthy'] and cli_ok and ami == 'healthy',
                restartable=database['healthy'] and not shutting_down and (not cli_ok or ami == 'unreachable'))


def database_tick(c, st, h, statepath):
    """Only start a stopped, enabled local unit. Never restart a running database."""
    database = h['database']
    if database['healthy']:
        st['database_failures'] = 0
        transition(c, st, 'MariaDB', 'healthy', 'Local MariaDB service and socket ping passed.')
        return False
    st['database_failures'] = st.get('database_failures', 0) + 1
    if st['database_failures'] < c['failures']:
        return False
    transition(c, st, 'MariaDB', 'outage', json.dumps(database) +
               '\nDatabase dependency unavailable; Asterisk recovery is deferred.')
    now = time.time()
    attempts = [t for t in st.get('database_starts', []) if now - t < 3600]
    allowed = (c['auto_restart'] and c['auto_start_mariadb'] and database['startable'] and
               not st.get('database_recovery_blocked') and not st.get('recovery_blocked') and
               now - st.get('last_database_start', 0) >= c['cooldown'] and
               len(attempts) < c['max_restarts_hour'])
    if len(attempts) >= c['max_restarts_hour']:
        st['database_recovery_blocked'] = True
        st['database_block_reason'] = 'Hourly database start limit reached'
        transition(c, st, 'MariaDB recovery lock', 'outage', st['database_block_reason'])
    if not allowed:
        log('MariaDB start deferred: state, policy, cooldown, limit or recovery latch')
        return False
    evidence = snapshot(h)
    # Recheck after collecting evidence; never race a service stop/start or a mask/disable.
    current = database_health()
    if not current['startable']:
        log('MariaDB state changed during diagnostics; no start requested')
        return True  # Re-evaluate full health, including a possible independent recovery.
    st.update(last_database_start=now, database_starts=attempts + [now], database_failures=0, database_recovery_inflight=True)
    save(statepath, st)
    rc, out, err = run(['systemctl', 'start', 'mariadb.service'], 120, kill_group=False)
    if rc:
        st['database_recovery_blocked'] = True
        save(statepath, st)
    diagnostic_write(LOG / 'last-database-start.log', f'exit={rc}\n{out}\n{err}')
    after = verify_database(c)
    st.pop('database_recovery_inflight', None)
    if not after['healthy']:
        st['database_recovery_blocked'] = True
    if rc or not after['healthy']:
        st['database_block_reason'] = 'Database start failed or verification did not pass'
    st['last_database_start_result'] = dict(exit=rc, database=after, time=time.time(), evidence=str(evidence))
    save(statepath, st)
    recovery_notices(c, st)
    save(statepath, st)
    return True


def fastagi_health():
    """TCP listener check only; it does not execute an AGI script or prove CRM correctness."""
    try:
        with socket.create_connection(('127.0.0.1', 4573), 2):
            return True
    except OSError:
        return False


def fastagi_tick(c, st, pbx_healthy):
    if not c['monitor_fastagi'] or not pbx_healthy:
        st['fastagi_failures'] = 0
        return
    listening = fastagi_health()
    st['last_fastagi'] = dict(listening=listening, time=time.time())
    if listening:
        st['fastagi_failures'] = 0
        transition(c, st, 'CRM FastAGI', 'healthy', 'TCP listener at 127.0.0.1:4573 is reachable again; verify CRM calls.')
    else:
        st['fastagi_failures'] = st.get('fastagi_failures', 0) + 1
        if st['fastagi_failures'] >= c['failures']:
            transition(c, st, 'CRM FastAGI', 'outage',
                       'Expected TCP listener at 127.0.0.1:4573 is unreachable. '
                       'Review Sangoma CRM / PM2. No modules were disabled and Asterisk was not restarted.')


def configure_services():
    c = config()
    print('MariaDB: start-only recovery for a stopped, enabled local service; global recovery policy also applies.')
    print('FastAGI: optional alerts only. Enable only when Sangoma CRM is intentionally in use.')
    for key, label in [('auto_start_mariadb', 'Automatically start stopped MariaDB? y/n'),
                       ('monitor_fastagi', 'Expect CRM FastAGI on 127.0.0.1:4573? y/n'),
                       ('database_query_check', 'Enable optional root socket SELECT 1 check? y/n')]:
        answer = ask(label, 'y' if c[key] else 'n').lower()
        if answer not in ['y', 'n']:
            raise ValueError('Answer y or n')
        c[key] = answer == 'y'
    validate(c)
    save(ETC / 'config.json', c)
    st = readjson(STATE / 'state.json', {})
    st.update(database_failures=0, fastagi_failures=0)
    save(STATE / 'state.json', st)
    print('Service settings saved. No service or module was changed.')


def module_records(text):
    """fwconsole --format=json emits one JSON record per output line."""
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except ValueError:
            raise RuntimeError('Unrecognized module-admin output; inspect native fwconsole ma list before proceeding') from None
        if (not isinstance(item, dict) or item.get('status') is not True or
                item.get('type') == 'error' or 'data' not in item):
            raise RuntimeError('Module-admin reported an error; no dependency bypass is allowed')
        records.append(item)
    if not records:
        raise RuntimeError('Module-admin returned no structured result')
    return records


def module_inventory():
    rc, out, _ = run(['fwconsole', 'ma', 'list', '--format=json', '--no-ansi', '--no-interaction'],
                     90, kill_group=False)
    if rc:
        raise RuntimeError(f'Module inventory failed (exit {rc}); review native fwconsole ma list')
    inventories = [r['data'] for r in module_records(out) if isinstance(r['data'], list)]
    if len(inventories) != 1:
        raise RuntimeError('Ambiguous module inventory; no changes allowed')
    inventory = {}
    for row in inventories[0]:
        if (not isinstance(row, list) or len(row) < 3 or
                not all(isinstance(value, str) for value in row[:3]) or
                not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', row[0]) or row[0] in inventory):
            raise RuntimeError('Invalid module inventory row; no changes allowed')
        inventory[row[0]] = dict(version=row[1], status=row[2])
    return inventory


def check_reverse_dependencies(name):
    rc, out, _ = run(['fwconsole', 'ma', 'reversedepends', name, '--format=json',
                     '--no-ansi', '--no-interaction'], 60, kill_group=False)
    if rc:
        raise RuntimeError(f'Reverse dependency check blocked {name} (exit {rc}); review fwconsole ma reversedepends {name}')
    records = module_records(out)
    if not any(r['data'] == 'No enabled modules depend on this module.' for r in records):
        raise RuntimeError('No positive reverse-dependency clearance; no changes allowed')


def show_module_audit(inventory=None):
    inventory = module_inventory() if inventory is None else inventory
    print('Installed/local module inventory. Enabled does not mean used; disabled does not mean uninstalled.')
    for name, info in sorted(inventory.items()):
        category = 'OPTIONAL - REVIEW USAGE' if name in OPTIONAL_MODULES else 'PROTECTED / AUDIT ONLY'
        print(f"{name:24} {info['version']:14} {info['status']:30} {category}")
    print('\nOptional feature impacts (only consider installed/enabled entries):')
    for name, impact in OPTIONAL_MODULES.items():
        if name in inventory:
            print(f'  {name}: {impact}')
    print('Every optional module requires confirmation for this site; installed does not mean unused.')
    print('Disabling a module may not stop its existing process or measurably reduce resource use.')
    return inventory


def verify_module_change(before, after, selected):
    if selected not in after or after[selected]['status'] != 'Disabled':
        raise RuntimeError('Selected module did not reach Disabled status; administrator review required')
    for name, info in before.items():
        if name != selected and after.get(name) != info:
            raise RuntimeError(f'Another module changed ({name}); stop and review the saved inventory')
    if set(after) != set(before):
        raise RuntimeError('Module inventory changed concurrently; stop and review')


def require_idle_calls():
    rc, out, _ = cli('core show channels count')
    channels = re.search(r'(?m)^\s*(\d+) active channels?\b', out)
    if rc or not channels or int(channels[1]) != 0:
        raise RuntimeError('Module change refused: active calls or channel count unknown; retry during maintenance')


def apply_module_disable(name, expected, approval=None):
    """Caller holds operation_lock. One selected module; no force, uninstall or restart."""
    if name not in OPTIONAL_MODULES:
        raise ValueError('Module is protected or not on the reviewed optional-feature list')
    if not isinstance(approval, dict) or any(not valid_note(approval.get(k)) for k in ['site', 'technician', 'reason']):
        raise RuntimeError('Site-specific approval requires site, approving technician and reason')
    pending = STATE / 'module-change-pending.json'
    if pending.exists() or fwconsole_busy():
        raise RuntimeError('A module change/fwconsole operation is pending; finish/review it first')
    before = module_inventory()
    if before.get(name) != expected or expected.get('status') != 'Enabled':
        raise RuntimeError('Selected module changed or is not Enabled; run the audit again')
    if not health(config())['healthy']:
        raise RuntimeError('Fix MariaDB/CLI/AMI health before changing modules')
    require_idle_calls()
    check_reverse_dependencies(name)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup = STATE / ('module-change-' + stamp)
    backup.mkdir(mode=0o700, parents=True)
    save(backup / 'inventory-before.json', before)
    settings = ETC / 'config.json'
    if settings.exists():
        if settings.is_symlink() or not settings.is_file():
            raise RuntimeError('Refusing a nonregular monitor configuration backup')
        shutil.copy2(settings, backup / 'monitor-config.json')
        os.chmod(backup / 'monitor-config.json', 0o600)
    atomic(backup / 'RESTORE.txt', f'Previous module was Enabled. After administrator review:\n'
           f'fwconsole ma enable {name}\nfwconsole reload\n'
           'bash /root/freepbx-care.sh status\nbash /root/freepbx-care.sh resume\n'
           'If a fwconsole operation timed out, check it has finished before further changes.\n'
           'This directory is an inventory/settings backup, not a full PBX/database backup.\n')
    record = dict(module=name, backup=str(backup), stage='disable requested', time=time.time(),
                  approval=approval, server=socket.gethostname())
    save(backup / 'approval.json', record)
    try:
        # Check again immediately before mutation; native disable checks dependencies again too.
        check_reverse_dependencies(name)
        if fwconsole_busy():
            raise RuntimeError('Another fwconsole operation started; no module command requested')
        require_idle_calls()
        save(pending, record)  # Persist before mutation, including across timeouts/reboots.
        rc, out, err = run(['fwconsole', 'ma', 'disable', name, '--format=json',
                            '--no-ansi', '--no-interaction'], 120, kill_group=False)
        diagnostic_write(backup / 'disable.log', f'exit={rc}\n{out}\n{err}')
        if rc:
            raise RuntimeError(f'Module disable failed/timed out (exit {rc})')
        records = module_records(out)
        if not any(r['data'] == f'Module {name} successfully disabled' for r in records):
            raise RuntimeError('Module-admin did not confirm the selected disable')
        verify_module_change(before, module_inventory(), name)
        record['stage'] = 'reload requested'
        save(pending, record)
        rc, out, err = run(['fwconsole', 'reload', '--no-ansi', '--no-interaction'], 180, kill_group=False)
        diagnostic_write(backup / 'reload.log', f'exit={rc}\n{out}\n{err}')
        if rc:
            raise RuntimeError(f'Configuration reload failed/timed out (exit {rc})')
        after = module_inventory()
        verify_module_change(before, after, name)
        final_health = health(config())
        if not final_health['healthy']:
            raise RuntimeError('Health check failed after reload; inspect diagnostics before further changes')
        if name == 'sangomacrm':
            c = config()
            c['monitor_fastagi'] = False
            save(ETC / 'config.json', c)
        save(backup / 'result.json', dict(module=name, inventory=after, health=final_health, completed=True))
        pending.unlink()
        print(f'{name} disabled and configuration reloaded. Backup/audit: {backup}')
        print('Test calls and affected features. Existing manual/backup pauses remain unchanged.')
    except Exception:
        if pending.exists():
            print(f'Module operation needs review. Monitoring is held by {pending}. Evidence: {backup}')
            print('Do not repeat commands blindly. Review RESTORE.txt and any continuing fwconsole process;')
            print('after resolving it and confirming PBX health, run resume to clear the module-change hold.')
        else:
            print(f'No module command requested; pre-change checks failed. Audit directory: {backup}')
        raise


def module_review():
    inventory = module_inventory()
    choices = [name for name in OPTIONAL_MODULES if inventory.get(name, {}).get('status') == 'Enabled']
    print('\nOptional features - choose one to review. Core/security modules are protected.')
    disabled = [MODULE_LABELS[name] for name in OPTIONAL_MODULES
                if inventory.get(name, {}).get('status') == 'Disabled']
    if disabled:
        print('Already disabled: ' + ', '.join(disabled))
    if not choices:
        print('No enabled optional features available to disable. No changes made.')
        return
    print('Every change requires approval for this specific site; installed does not mean unused.')
    while True:
        for index, name in enumerate(choices, 1):
            hint = ''
            print(f'  {index}. {MODULE_LABELS[name]}{hint}')
        print('  A. View full module audit\n  0. Back without changes')
        choice = ask('Choose a feature number', '0').lower()
        if choice in ['', '0']:
            return
        if choice == 'a':
            show_module_audit(inventory)
            continue
        if not choice.isascii() or not choice.isdigit() or not 1 <= int(choice) <= len(choices):
            print('Enter a number shown above, A for the full audit, or 0 to go back.')
            continue
        name = choices[int(choice) - 1]
        print(f'\nSelected: {MODULE_LABELS[name]} ({name})')
        print('Feature impact:', OPTIONAL_MODULES[name])
        print('This disables the selected module and reloads FreePBX configuration.')
        print('Have a current PBX backup and an approved maintenance window. Dependency/call/health checks still apply.')
        while True:
            answer = ask('Disable this unused feature and reload configuration? y/n', 'n').lower()
            if answer in ['', 'n', 'no']:
                print('Cancelled; no module changes made.')
                return
            if answer in ['y', 'yes']:
                approval = {key: ask(label) for key, label in [
                    ('site', 'Site/property authorizing this change'),
                    ('technician', 'Approving technician'), ('reason', 'Why is this feature unused at this site?')]}
                with operation_lock():
                    apply_module_disable(name, inventory[name], approval)
                return
            print('Answer y or n. Enter keeps the feature enabled.')


def crash_audit():
    print('Crash review: memory/OOM and swap pressure; disk space AND inodes; CPU quotas/I/O stalls;')
    print('failed services, overlapping legacy jobs, backups, module/OS updates, and SIP/security incidents.')
    print('High usage, historical OOM counters, or an installed module alone do not prove the cause.')
    print('Read-only evidence; no services/modules restarted/disabled and no files purged.')
    print('Diagnostics saved:', snapshot(health(config())))


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
    deadline = time.monotonic() + 45
    for cmd in [['free', '-m'], ['df', '-h', '/', '/var'], ['df', '-i', '/', '/var'],
                ['cat', '/sys/fs/cgroup/memory.events', '/sys/fs/cgroup/memory.current',
                 '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/cpu.stat', '/sys/fs/cgroup/pids.events',
                 '/sys/fs/cgroup/pids.current', '/sys/fs/cgroup/pids.max'],
                ['cat', '/sys/fs/cgroup/cpu.max', '/sys/fs/cgroup/cpuset.cpus.effective',
                 '/sys/fs/cgroup/cpu.pressure', '/sys/fs/cgroup/memory.pressure', '/sys/fs/cgroup/io.pressure'],
                ['journalctl', '-k', '-n', '100', '--no-pager'],
                ['asterisk', '-rx', 'core show uptime'],
                ['asterisk', '-rx', 'core show channels count'],
                ['asterisk', '-rx', 'manager show settings'],
                ['systemctl', 'status', 'incron', 'mariadb', 'freepbx', 'apache2', '--no-pager'],
                ['systemctl', '--failed', '--no-pager'],
                ['ss', '-lntp'],
                ['journalctl', '-u', 'mariadb', '-b', '-1', '-n', '80', '--no-pager'],
                ['journalctl', '-u', 'mariadb', '--since', '7 days ago', '-n', '100', '--no-pager'],
                ['fwconsole', 'pm2', '--list'],
                ['journalctl', '-u', 'incron', '-u', 'mariadb', '-u', 'freepbx',
                 '-u', 'apache2', '-n', '100', '--no-pager'],
                ['tail', '-n', '150', '/var/log/asterisk/full'],
                ['ps', '-eo', 'pid,ppid,user,stat,etimes,comm'],
                ['systemd-detect-virt', '--container'],
                ['uptime']]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            chunks.append('\nDiagnostic time budget reached; remaining commands skipped.')
            break
        try:
            rc, out, err = run(cmd, min(5, remaining))
        except OSError as e:
            rc, out, err = 127, '', str(e)
        chunks.append(f'\n$ {" ".join(cmd)} (exit {rc})\n{out[:32768]}{err[:8192]}')
    diagnostic_write(dest, '\n'.join(chunks))
    # Bound storage, retaining the most recent twenty incidents.
    for old in sorted(LOG.glob('incident-*.log'))[:-20]:
        old.unlink()
    return dest


def tick(c):
    statepath = STATE / 'state.json'
    st = readjson(statepath, {})
    now = time.time()
    for prefix in ['', 'database_']:
        if st.get(prefix + 'recovery_inflight'):
            st[prefix + 'recovery_blocked'] = True
            st[prefix + 'block_reason'] = 'Previous recovery interrupted; operator review required'
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if st.get('boot') != boot:
        st.update(boot=boot, failures=0, database_failures=0, fastagi_failures=0)
        st.pop('observed_asterisk_uptime', None)
        reset_extension_debounce(c)
    # Long scheduling gaps can follow LXC suspension, backup or host overload.
    gap = now - st.get('last_observed', now)
    if gap > 300:
        st.update(failures=0, database_failures=0, fastagi_failures=0, settle_until=now + c['resume_grace'])
        reset_extension_debounce(c)
        reset_trunk_debounce(c)
        st.pop('observed_asterisk_uptime', None)
    st['last_observed'] = now
    uptime = float(Path('/proc/uptime').read_text().split()[0])
    paused = (readjson(STATE / 'pause.json', {}).get('until', 0) > now or
              readjson(STATE / 'backup-pause.json', {}).get('until', 0) > now)
    if (paused or uptime < c['boot_grace'] or st.get('settle_until', 0) > now or fwconsole_busy() or
            (STATE / 'module-change-pending.json').exists()):
        st['failures'] = 0
        st.pop('observed_asterisk_uptime', None)
        reset_trunk_debounce(c)
        st.update(database_failures=0, fastagi_failures=0)
        reset_extension_debounce(c)
        save(statepath, st)
        log('Monitoring skipped: pause, boot/resume grace, fwconsole operation, or pending module review')
        return
    h = health(c)
    recovery_notices(c, st)
    observe_asterisk_restarts(c, st, h, now)
    if not h['database']['healthy']:
        st['failures'] = 0  # Never count a database dependency outage toward an Asterisk restart.
    if database_tick(c, st, h, statepath):
        h = health(c)
        if h['database']['healthy']:
            database_tick(c, st, h, statepath)
    log(f"Health: CLI={h['cli']} AMI={h['ami']} MariaDB={h['database']['state']}")
    st['last_health'] = dict(h, time=now)
    if not h['database']['healthy']:
        st['fastagi_failures'] = 0
        reset_extension_debounce(c)
        reset_trunk_debounce(c)
        save(statepath, st)
        log('Asterisk/extension/CRM recovery checks deferred: database dependency unavailable')
        return
    if h['healthy']:
        st['failures'] = 0
        transition(c, st, 'PBX', 'healthy', 'CLI and authenticated AMI Ping passed.')
    else:
        st['failures'] = st.get('failures', 0) + 1
        if st['failures'] >= c['failures']:
            transition(c, st, 'PBX', 'outage', json.dumps(h))
            history = [t for t in st.get('restarts', []) if now - t < 3600]
            if len(history) >= c['max_restarts_hour']:
                st['recovery_blocked'] = True
                st['block_reason'] = 'Hourly Asterisk recovery limit reached'
                transition(c, st, 'Asterisk recovery lock', 'outage', st['block_reason'])
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
                # Diagnostics may take time: do not act on stale health/call information.
                current = health(c)
                if fwconsole_busy() or not current['restartable'] or recovery_command(current) != command:
                    log('Recovery deferred: health/process state changed during diagnostics')
                    save(statepath, st)
                    return
                if c['defer_active_calls'] and current['cli'] and not idle_channels():
                    log('Recovery deferred: new calls or unknown channel count after diagnostics')
                    save(statepath, st)
                    return
                st.update(last_restart=now, restarts=history + [now], failures=0, recovery_inflight=True)
                save(statepath, st)
                log(f'Recovery via {" ".join(command)}; evidence: {evidence}')
                rc, out, err = run(command, 600, kill_group=False)
                if rc:
                    st['recovery_blocked'] = True
                    save(statepath, st)
                diagnostic_write(LOG / 'last-restart.log', f'exit={rc}\n{out}\n{err}')
                after = verify_recovery(c)
                st.pop('recovery_inflight', None)
                if rc or not after['healthy']:
                    st['recovery_blocked'] = True
                    st['block_reason'] = 'Recovery command failed or post-recovery verification did not pass'
                failed_evidence = str(snapshot(after)) if rc or not after['healthy'] else None
                st['last_restart_result'] = dict(exit=rc, command=command, health=after, time=time.time(),
                                                failure_evidence=failed_evidence)
                recovery_notices(c, st)
                log(f'Restart completed: exit={rc}; health={after}')
            elif not h['restartable']:
                log('Configuration/authentication/protocol problem: automatic restart suppressed')
    if st.get('last_restart_result', {}).get('time', 0) >= now:
        h = st['last_restart_result']['health']
        st['last_health'] = dict(h, time=time.time())
        if h.get('asterisk_uptime') is not None:
            st['observed_asterisk_uptime'] = h['asterisk_uptime']
    fastagi_tick(c, st, h['healthy'])
    save(statepath, st)
    # Optional extension checks run after the core watchdog and cannot request recovery.
    try:
        extensions_tick(c, h['healthy'])
    except (RuntimeError, ValueError, OSError) as e:
        log(f'Extension monitoring failed: {e}; core PBX check completed')
    try:
        trunks_tick(c, h['healthy'])
    except (RuntimeError, ValueError, OSError) as e:
        log(f'Trunk monitoring failed: {e}; core PBX check completed')


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
        raise RuntimeError('Fix MariaDB/CLI/AMI health before enabling unattended recovery')


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
        raise RuntimeError('Preflight failed: fix MariaDB/CLI/AMI health before enabling unattended recovery')
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
    if choice == '13':
        module_review()  # Do not hold the watchdog lock while waiting for technician input.
        return
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
        elif choice == '12': configure_services()
        elif choice == '14': crash_audit()
        elif choice == '15': configure_trunks()
        elif choice == '16': print(json.dumps(trunk_report(config()), indent=2))
        elif choice == '17': configure_exclusion()
        elif choice == '18':
            if ask('Reviewed recovery evidence and safe to unlock? y/n', 'n').lower() in ['y', 'yes']:
                recovery_unlock()


def menu():
    while True:
        print(f'\nFreePBX Care {VERSION}\n1 Configure Asterisk monitor\n2 Install/update monitoring\n3 Configure SMTP relay\n4 Read-only health/status\n5 Send test email\n6 Pause monitoring\n7 Resume monitoring\n8 Disable monitoring\n9 Collect diagnostics (no restart)\n10 Configure extension monitoring\n11 Read-only extension status\n12 Configure MariaDB / CRM checks\n13 Review/disable unused optional modules\n14 Investigate crash/resource issues\n15 Configure SIP trunk alerts\n16 Read-only SIP trunk status\n17 Property/trunk maintenance exclusion\n18 Unlock recovery after review\n0 Exit')
        choice = ask('Choose', '0')
        if choice == '0':
            return
        try:
            menu_action(choice)
        except (RuntimeError, ValueError, OSError) as e:
            print('ERROR:', redact(e))


def status():
    print('Version:', VERSION)
    saved = readjson(STATE / 'state.json', {})
    print('Automatic recovery locks:', json.dumps(dict(
        asterisk=bool(saved.get('recovery_blocked') or saved.get('recovery_inflight')),
        mariadb=bool(saved.get('database_recovery_blocked') or saved.get('database_recovery_inflight')),
        asterisk_reason=saved.get('block_reason'), mariadb_reason=saved.get('database_block_reason'))))
    print('Resume clears maintenance; recovery-unlock separately reviews recovery locks. Neither starts a stopped timer.')
    print('Trunk settings:', json.dumps(config()['trunk_monitor'], indent=2))
    print('Saved trunk state:', json.dumps(readjson(STATE / 'trunks.json', {}), indent=2))
    print('Scoped maintenance:', json.dumps(readjson(STATE / 'exclusions.json', {}), indent=2))
    print('Current health:', json.dumps(health(config()), indent=2))
    print('AMI configuration (no secrets):', json.dumps(ami_config_report(config())))
    print('Saved state:', json.dumps(readjson(STATE / 'state.json', {}), indent=2))
    print('Maintenance:', json.dumps(readjson(STATE / 'pause.json', {})))
    print('Backup pause:', json.dumps(readjson(STATE / 'backup-pause.json', {})))
    print('Pending module-change hold:', json.dumps(readjson(STATE / 'module-change-pending.json', {})))
    print('Extension settings:', json.dumps(config()['extension_monitor'], indent=2))
    print('Saved extension state:', json.dumps(readjson(STATE / 'extensions.json', {}), indent=2))
    c = config()
    print('MariaDB automatic start:', c['auto_start_mariadb'], '(requires automatic recovery enabled)')
    print('CRM FastAGI:', json.dumps(dict(monitored=c['monitor_fastagi'],
          listening=fastagi_health() if c['monitor_fastagi'] else None)))
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
    pending = STATE / 'module-change-pending.json'
    if pending.exists():
        if fwconsole_busy() or not health(config())['healthy']:
            raise RuntimeError('Module-change hold retained: finish fwconsole work and restore MariaDB/CLI/AMI health first')
        pending.unlink()
    save(STATE / 'pause.json', dict(until=0))
    st = readjson(STATE / 'state.json', {})
    st.update(failures=0, database_failures=0, fastagi_failures=0,
              settle_until=time.time() + config()['resume_grace'])
    save(STATE / 'state.json', st)
    print('Manual pause and reviewed module-change hold cleared; settling grace applied. Backup pause remains independent.')
    if st.get('recovery_blocked') or st.get('database_recovery_blocked'):
        print('Automatic recovery remains locked. Review diagnostics, then use recovery-unlock explicitly.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='menu', choices=[
        'menu', 'configure', 'install', 'preflight', 'smtp', 'status', 'diagnose', 'check', 'test-mail',
        'pause', 'resume', 'backup-pause', 'backup-resume', 'disable', 'extensions', 'extensions-status', 'services',
        'modules', 'module-audit', 'crash-audit', 'trunks', 'trunks-status', 'exclusions', 'recovery-unlock'])
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
    if args.command == 'modules':
        module_review()
        return
    with operation_lock():
        if args.command == 'check':
            if not (ETC / 'config.json').exists():
                raise RuntimeError('Configure monitoring first')
            tick(config())
        elif args.command == 'configure': configure()
        elif args.command == 'extensions': configure_extensions()
        elif args.command == 'services': configure_services()
        elif args.command == 'trunks': configure_trunks()
        elif args.command == 'trunks-status': print(json.dumps(trunk_report(config()), indent=2))
        elif args.command == 'exclusions': configure_exclusion()
        elif args.command == 'recovery-unlock': recovery_unlock()
        elif args.command == 'module-audit': show_module_audit()
        elif args.command == 'crash-audit': crash_audit()
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
        print(f'ERROR: {redact(e)}', file=sys.stderr)
        sys.exit(1)
PYTHON
)" "$0" "$@"
