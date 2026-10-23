#!/bin/bash
# Proxmox HOST entrypoint. The reviewed in-container cleaner is embedded below.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root on the Proxmox host.' >&2; exit 1; }
command -v pct >/dev/null || { echo 'pct is missing: this command belongs on a Proxmox host.' >&2; exit 1; }
apply_args=()
all=false
ctids=()
for arg in "$@"; do
  case "$arg" in
    --apply|--reset-smtp|--remove-sender-rewrites|--retire-inherited-lock) apply_args+=("$arg") ;;
    --all-running-freepbx) all=true ;;
    *) [[ $arg =~ ^[0-9]+$ ]] || { echo "Invalid argument: $arg" >&2; exit 2; }
       ctids+=("$arg") ;;
  esac
done
if $all; then
  [[ ${#ctids[@]} -eq 0 ]] || { echo 'Use explicit CTIDs OR --all-running-freepbx.' >&2; exit 2; }
  listing=$(pct list)
  while read -r candidate; do
    [[ -z $candidate ]] || ctids+=("$candidate")
  done < <(awk 'NR>1 && $2 == "running" {print $1}' <<< "$listing")
fi
[[ ${#ctids[@]} -gt 0 ]] || {
  echo 'Usage: bash proxmox-cleanup-freepbx.sh [--apply] [--reset-smtp] CTID [CTID ...]'
  echo 'Or use --all-running-freepbx for running containers on THIS Proxmox node.'
  exit 2
}
echo 'Stopped containers are not started or modified. Only FreePBX containers are processed.'
if [[ " ${apply_args[*]} " == *' --reset-smtp '* ]]; then
  echo 'SMTP reset requested: normal SMTP delivery pauses until new setup if an old relay is recognized.'
else
  echo 'SMTP settings will be preserved; no SMTP reset was requested.'
fi
processed=0
skipped=0
failed=0
for ctid in "${ctids[@]}"; do
  echo "===== CT $ctid ====="
  if ! config=$(timeout 15 pct config "$ctid"); then
    echo "FAILED CT $ctid: cannot read configuration."; failed=$((failed + 1)); continue
  fi
  if grep -q '^lock:' <<< "$config"; then
    echo "FAILED CT $ctid: container is locked (backup/migration/etc.); retry after it completes."
    failed=$((failed + 1)); continue
  fi
  if ! status=$(timeout 15 pct status "$ctid") || [[ $status != 'status: running' ]]; then
    echo "SKIP CT $ctid: not running or unavailable."; skipped=$((skipped + 1)); continue
  fi
  if ! timeout 15 pct exec "$ctid" -- test -f /etc/freepbx.conf; then
    echo "SKIP CT $ctid: FreePBX not detected or probe failed; no changes made."
    skipped=$((skipped + 1)); continue
  fi
  if pct exec "$ctid" -- /bin/bash -s -- "${apply_args[@]}" <<'FREEPBX_CLEANUP_PAYLOAD'
#!/bin/bash
set -euo pipefail
command -v python3 >/dev/null || { echo 'Install python3 first'; exit 1; }
exec python3 -c "$(cat <<'PYTHON'
"""Archive the two supplied legacy monitors. Preview by default; --apply changes files."""
import argparse
from contextlib import contextmanager
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

if sys.argv[0] == '-c':
    sys.argv = sys.argv[1:]
os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
os.environ['LC_ALL'] = 'C'
ARCHIVE = Path('/var/lib/freepbx-care')
SMTP_RESET = Path('/etc/freepbx-care/smtp-reset.json')
SMTP_GUARD = 'smtp, relay'
LEGACY_SMTP_PARAMS = ['relayhost', 'smtp_use_tls', 'smtp_sasl_auth_enable',
    'smtp_sasl_security_options', 'smtp_sasl_password_maps', 'smtp_tls_security_level',
    'smtp_tls_CAfile', 'smtp_tls_wrappermode', 'smtp_sasl_mechanism_filter']
MONITORS = ['/usr/local/bin/asterisk-monitor.sh', '/usr/local/bin/extension_monitor.sh']
INSTALLERS = {
    '/root/install-extension-check.sh': '20541090a2237df1f8b9631e5e71c584c2effc0e1e9cdf6d1524475fb5e6a72a',
    '/root/install-fpbx-monitor.sh': '80a22a351f4ecf7e07caf60b917344376d2eb45ed1387f33c8d4ad68d3bf1f4e',
    '/root/setup_smtp.sh': '0f157310966230c9257c319e7e353c921a260f0a7e17a6f294cc45c8ed9325d5',
    '/root/smtp-for-freepbx17.sh': '0f157310966230c9257c319e7e353c921a260f0a7e17a6f294cc45c8ed9325d5',
}
PATTERN = re.compile(r'''(?<![A-Za-z0-9_./-])/usr/local/bin/(?:asterisk-monitor\.sh|extension_monitor\.sh)(?=[\s"';&|<>]|$)''')
POSTFIX_FILES = ['/etc/postfix/main.cf', '/etc/postfix/generic', '/etc/postfix/generic.db',
                 '/etc/postfix/sender_canonical_maps', '/etc/postfix/sender_canonical_maps.db',
                 '/etc/postfix/header_check', '/etc/postfix/sasl/sasl_passwd',
                 '/etc/postfix/sasl/sasl_passwd.db', '/etc/aliases', str(SMTP_RESET)]


def run(args, data=None, ok=True):
    p = subprocess.run(args, input=data, capture_output=True, text=True, timeout=30)
    if ok and p.returncode:
        raise RuntimeError(f'{args[0]} failed (exit {p.returncode}): {p.stderr[:200]}')
    return p


def split_cron(text):
    kept, removed = [], []
    for line in text.splitlines(keepends=True):
        if not line.lstrip().startswith('#') and PATTERN.search(line):
            # Refuse compound jobs rather than deleting an unrelated chained task.
            no_redirect = re.sub(r'\d*[<>]&\d+', '', line)
            if re.search(r'[;&|]', no_redirect):
                raise ValueError('A legacy cron line contains chained commands; split/review that line first')
            removed.append(line)
        else:
            kept.append(line)
    return ''.join(kept), removed


def read_cron():
    p = run(['crontab', '-l'], ok=False)
    if p.returncode and 'no crontab for' not in p.stderr.lower():
        raise RuntimeError('Cannot inspect root crontab')
    return p.stdout if p.returncode == 0 else ''


def regular(path):
    if path.is_symlink():
        raise ValueError(f'Refusing symlink: {path}')
    if path.exists() and not path.is_file():
        raise ValueError(f'Refusing non-file: {path}')
    return path.exists()


def legacy_rewrites():
    """Only identify exact paths and the catch-all rules produced by the old installer."""
    rules = {}
    main = Path('/etc/postfix/main.cf')
    if not regular(main):
        return rules
    for param, kind, path in [
        ('sender_canonical_maps', 'regexp', '/etc/postfix/sender_canonical_maps'),
        ('smtp_header_checks', 'regexp', '/etc/postfix/header_check'),
        ('smtp_generic_maps', 'hash', '/etc/postfix/generic')]:
        p = Path(path)
        if not regular(p):
            continue
        text = p.read_text().strip()
        recognized = False
        if param == 'sender_canonical_maps':
            recognized = bool(re.fullmatch(r'/\.\+/ [A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+', text))
        elif param == 'smtp_header_checks':
            recognized = bool(re.fullmatch(r'/\^From:\.\*\$/ REPLACE From: [A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+', text))
        else:
            rows = [s.split() for s in text.splitlines()]
            expected = ['root', 'root@localhost', 'root@localhost.localdomain', 'root@freepbx',
                        'root@freepbx.localdomain', 'asterisk', 'asterisk@localhost',
                        'asterisk@localhost.localdomain', 'asterisk@freepbx',
                        'asterisk@famecomputers.com', 'vm@asterisk']
            recognized = (len(rows) == len(expected) and all(len(r) == 2 for r in rows) and
                          [r[0] for r in rows] == expected and len({r[1] for r in rows}) == 1)
        if recognized and run(['postconf', '-h', param]).stdout.strip() == f'{kind}:{path}':
            rules[param] = f'{kind}:{path}'
    return rules


def old_process_running():
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        if path.parent.name == str(os.getpid()):
            continue
        try:
            if any(a.decode(errors='replace') in MONITORS for a in path.read_bytes().split(b'\0')):
                return True
        except OSError:
            continue
    return False


def active_controller_running():
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        if path.parent.name == str(os.getpid()): continue
        try:
            args = [a.decode(errors='replace') for a in path.read_bytes().split(b'\0') if a]
            if any(a in MONITORS or a.rsplit('/', 1)[-1] == 'fwconsole' for a in args):
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise RuntimeError('Cannot inspect all processes; inherited-lock retirement refused') from None
    return False


def lock_holders(fd):
    target = os.fstat(fd)
    holders = []
    for proc in Path('/proc').glob('[0-9]*'):
        if proc.name == str(os.getpid()): continue
        try:
            fds = list((proc / 'fd').iterdir())
            matches = False
            for entry in fds:
                try:
                    item = entry.stat()
                    if (item.st_dev, item.st_ino) == (target.st_dev, target.st_ino):
                        matches = True
                        break
                except (FileNotFoundError, ProcessLookupError):
                    continue
            if matches:
                args = [a.decode(errors='replace') for a in (proc / 'cmdline').read_bytes().split(b'\0') if a]
                holders.append(dict(pid=int(proc.name), command=(proc / 'comm').read_text().strip(), args=args))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise RuntimeError('Cannot inspect all file descriptors; inherited-lock retirement refused') from None
    return holders


def validate_inherited_holders(holders):
    if not holders:
        raise RuntimeError('No identifiable Asterisk holders; inherited-lock retirement refused')
    for holder in holders:
        args = holder['args']
        command = holder['command']
        first = args[0].rsplit('/', 1)[-1] if args else ''
        safe_wrapper = (command == 'safe_asterisk' and first in ['sh', 'bash', 'dash', 'safe_asterisk'] and
                        any(a.rsplit('/', 1)[-1] == 'safe_asterisk' for a in args[:2]))
        daemon = command == 'asterisk' and first == 'asterisk'
        if not (safe_wrapper or daemon):
            raise RuntimeError(f"Lock also opened by PID {holder['pid']} ({command}); retirement refused")


def retire_inherited_lock(path, fd):
    """Disable known legacy scheduling, then rename only a verified inherited lock.

    No process is signalled. Existing daemons keep their original open inode.
    """
    if path != Path('/tmp/ast_mon.lock'):
        raise RuntimeError('Only the legacy /tmp/ast_mon.lock can be retired')
    original = os.fstat(fd)
    if not stat.S_ISREG(original.st_mode) or original.st_uid != 0:
        raise RuntimeError('Legacy lock must be a root-owned regular file')
    if active_controller_running():
        raise RuntimeError('A legacy monitor or fwconsole command is active; wait for it to finish')
    holders = lock_holders(fd)
    validate_inherited_holders(holders)
    output = run(['asterisk', '-rx', 'core show uptime seconds']).stdout
    if not re.search(r'System uptime:\s*\d+', output):
        raise RuntimeError('Asterisk CLI readiness not established; inherited lock left untouched')
    cron = read_cron()
    kept, removed = split_cron(cron)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup = ARCHIVE / ('lock-retirement-' + stamp)
    backup.mkdir(mode=0o700, parents=True)
    (backup / 'root-crontab.bak').write_text(cron)
    changed = False
    try:
        if read_cron() != cron:
            raise RuntimeError('Root crontab changed during inspection; retry')
        if removed:
            run(['crontab', '-'], kept)
            changed = True
        if active_controller_running():
            raise RuntimeError('A controller started during retirement; wait and retry')
        validate_inherited_holders(lock_holders(fd))
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise RuntimeError('Legacy lock path changed during inspection; retry')
        retired = path.with_name(path.name + '.retired-' + stamp)
        if retired.exists(): raise RuntimeError('Retirement destination already exists')
        os.rename(path, retired)
        (backup / 'retirement.json').write_text(json.dumps(dict(
            original=str(path), retired=str(retired), holders=holders,
            removed_cron=removed, device=original.st_dev, inode=original.st_ino), indent=2))
        print(f'Inherited lock retired to {retired}; no processes stopped. Cron backup: {backup}')
    except Exception:
        if changed:
            print(f'Legacy cron jobs remain disabled to prevent a race. Backup: {backup}')
        raise


@contextmanager
def locks(retire_inherited=False):
    handles = []
    try:
        for name in ['/run/freepbx-care.lock', '/tmp/ast_mon.lock']:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            f = os.fdopen(fd, 'w')
            handles.append(f)
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                if retire_inherited and name == '/tmp/ast_mon.lock':
                    retire_inherited_lock(Path(name), f.fileno())
                    handles.remove(f)
                    f.close()
                    fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                    f = os.fdopen(fd, 'w')
                    handles.append(f)
                    try:
                        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        raise RuntimeError('Replacement legacy lock is busy; retry after inspecting processes') from None
                else:
                    raise RuntimeError(f'A monitor/recovery holds {name}; inspect the holder before retrying') from None
        if old_process_running():
            raise RuntimeError('A legacy monitor process is running; wait for it to finish and retry')
        yield
    finally:
        for f in handles:
            f.close()


def smtp_reset_plan():
    if not regular(Path('/etc/postfix/main.cf')):
        return None
    active = run(['postconf', '-h', 'smtp_sasl_password_maps']).stdout.strip()
    if active != 'hash:/etc/postfix/sasl/sasl_passwd':
        print('No active relay map matching the original SMTP installer; SMTP reset skipped.')
        return None
    if SMTP_RESET.exists():
        raise RuntimeError('SMTP reset marker already exists; finish/review the previous reset first')
    return dict(previous_defer_transports=run(['postconf', '-h', 'defer_transports']).stdout.strip(),
                guard=SMTP_GUARD)


def write_reset_marker(value):
    SMTP_RESET.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=SMTP_RESET.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(value, f)
        os.replace(name, SMTP_RESET)
    finally:
        if os.path.exists(name): os.unlink(name)


def cleanup(apply=False, remove_rewrites=False, reset_smtp=False):
    cron = read_cron()
    kept, removed = split_cron(cron)
    archive = []
    for name in MONITORS:
        if regular(Path(name)):
            archive.append(Path(name))
    for name, digest in INSTALLERS.items():
        p = Path(name)
        if regular(p):
            raw = p.read_bytes().replace(b'\r\n', b'\n')
            if hashlib.sha256(raw).hexdigest() == digest:
                archive.append(p)
            else:
                print(f'Preserve modified/unrecognized installer: {name}')
    rules = legacy_rewrites()
    reset = smtp_reset_plan() if reset_smtp else None
    remove_rewrites = remove_rewrites or bool(reset)
    if reset:
        for name in ['/etc/postfix/sasl/sasl_passwd', '/etc/postfix/sasl/sasl_passwd.db']:
            if regular(Path(name)): archive.append(Path(name))
    timer = Path('/etc/systemd/system/freepbx-care.timer')
    disable_care = (regular(timer) and 'Description=Check FreePBX health' in timer.read_text() and
                    (run(['systemctl', 'is-enabled', 'freepbx-care.timer'], ok=False).returncode == 0 or
                     run(['systemctl', 'is-active', 'freepbx-care.timer'], ok=False).returncode == 0))
    print(f'Legacy root cron jobs to remove: {len(removed)}')
    print('Files to archive:', ', '.join(map(str, archive)) or 'none')
    print('Previous FreePBX Care timer to disable:', disable_care)
    print('Recognized legacy sender rules:', ', '.join(rules) or 'none')
    print('Sender rules:', 'detach recognized rules' if remove_rewrites else 'preserve (default)')
    if reset:
        print('RESET SMTP: remove old relay/TLS/auth settings and archive its password files.')
        print('External smtp/relay deliveries will be deferred until the UPDATED SMTP setup completes.')
    else:
        print('SMTP relay/password settings remain in place.')
    print('Aliases, queues, packages, firewall and core service configuration remain in place.')
    print('Legacy logs and unknown /tmp property flags remain available; no wildcard deletion.')
    if not apply:
        print('Preview only. Apply with: bash cleanup-legacy-freepbx.sh --apply')
        return
    if not archive and not removed and not (remove_rewrites and rules) and not disable_care and not reset:
        print('No legacy changes needed.')
        return
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup = ARCHIVE / ('legacy-backup-' + stamp)
    backup.mkdir(mode=0o700, parents=True)
    (backup / 'root-crontab.bak').write_text(cron)
    for name in POSTFIX_FILES:
        p = Path(name)
        if regular(p):
            target = backup / p.relative_to(p.anchor)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
            os.chmod(target, 0o600)
    (backup / 'manifest.json').write_text(json.dumps(dict(
        archived=list(map(str, archive)), removed_cron=removed,
        detached_rules=rules if remove_rewrites else {}, smtp_reset=reset,
        disabled_care_timer=disable_care), indent=2))
    moved = []
    cron_written = False
    original_main = Path('/etc/postfix/main.cf')
    try:
        if disable_care:
            run(['systemctl', 'disable', '--now', 'freepbx-care.timer'])
        if read_cron() != cron:
            raise RuntimeError('Root crontab changed during cleanup; retry')
        if removed:
            run(['crontab', '-'], kept)
            cron_written = True
        if reset:
            write_reset_marker(reset)
            # Avoid accidental direct delivery after removing relayhost.
            run(['postconf', '-e', 'defer_transports = ' + SMTP_GUARD])
            for param in LEGACY_SMTP_PARAMS:
                run(['postconf', '-X', param])
        if remove_rewrites and rules:
            for param in rules:
                run(['postconf', '-X', param])
        if reset or (remove_rewrites and rules):
            run(['postfix', 'check'])
            run(['postfix', 'reload'])
        for p in archive:
            target = backup / p.relative_to(p.anchor)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(p), str(target))
            moved.append((p, target))
    except Exception:
        for p, target in reversed(moved):
            shutil.move(str(target), str(p))
        if cron_written:
            run(['crontab', '-'], cron, ok=False)
        saved_main = backup / 'etc/postfix/main.cf'
        if (remove_rewrites or reset) and saved_main.exists():
            shutil.copy2(saved_main, original_main)
            run(['postfix', 'reload'], ok=False)
        if reset and SMTP_RESET.exists():
            SMTP_RESET.unlink()
        print(f'Cleanup failed; attempted file/crontab rollback. Review {backup}.')
        print('If the previous Care timer was disabled, it remains disabled until explicitly re-enabled.')
        raise
    print(f'Cleanup complete. Backup: {backup}')
    print('Legacy monitoring is disabled. Install the replacement promptly; no Asterisk restart was performed.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apply', action='store_true')
    p.add_argument('--remove-sender-rewrites', action='store_true',
                   help='also detach exact recognized legacy sender rules; may change voicemail sender behavior')
    p.add_argument('--reset-smtp', action='store_true',
                   help='reset recognized old SMTP relay settings; defer SMTP delivery until new setup')
    p.add_argument('--retire-inherited-lock', action='store_true',
                   help='disable known legacy cron and retire a lock held only by healthy Asterisk daemons')
    args = p.parse_args()
    if os.geteuid() != 0 or not Path('/etc/freepbx.conf').exists():
        raise RuntimeError('Run as root INSIDE the FreePBX container, not on the Proxmox host')
    os.umask(0o077)
    if args.apply:
        with locks(args.retire_inherited_lock):
            cleanup(True, args.remove_sender_rewrites, args.reset_smtp)
    else:
        cleanup(False, args.remove_sender_rewrites, args.reset_smtp)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
PYTHON
)" "$0" "$@"
FREEPBX_CLEANUP_PAYLOAD
  then
    processed=$((processed + 1))
  else
    echo "FAILED CT $ctid: inspect the cleanup output above."
    failed=$((failed + 1))
  fi
done
echo "Summary: processed=$processed skipped=$skipped failed=$failed"
echo 'Backups are inside each processed container: /var/lib/freepbx-care/legacy-backup-*'
echo 'Install/configure the UPDATED freepbx-care.sh SMTP setup promptly after an SMTP reset.'
[[ $failed -eq 0 && $skipped -eq 0 ]]
