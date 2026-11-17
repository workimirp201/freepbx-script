#!/bin/bash
set -euo pipefail
exec python3 -c "$(cat <<'PYTHON'
import sys
if sys.argv[0]=='-c':sys.argv=sys.argv[1:]
"""Node-local v9 deployment. Preview updates by default; no cluster fan-out."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

# Replaced by build-development.py with the reviewed component pins/payload.
HASHES = {'freepbx-care.sh': '88962969b47757b0a32159249b468623c7ee7edba07a0d3eb4b6f5d10838894f', 'freepbx-voicemail.py': 'f0316a610b52c845178dbeec0524b4fc22997dd81132666d6788e89b2663890b', 'freepbx-voicemail-ami.py': '8acacb15c8eac45869d251325203d1cc190d82e5faaa09d0e7ff3125fea10edf'}
PAYLOAD = '"""Executed inside one CT under both operation locks. Payload is hash-pinned by host."""\nimport fcntl\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport shutil\nimport subprocess\nimport sys\nimport tempfile\nimport time\n\nTARGETS={\'freepbx-care.sh\':Path(\'/root/freepbx-care.sh\'),\n         \'freepbx-voicemail.py\':Path(\'/usr/local/lib/freepbx-care/voicemail.py\'),\n         \'freepbx-voicemail-ami.py\':Path(\'/usr/local/lib/freepbx-care/voicemail_ami.py\')}\nUNITS=[\'freepbx-care.service\',\'freepbx-care.timer\',\'freepbx-voicemail.service\',\n       \'freepbx-voicemail.timer\',\'freepbx-voicemail-listener.service\']\nETC=Path(\'/etc/freepbx-care\');STATE=Path(\'/var/lib/freepbx-care\')\nAMI_FILES=[\'manager_custom.conf\',\'manager_care_voicemail.conf\']\n\ndef ctl(*args,check=True):\n    p=subprocess.run([\'systemctl\',*args],capture_output=True,text=True,timeout=25)\n    if check and p.returncode:raise RuntimeError(\'systemctl \'+args[0]+\' failed; review journal\')\n    return p.stdout.strip()\n\ndef atomic(path,raw,mode):\n    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)\n    fd,temp=tempfile.mkstemp(dir=path.parent,prefix=\'.care-transaction-\')\n    try:\n        with os.fdopen(fd,\'wb\') as f:\n            os.fchmod(f.fileno(),mode);f.write(raw);f.flush();os.fsync(f.fileno())\n        os.replace(temp,path)\n    finally:\n        if os.path.exists(temp):os.unlink(temp)\n\ndef namespace(source):\n    code=source.split("<<\'PYTHON\'\\n",1)[1].rsplit(\'\\nPYTHON\\n\',1)[0]\n    result={\'__name__\':\'care_transaction\'};sys.argv=[\'/root/freepbx-care.sh\']\n    exec(compile(code,\'care:validation\',\'exec\'),result)\n    return result\n\ndef rollback(backup):\n    backup=Path(backup)\n    if not backup.name.startswith(\'deployment-backup-\') or backup.parent!=STATE or backup.is_symlink():raise RuntimeError(\'Use a deployment backup inside this CT Care state directory\')\n    manifest=json.loads((backup/\'manifest.json\').read_text())\n    current=TARGETS[\'freepbx-care.sh\']\n    if current.is_file() and namespace(current.read_text())[\'fwconsole_busy\']():raise RuntimeError(\'Native work is active; finish before rollback\')\n    for unit in [\'freepbx-care.service\',\'freepbx-voicemail.service\']:\n        if ctl(\'show\',unit,\'-p\',\'ActiveState\',\'--value\',check=False) in [\'active\',\'activating\',\'deactivating\']:raise RuntimeError(\'Care/voicemail work active; retry later\')\n    allowed={str(p) for p in TARGETS.values()}|{str(ETC/n) for n in [\'config.json\',\'monitoring.json\',\'node-managed.json\',\'voicemail.json\']}\n    allowed|={str(Path(\'/etc/asterisk\')/n) for n in AMI_FILES}\n    allowed|={str(Path(\'/etc/systemd/system\')/u) for u in UNITS}\n    allowed|={str(Path(\'/etc/postfix\')/n) for n in [\'main.cf\',\'master.cf\',\'sasl_passwd\',\'sasl_passwd.db\',\'sender_canonical\',\'sender_canonical.db\']}\n    for info in manifest[\'files\']:\n        if info[\'path\'] not in allowed or not str(info[\'backup\']).isdigit():raise RuntimeError(\'Invalid rollback manifest path\')\n        if Path(info[\'path\']).is_symlink() or (backup/info[\'backup\']).is_symlink():raise RuntimeError(\'Refusing symlink rollback path\')\n    for u in [\'freepbx-care.timer\',\'freepbx-voicemail.timer\',\'freepbx-voicemail-listener.service\']:ctl(\'stop\',u,check=False)\n    for info in manifest[\'files\']:\n        p=Path(info[\'path\'])\n        if info[\'exists\']:\n            atomic(p,(backup/info[\'backup\']).read_bytes(),info[\'mode\']);os.chown(p,info[\'uid\'],info[\'gid\'])\n        else:p.unlink(missing_ok=True)\n    ctl(\'daemon-reload\')\n    if any(x[\'path\'].startswith(\'/etc/asterisk/\') for x in manifest[\'files\']):\n        subprocess.run([\'asterisk\',\'-rx\',\'manager reload\'],check=True,timeout=20,capture_output=True)\n    restore_units(manifest[\'states\'])\n    if any(x[\'path\'].startswith(\'/etc/postfix/\') for x in manifest[\'files\']):\n        subprocess.run([\'postfix\',\'reload\'],check=False,timeout=20,capture_output=True)\n    return dict(result=\'rolled-back\',backup=str(backup))\n\ndef restore_units(states):\n    for unit,old in states.items():\n        if old[\'enabled\'] in [\'enabled\',\'enabled-runtime\']:\n            ctl(\'unmask\',unit,check=False)\n            ctl(\'enable\',*([\'--runtime\'] if old[\'enabled\']==\'enabled-runtime\' else []),unit)\n        elif old[\'enabled\'] in [\'masked\',\'masked-runtime\']:\n            ctl(\'mask\',*([\'--runtime\'] if old[\'enabled\']==\'masked-runtime\' else []),unit)\n        else:ctl(\'disable\',unit,check=False)\n        # Never run/restart the PBX check as a rollback side effect.\n        if unit.endswith(\'.timer\') or unit==\'freepbx-voicemail-listener.service\':\n            ctl(\'start\' if old[\'active\']==\'active\' else \'stop\',unit,check=old[\'active\']==\'active\')\n\ndef transaction(data):\n    files=data[\'files\'];hashes=data[\'hashes\']\n    for name in TARGETS:\n        raw=files[name].encode()\n        if hashlib.sha256(raw).hexdigest()!=hashes[name]:raise RuntimeError(\'Component payload hash mismatch\')\n        if name.endswith(\'.py\'):compile(raw,name,\'exec\')\n    ns=namespace(files[\'freepbx-care.sh\'])\n    if not Path(\'/etc/freepbx.conf\').is_file():return dict(result=\'skipped\',reason=\'not FreePBX\')\n    if data[\'mode\']==\'update\' and not (ETC/\'config.json\').is_file():return dict(result=\'skipped\',reason=\'Care not installed; use initial installer\')\n    if (STATE/\'module-change-pending.json\').exists() or ns[\'fwconsole_busy\']():raise RuntimeError(\'Finish native/module work first\')\n    service=Path(\'/etc/systemd/system/freepbx-care.service\')\n    if service.is_file() and \'ExecStart=/bin/bash /root/freepbx-care.sh check\' not in service.read_text():\n        raise RuntimeError(\'Custom Care service requires review\')\n    if Path(\'/etc/systemd/system/freepbx-care.service.d\').exists():raise RuntimeError(\'Custom Care overrides require review before update\')\n    for unit in UNITS:\n        path=Path(\'/etc/systemd/system\')/unit\n        if (Path(\'/etc/systemd/system\')/(unit+\'.d\')).exists() or (Path(\'/run/systemd/system\')/(unit+\'.d\')).exists():\n            raise RuntimeError(\'Custom Care/voicemail unit overrides require review: \'+unit)\n        if path.is_file() and unit.startswith(\'freepbx-voicemail\'):\n            expected=(\'Unit=freepbx-voicemail.service\' if unit.endswith(\'.timer\') else\n                      \'ExecStart=/usr/bin/python3 /usr/local/lib/freepbx-care/\'+(\'voicemail_ami.py\' if \'listener\' in unit else \'voicemail.py work\'))\n            if expected not in path.read_text():raise RuntimeError(\'Custom voicemail unit requires review: \'+unit)\n    ns[\'preflight\']()\n    for unit in [\'freepbx-care.service\',\'freepbx-voicemail.service\']:\n        if ctl(\'show\',unit,\'-p\',\'ActiveState\',\'--value\',check=False) in [\'active\',\'activating\',\'deactivating\']:\n            raise RuntimeError(\'Care/voicemail operation active; retry after it completes\')\n    if not data[\'apply\']:return dict(result=\'preview\',version=ns[\'VERSION\'],components=list(TARGETS))\n    paths=list(TARGETS.values())+[ETC/\'config.json\',ETC/\'monitoring.json\',ETC/\'node-managed.json\',ETC/\'voicemail.json\']\n    paths += [Path(\'/etc/asterisk\')/n for n in AMI_FILES]\n    paths += [Path(\'/etc/systemd/system\')/u for u in UNITS]\n    # SMTP/package installation is explicit on first install; files can be restored,\n    # installed packages are intentionally retained if configuration fails.\n    if data.get(\'smtp\'):\n        paths += [Path(\'/etc/postfix\')/n for n in [\'main.cf\',\'master.cf\',\'sasl_passwd\',\'sasl_passwd.db\',\'sender_canonical\',\'sender_canonical.db\']]\n    for p in paths:\n        if p.is_symlink() or (p.exists() and not p.is_file()):raise RuntimeError(\'Custom/symlink deployment path requires review\')\n    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)\n    backup=STATE/(\'deployment-backup-\'+str(time.time_ns()));backup.mkdir(mode=0o700)\n    states={u:dict(enabled=ctl(\'show\',u,\'-p\',\'UnitFileState\',\'--value\',check=False),\n                   active=ctl(\'show\',u,\'-p\',\'ActiveState\',\'--value\',check=False)) for u in UNITS}\n    manifest={\'version\':ns[\'VERSION\'],\'phase\':\'prepared\',\'states\':states,\'files\':[],\'created\':time.time()}\n    for index,p in enumerate(paths):\n        info={\'path\':str(p),\'backup\':str(index),\'exists\':p.exists()}\n        if p.exists():\n            st=p.stat();info.update(mode=st.st_mode&0o777,uid=st.st_uid,gid=st.st_gid)\n            atomic(backup/str(index),p.read_bytes(),0o600)\n        manifest[\'files\'].append(info)\n    def phase(value):\n        manifest[\'phase\']=value;atomic(backup/\'manifest.json\',json.dumps(manifest,indent=2).encode(),0o600)\n    phase(\'prepared\')\n    try:\n        for unit in [\'freepbx-care.timer\',\'freepbx-voicemail.timer\',\'freepbx-voicemail-listener.service\']:ctl(\'stop\',unit,check=False)\n        # Locks already held; repeat activity check after stopping dispatchers.\n        if ns[\'fwconsole_busy\']():raise RuntimeError(\'Native work started during preflight\')\n        for name,target in TARGETS.items():atomic(target,files[name].encode(),0o700)\n        phase(\'components-written\')\n        if data[\'mode\']==\'install\':\n            current=json.loads((ETC/\'config.json\').read_text()) if (ETC/\'config.json\').exists() else {}\n            # Initial installer never silently changes existing per-site recovery settings.\n            for key,value in data.get(\'settings\',{}).items():current.setdefault(key,value)\n            atomic(ETC/\'config.json\',(json.dumps(current,indent=2)+\'\\n\').encode(),0o600)\n        if data.get(\'enable_core_fastagi\'):\n            current=json.loads((ETC/\'config.json\').read_text());current[\'recover_core_fastagi\']=True\n            atomic(ETC/\'config.json\',json.dumps(current,indent=2).encode(),0o600)\n        if data.get(\'smtp\'):\n            profile=backup/\'smtp-profile.json\';atomic(profile,json.dumps(data[\'smtp\']).encode(),0o600)\n            try:ns[\'smtp_setup\'](data[\'smtp\'])\n            finally:profile.unlink(missing_ok=True)\n        # Node-managed by default. Container timer must never race initial deployment.\n        if not (ETC/\'node-managed.json\').exists():\n            original=states[\'freepbx-care.timer\']\n            atomic(ETC/\'node-managed.json\',json.dumps(original).encode(),0o600)\n        for directory in [ETC,STATE,Path(\'/var/log/freepbx-care\')]:directory.mkdir(mode=0o700,parents=True,exist_ok=True)\n        ns[\'install\']()\n        ctl(\'disable\',\'--now\',\'freepbx-care.timer\')\n        phase(\'care-installed\')\n        # Configured r8 workers are updated too. Existing profile/credentials never reset.\n        migration_required=False\n        vmconfig=ETC/\'voicemail.json\'\n        if vmconfig.exists():\n            import importlib.util\n            spec=importlib.util.spec_from_file_location(\'deployment_voicemail\',TARGETS[\'freepbx-voicemail.py\'])\n            vm=importlib.util.module_from_spec(spec);sys.modules[spec.name]=vm;spec.loader.exec_module(vm)\n            c=vm.config()\n            vm.install(enable=False)\n            if c.get(\'listener\',{}).get(\'secret\') and c.get(\'ops_email\'):\n                restore_units({u:s for u,s in states.items() if u.startswith(\'freepbx-voicemail\')})\n            else:\n                migration_required=any(p.get(\'enabled\') for p in c.get(\'mailboxes\',{}).values())\n                ctl(\'disable\',\'--now\',\'freepbx-voicemail.timer\',check=False)\n                ctl(\'disable\',\'--now\',\'freepbx-voicemail-listener.service\',check=False)\n                print(\'Voicemail migration requires menu 19: operations email and dedicated AMI account. Worker paused; saved profiles retained.\')\n        else:\n            for unit in UNITS:\n                if unit.startswith(\'freepbx-voicemail\'):\n                    ctl(\'disable\',\'--now\',unit,check=False)\n                    (Path(\'/etc/systemd/system\')/unit).unlink(missing_ok=True)\n            ctl(\'daemon-reload\')\n        for name,target in TARGETS.items():\n            if hashlib.sha256(target.read_bytes()).hexdigest()!=hashes[name]:raise RuntimeError(\'Post-install hash mismatch\')\n        phase(\'committed\')\n        if data[\'mode\']==\'install\':ns[\'testmail\']()\n        return dict(result=\'updated\' if data[\'mode\']==\'update\' else \'installed\',version=ns[\'VERSION\'],backup=str(backup),voicemail_setup_required=migration_required)\n    except BaseException:\n        phase(\'rolling-back\')\n        for unit in [\'freepbx-care.timer\',\'freepbx-voicemail.timer\',\'freepbx-voicemail-listener.service\']:ctl(\'stop\',unit,check=False)\n        for info in reversed(manifest[\'files\']):\n            path=Path(info[\'path\'])\n            if info[\'exists\']:\n                atomic(path,(backup/info[\'backup\']).read_bytes(),info[\'mode\']);os.chown(path,info[\'uid\'],info[\'gid\'])\n            else:path.unlink(missing_ok=True)\n        ctl(\'daemon-reload\');restore_units(states)\n        if data.get(\'smtp\'):subprocess.run([\'postfix\',\'reload\'],timeout=20,check=False,capture_output=True)\n        phase(\'rolled-back\');raise\n\ndef main():\n    data=json.load(sys.stdin);os.umask(0o077)\n    if not data[\'apply\']:\n        print(\'FREEPBX_UPDATE_RESULT=\'+json.dumps(transaction(data)));return\n    # Both setup/worker and Care honor these same locks. Never kill an active send.\n    STATE.mkdir(mode=0o700,parents=True,exist_ok=True)\n    vmstate=STATE/\'voicemail\';vmstate.mkdir(mode=0o700,exist_ok=True)\n    with open(\'/run/freepbx-care.lock\',\'w\') as care, (vmstate/\'lock\').open(\'w\') as voicemail:\n        for f in [care,voicemail]:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n        result=rollback(data[\'rollback\']) if data.get(\'rollback\') else transaction(data)\n        print(\'FREEPBX_UPDATE_RESULT=\'+json.dumps(result))\n\nif __name__==\'__main__\':\n    try:main()\n    except (OSError,RuntimeError,ValueError) as error:\n        if isinstance(error,BlockingIOError):reason=\'Care/voicemail operation lock is busy; wait and retry without killing current work\'\n        elif str(error).startswith((\'Care/voicemail operation active\',\'Finish native/module work first\',\'Custom Care\',\'Component payload hash mismatch\')):\n            reason=str(error)\n        else:reason=\'Operation refused/failed (\'+type(error).__name__+\'); inspect CT health, journal and private deployment manifest\'\n        print(\'FREEPBX_UPDATE_RESULT=\'+json.dumps(dict(result=\'failed\',reason=reason)))\n'
BASE='https://raw.githubusercontent.com/workimirp201/freepbx-script/refs/heads/main/'
MODE='update'

def run(args,timeout=30,data=None):
    with tempfile.TemporaryFile() as inp,tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        if data is not None:inp.write(data.encode())
        inp.seek(0)
        p=subprocess.Popen(args,stdin=inp,stdout=out,stderr=err,start_new_session=True)
        deadline=time.monotonic()+timeout
        while p.poll() is None:
            if time.monotonic()>deadline or os.fstat(out.fileno()).st_size+os.fstat(err.fileno()).st_size>2*1024*1024:
                p.terminate()
                try:p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    p.kill()
                    try:p.wait(timeout=2)
                    except subprocess.TimeoutExpired:pass
                raise RuntimeError('Deployment deadline/output limit; inspect CT manifest before retrying')
            time.sleep(.05)
        if p.returncode:raise RuntimeError('Command failed (exit '+str(p.returncode)+'); inspect CT journal/private deployment manifest')
        out.seek(0);return out.read(1024*1024).decode(errors='replace').strip()

def bundle(directory=None):
    files={}
    for name,digest in HASHES.items():
        if directory:
            path=Path(directory)/name
            if path.is_symlink():raise RuntimeError('Refusing symlink bundle component')
            raw=path.read_bytes()
        else:
            with urllib.request.urlopen(BASE+name,timeout=30) as response:raw=response.read(524289)
        if len(raw)>524288 or hashlib.sha256(raw).hexdigest()!=digest:
            raise RuntimeError('Component mismatch: '+name+'; publish matching release files. No CT changed.')
        files[name]=raw.decode('utf-8')
    return files

def ask(label,default=''):
    value=input(label+(' ['+default+']' if default else '')+': ').strip();return value or default

def settings():
    host=ask('SMTP relay DNS hostname');port=int(ask('SMTP port','587'))
    tls=ask('TLS mode: starttls or implicit','implicit' if port==465 else 'starttls')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',host) or not 1<=port<=65535 or tls not in ['implicit','starttls']:raise ValueError('Invalid SMTP transport')
    username=ask('SMTP username');password=getpass.getpass('SMTP password: ')
    if not username or re.search(r'[\s:]',username) or not password or re.search(r'[\r\n]',password):raise ValueError('Invalid credentials')
    sender=ask('Relay-authorized sender email');recipient=ask('Operations email','monitor@famecomputers.com')
    if any(not re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',x) for x in [sender,recipient]):raise ValueError('Invalid email')
    while True:
        recovery=ask('Enable automatic recovery? y/n','y').lower()
        if recovery in ['y','n']:break
        print('Answer y or n')
    return dict(host=host,port=port,tls=tls,username=username,password=password,sender=sender),dict(sender=sender,email=recipient,auto_restart=recovery=='y',recovery_priority='availability')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('ctids',nargs='*');p.add_argument('--all-running-freepbx',action='store_true')
    p.add_argument('--apply',action='store_true');p.add_argument('--install-missing',action='store_true')
    p.add_argument('--enable-core-fastagi',action='store_true');p.add_argument('--exclude',action='append',default=[])
    p.add_argument('--bundle-dir',help='Local complete reviewed release folder instead of GitHub')
    p.add_argument('--rollback',help='Explicit in-container deployment-backup directory; requires --apply and one CTID')
    a=p.parse_args()
    if os.geteuid()!=0 or not shutil.which('pct'):p.error('Root on the local Proxmox node required')
    if any(not x.isdigit() for x in a.ctids+a.exclude):p.error('Numeric CTIDs only')
    if a.ctids and a.all_running_freepbx:p.error('Choose explicit CTIDs or all running')
    if a.rollback and (not a.apply or len(a.ctids)!=1 or a.all_running_freepbx or MODE!='update'):p.error('Rollback requires updater --apply, one explicit CTID, and no all-running flag')
    listing={}
    for line in run(['pct','list']).splitlines()[1:]:
        row=line.split()
        if len(row)>=2 and row[0].isdigit():listing[row[0]]=row[1]
    targets=list(dict.fromkeys(a.ctids)) if a.ctids else [x for x,s in listing.items() if s=='running'] if a.all_running_freepbx else []
    if not targets:p.error('Specify CTIDs or --all-running-freepbx')
    files={} if a.rollback else bundle(a.bundle_dir)
    smtp,config=(settings() if MODE=='install' and a.apply else (None,{}))
    if MODE=='install' and not a.apply:print('PREVIEW; use --apply to configure SMTP and deploy. No changes.')
    summary={'installed':[],'updated':[],'preview':[],'skipped':[],'rolled-back':[],'failed':[]}
    for ctid in targets:
        print('===== CT '+ctid+' =====',flush=True)
        try:
            if ctid in a.exclude or listing.get(ctid)!='running':summary['skipped'].append(ctid);continue
            if re.search(r'(?m)^lock:',run(['pct','config',ctid])):raise RuntimeError('Container locked; retry later')
            result=run(['pct','exec',ctid,'--','python3','-c',PAYLOAD],timeout=1200,
                       data=json.dumps(dict(files=files,hashes=HASHES,mode=MODE,apply=a.apply,
                                            smtp=smtp,settings=config,enable_core_fastagi=a.enable_core_fastagi,rollback=a.rollback)))
            for line in result.splitlines():
                if line.startswith('FREEPBX_UPDATE_RESULT='):
                    outcome=json.loads(line.split('=',1)[1]);break
            else:raise RuntimeError('No completion receipt; inspect CT deployment backup before retry')
            summary[outcome['result']].append(ctid);print(json.dumps(outcome),flush=True)
        except (OSError,RuntimeError,ValueError,subprocess.SubprocessError) as e:
            print('CT '+ctid+': '+str(e));summary['failed'].append(ctid)
    print('Summary: '+json.dumps(summary));return bool(summary['failed'])

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        print('Deployment failed; no credentials displayed. Inspect private CT manifest/journal.',file=sys.stderr);sys.exit(1)

PYTHON
)" "$0" "$@"
