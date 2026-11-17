#!/bin/bash
set -euo pipefail
exec python3 -c "$(cat <<'PYTHON'
import sys
if sys.argv[0]=='-c':sys.argv=sys.argv[1:]
#!/usr/bin/env python3
"""v9 node-local scheduler. No cross-node SSH or hard-coded CT exclusions."""
import argparse
import email.message
import email.utils
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path('/var/lib/proxmox-care')
VERSION='2026.11.17-local-care-r9'
DEFAULTS=dict(check_timeout=960,min_memory_percent=15,max_load_per_cpu=1.5,max_pressure_percent=25,
              reminder_seconds=3600,max_health_age=7200)

def run(argv,timeout=20,data=None):
    # Regular files avoid communicate() waiting forever on inherited pipe ends.
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err,tempfile.TemporaryFile() as inp:
        if data is not None:inp.write(data.encode() if isinstance(data,str) else data)
        inp.seek(0)
        p=subprocess.Popen(argv,stdin=inp,stdout=out,stderr=err,start_new_session=True)
        deadline=time.monotonic()+timeout
        while p.poll() is None:
            if time.monotonic()>deadline or out.tell()+err.tell()>2*1024*1024:
                p.terminate()
                try:p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    p.kill()
                    try:p.wait(timeout=2)
                    except subprocess.TimeoutExpired:pass
                raise RuntimeError('Control command timed out/output limit; remote completion must be verified')
            time.sleep(.05)
        out.seek(0);err.seek(0)
        text=out.read(1024*1024).decode(errors='replace')
        if p.returncode:raise RuntimeError('Control command failed (exit '+str(p.returncode)+'); inspect local journal')
        return text.strip()

def save(name,value):
    fd,temp=tempfile.mkstemp(prefix='.node-',dir=ROOT)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(value,f,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(temp,ROOT/name)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def load(name,default):
    path=ROOT/name
    if not path.exists():return default
    if path.is_symlink():raise RuntimeError('Refusing symlink node state/config')
    return json.loads(path.read_text())

def address(value):return isinstance(value,str) and bool(re.fullmatch(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',value))

def config():
    return validate(dict(DEFAULTS,**load('config.json',{})))

def validate(c):
    if not address(c.get('email')) or not address(c.get('sender')):raise RuntimeError('Node recipient/sender invalid; configure --email and --sender')
    if c.get('reply_to') and not address(c['reply_to']):raise RuntimeError('Invalid node Reply-To')
    for key in DEFAULTS:
        if type(c[key]) not in [int,float] or c[key]<=0:raise RuntimeError('Invalid node threshold: '+key)
    if c['check_timeout']>1000 or c['min_memory_percent']>90 or c['max_pressure_percent']>100:
        raise RuntimeError('Node threshold exceeds service/resource limits')
    return c

def send(c,subject,body):
    msg=email.message.EmailMessage()
    msg['To']=c['email'];msg['From']=c['sender'];msg['Subject']=subject
    msg['Date']=email.utils.formatdate(localtime=True)
    msg['Message-ID']=email.utils.make_msgid(domain=c['sender'].rsplit('@',1)[-1])
    if c.get('reply_to'):msg['Reply-To']=c['reply_to']
    msg.set_content(body)
    run(['/usr/sbin/sendmail','-oi','-f',c['sender'],'--',c['email']],timeout=15,data=msg.as_bytes())

def incident(c,state,key,reason=None):
    events=state.setdefault('incidents',{});old=events.get(key,{})
    if reason is None:
        if old.get('status')!='open':return
        status='resolved';reason='Condition resolved; subsequent monitoring continues.'
    else:status='open'
    fresh=old.get('status')!=status or old.get('reason')!=reason
    if not fresh and time.time()-old.get('sent',0)<c['reminder_seconds']:return
    iid=uuid.uuid4().hex if fresh and status=='open' else old.get('id',uuid.uuid4().hex)
    subject=f'[Care][{"ACTION REQUIRED" if status=="open" else "RESOLVED"}][{socket.gethostname()}] {key}'
    print(subject+': '+reason,flush=True)
    try:
        send(c,subject,reason+'\nIncident: '+iid+'\nObserved: '+email.utils.formatdate(localtime=True)+'\nReview node/CT journals. No CT reboot or forced PBX kill was requested.')
        events[key]=dict(id=iid,status=status,reason=reason,sent=time.time())
    except (OSError,RuntimeError):print('Node email not accepted; journal is the fallback.',flush=True)

def inventory():
    result={}
    for line in run(['pct','list']).splitlines()[1:]:
        p=line.split()
        if len(p)>=2 and p[0].isdigit():result[p[0]]=p[1]
    return result

PAYLOAD=r'''
import datetime,json,os,pathlib,subprocess,sys
action=sys.argv[1]
etc=pathlib.Path('/etc/freepbx-care');state=pathlib.Path('/var/lib/freepbx-care')
def read(path,default):return json.loads(path.read_text()) if path.is_file() else default
def ctl(*args):return subprocess.check_output(['systemctl',*args],text=True,timeout=15).strip()
def result(**kw):print(json.dumps(kw));raise SystemExit()
if action=='poll':
    # A disable flag/missing file must never conceal an already-running check.
    active=ctl('show','freepbx-care.service','-p','ActiveState','--value')
    if active not in ['inactive','failed']:result(status='running')
    for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
        try:
            if any(x.rsplit(b'/',1)[-1]==b'fwconsole' for x in p.read_bytes().split(b'\0')):result(status='native-work-running')
        except OSError:pass
if not pathlib.Path('/etc/freepbx.conf').is_file():result(status='not-freepbx')
if not pathlib.Path('/root/freepbx-care.sh').is_file() or not (etc/'config.json').is_file():result(status='missing-care')
if action not in ['restore','disable-timer','inspect'] and read(etc/'monitoring.json',{'enabled':True}).get('enabled',True) is not True:result(status='disabled')
service=pathlib.Path('/etc/systemd/system/freepbx-care.service');timer=service.with_suffix('.timer')
if not service.is_file() or not timer.is_file():result(status='missing-care-units')
if service.is_symlink() or timer.is_symlink():raise RuntimeError('Unrecognized unit aliases')
effective=ctl('cat','freepbx-care.service')
if 'ExecStart=/bin/bash /root/freepbx-care.sh check' not in effective or 'KillMode=process' not in effective:
    raise RuntimeError('Unrecognized Care service; review custom configuration')
if pathlib.Path('/etc/systemd/system/freepbx-care.service.d').exists() or pathlib.Path('/run/systemd/system/freepbx-care.service.d').exists():
    raise RuntimeError('Custom Care service overrides require review')
if ctl('show','freepbx-care.service','-p','KillMode','--value')!='process':raise RuntimeError('Effective Care KillMode is not process')
execution=ctl('show','freepbx-care.service','-p','ExecStart','--value')
if 'argv[]=/bin/bash /root/freepbx-care.sh check ;' not in execution or execution.count('argv[]=')!=1:
    raise RuntimeError('Effective Care command differs from reviewed script')
active=ctl('show','freepbx-care.service','-p','ActiveState','--value')
if action=='inspect':result(status='detected',monitoring=read(etc/'monitoring.json',{'enabled':True}).get('enabled',True),active=active)
if action=='start':
    marker=etc/'node-managed.json'
    if not marker.exists():
        original=dict(enabled=ctl('show','freepbx-care.timer','-p','UnitFileState','--value'),active=ctl('show','freepbx-care.timer','-p','ActiveState','--value'))
        fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(original,f)
    subprocess.run(['systemctl','disable','--now','freepbx-care.timer'],check=True,timeout=15)
    if active in ['inactive','failed']:subprocess.run(['systemctl','start','--no-block','freepbx-care.service'],check=True,timeout=15)
    result(status='running')
if action=='disable-timer':
    marker=etc/'node-managed.json'
    if not marker.exists():
        original=dict(enabled=ctl('show','freepbx-care.timer','-p','UnitFileState','--value'),active=ctl('show','freepbx-care.timer','-p','ActiveState','--value'))
        fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(original,f)
    subprocess.run(['systemctl','disable','--now','freepbx-care.timer'],check=True,timeout=15)
    result(status='transferred')
if action=='restore':
    if active not in ['inactive','failed']:raise RuntimeError('Wait for active Care service before restore')
    marker=etc/'node-managed.json';old=read(marker,{})
    enabled=old.get('enabled','disabled')
    if enabled in ['enabled','enabled-runtime']:
        command=['systemctl','enable']+(['--runtime'] if enabled.endswith('-runtime') else [])+['freepbx-care.timer']
    elif enabled in ['masked','masked-runtime']:command=['systemctl','mask']+(['--runtime'] if enabled.endswith('-runtime') else [])+['freepbx-care.timer']
    else:command=['systemctl','disable','freepbx-care.timer']
    subprocess.run(command,check=True,timeout=15)
    subprocess.run(['systemctl','start' if old.get('active')=='active' else 'stop','freepbx-care.timer'],check=True,timeout=15)
    marker.unlink(missing_ok=True);result(status='restored')
if active not in ['inactive','failed']:result(status='running')
for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
    try:
        if any(x.rsplit(b'/',1)[-1]==b'fwconsole' for x in p.read_bytes().split(b'\0')):result(status='native-work-running')
    except OSError:pass
saved=read(state/'state.json',{})
check=saved.get('last_check_result',{})
locks=[name for prefix,name in [('', 'Asterisk'),('database_', 'MariaDB'),('core_fastagi_', 'Core FastAGI')] if saved.get(prefix+'recovery_blocked') or saved.get(prefix+'recovery_inflight')]
vm=state/'voicemail';failures=0
for path in vm.glob('*.json'):
    if len(path.stem)!=64:continue
    job=read(path,{})
    failures+=bool(job.get('blocked') or any(v.get('result') in ['review','rejected'] for v in job.get('deliveries',{}).values()))
listener=read(vm/'listener-health.json',{})
operations=read(vm/'operations.json',{})
failures+=sum(1 for issue in operations.values() if isinstance(issue,dict) and issue.get('status')=='open')
vconfig=read(etc/'voicemail.json',{})
if vconfig.get('listener') and any(p.get('enabled') for p in vconfig.get('mailboxes',{}).values()):
    import time
    if listener.get('status')!='healthy' or time.time()-listener.get('time',0)>90:failures+=1
result(status='complete',check=check,locks=locks,voicemail_failures=failures,listener=listener,
       execution_error=active=='failed')
'''

def ct(ctid,action):return json.loads(run(['pct','exec',ctid,'--','python3','-c',PAYLOAD,action],timeout=60))

def prior_finished(state,listing):
    pending=state.get('pending_ct')
    if not pending:return True
    if pending not in listing:
        state.setdefault('handoffs',[]).append(dict(ctid=pending,time=time.time(),reason='No longer local; source pending released'))
        state.pop('pending_ct',None);return True
    if listing[pending]=='stopped':state.pop('pending_ct',None);return True
    result=ct(pending,'poll')
    if result['status'] not in ['running','native-work-running']:
        state.pop('pending_ct',None);return True
    return False

def pressure(c):
    mem={k.rstrip(':'):int(v.split()[0]) for k,v in (line.split(None,1) for line in Path('/proc/meminfo').read_text().splitlines())}
    if mem['MemAvailable']/mem['MemTotal']<c['min_memory_percent']/100:return 'Low available memory'
    if os.getloadavg()[0]/(os.cpu_count() or 1)>c['max_load_per_cpu']:return 'High host load'
    for kind in ['cpu','memory','io']:
        path=Path('/proc/pressure')/kind
        if path.is_file():
            for line in path.read_text().splitlines():
                fields=dict(x.split('=') for x in line.split()[1:])
                if float(fields['avg10'])>c['max_pressure_percent']:return 'High host '+kind+' pressure'
    return ''

def once(c,state):
    listing=inventory()
    if not prior_finished(state,listing):
        incident(c,state,'Pending check','Prior service/native work remains active; new dispatch deferred');return
    incident(c,state,'Pending check')
    reason=pressure(c)
    if reason:incident(c,state,'Host pressure',reason);return
    incident(c,state,'Host pressure')
    targets=sorted([x for x,s in listing.items() if s=='running' and x not in state.get('excluded',[]) and x not in state.get('quarantine',{})],key=int)
    if not targets:return
    ctid=next((x for x in targets if int(x)>int(state.get('cursor') or 0)),targets[0])
    state['cursor']=ctid
    cfg=run(['pct','config',ctid])
    if re.search(r'(?m)^lock:',cfg):
        print('CT '+ctid+': backup/migration locked; deferred');return
    state['pending_ct']=ctid;save('state.json',state)
    try:
        result=ct(ctid,'start');deadline=time.monotonic()+c['check_timeout']
        while result['status'] in ['running','native-work-running']:
            if time.monotonic()>deadline:raise RuntimeError('Check deadline exceeded; leaving native recovery intact')
            time.sleep(2);result=ct(ctid,'poll')
        state.pop('pending_ct',None)
        status=result['status'];state.setdefault('results',{})[ctid]=dict(result=result,seen=time.time())
        if status in ['missing-care','missing-care-units']:
            incident(c,state,'CT '+ctid+' installation',status+'; inspect before installing Care');return
        if status in ['disabled','not-freepbx']:
            print('CT '+ctid+': '+status);return
        incident(c,state,'CT '+ctid+' installation')
        report=result.get('check',{});issues=[]
        if result.get('execution_error'):issues.append('Care service failed; saved health may predate this attempt')
        if report.get('status') in ['unhealthy','failed']:issues.append('PBX '+report.get('status','unknown'))
        if report.get('status') in ['deferred','disabled']:print('CT '+ctid+': '+report['status']+'; '+report.get('reason',''))
        if time.time()-report.get('checked_at',0)>c['max_health_age']:issues.append('Fresh health evidence overdue; '+report.get('reason','no structured check yet'))
        issues += [x+' recovery requires review' for x in result.get('locks',[])]
        if result.get('voicemail_failures'):issues.append('Voicemail jobs require review: '+str(result['voicemail_failures']))
        if issues:incident(c,state,'CT '+ctid+' health','; '.join(issues))
        else:incident(c,state,'CT '+ctid+' health')
        print('CT '+ctid+': '+report.get('status','unknown/stale')+'; see structured result',flush=True)
    except (OSError,RuntimeError,ValueError):
        state.setdefault('quarantine',{})[ctid]={'time':time.time(),'reason':'Dispatch/check failed or completion unknown'}
        incident(c,state,'CT '+ctid+' execution','Check failed or timed out; review quarantine/pending state')

def install(c):
    backup=ROOT/('install-backup-'+str(time.time_ns()));backup.mkdir(mode=0o700)
    unitroot=Path('/etc/systemd/system')
    target=Path('/root/proxmox-care-scheduler.sh')
    source=Path(sys.argv[0])
    paths=[ROOT/'config.json',ROOT/'alert-fallback.json',unitroot/'proxmox-care.service',unitroot/'proxmox-care.timer',target]
    existed={str(path):path.exists() for path in paths}
    for path in paths:
        if path.is_symlink():raise RuntimeError('Refusing custom symlink install path')
        if path.is_file():shutil.copy2(path,backup/path.name)
    # Fresh test bypasses incident dedup and validates the actual recipient.
    send(c,f'[Care][TEST][{socket.gethostname()}] Node email test','Fresh test; confirm actual inbox receipt before accepting deployment.')
    old_timer=dict(enabled=run(['systemctl','show','proxmox-care.timer','-p','UnitFileState','--value']),
                   active=run(['systemctl','show','proxmox-care.timer','-p','ActiveState','--value']))
    save('last-install-backup.json',dict(path=str(backup),existed=existed,timer=old_timer))
    try:
        if source.resolve()!=target.resolve():
            fd,temp=tempfile.mkstemp(prefix='.proxmox-care-',dir=target.parent)
            try:
                with os.fdopen(fd,'wb') as f:
                    os.fchmod(f.fileno(),0o700);f.write(source.read_bytes());f.flush();os.fsync(f.fileno())
                os.replace(temp,target)
            finally:
                if os.path.exists(temp):os.unlink(temp)
        os.chmod(target,0o700)
        save('config.json',c)
        save('alert-fallback.json',{key:c[key] for key in ['email','sender','reminder_seconds']})
        (unitroot/'proxmox-care.service').write_text('[Unit]\nDescription=FreePBX Care v9 node queue\n[Service]\nType=oneshot\nExecStart=/bin/bash /root/proxmox-care-scheduler.sh run\nTimeoutStartSec=1200\nNice=10\nIOSchedulingClass=idle\nUMask=0077\n')
        (unitroot/'proxmox-care.timer').write_text('[Unit]\nDescription=Dispatch next local Care check\n[Timer]\nOnBootSec=5min\nOnUnitInactiveSec=10s\nAccuracySec=2s\nRandomizedDelaySec=3s\nUnit=proxmox-care.service\n[Install]\nWantedBy=timers.target\n')
        run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','proxmox-care.timer'])
        for unit in ['proxmox-care.service','proxmox-care.timer']:os.chmod(unitroot/unit,0o644)
    except Exception:
        for path in paths:
            if existed[str(path)]:shutil.copy2(backup/path.name,path)
            else:path.unlink(missing_ok=True)
        run(['systemctl','daemon-reload'])
        if old_timer['enabled'] in ['enabled','enabled-runtime']:
            run(['systemctl','enable']+(['--runtime'] if old_timer['enabled'].endswith('-runtime') else [])+['proxmox-care.timer'])
        else:run(['systemctl','disable','proxmox-care.timer'])
        run(['systemctl','start' if old_timer['active']=='active' else 'stop','proxmox-care.timer'])
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version',action='version',version=VERSION)
    p.add_argument('command',choices=['install','disable-timers','adopt','run','release','restore','status'])
    p.add_argument('ctids',nargs='*');p.add_argument('--apply',action='store_true')
    p.add_argument('--email');p.add_argument('--sender');p.add_argument('--reply-to')
    a=p.parse_args()
    if os.geteuid()!=0 or not shutil.which('pct'):p.error('Root shell on this Proxmox node required')
    if any(not x.isdigit() for x in a.ctids):p.error('Numeric CTIDs only')
    if a.command not in ['disable-timers','adopt'] and a.apply:p.error('--apply is only for timer transfer/adoption')
    if a.command in ['run','install','status'] and a.ctids:p.error('This command does not accept CTIDs')
    if a.command!='install' and any([a.email,a.sender,a.reply_to]):p.error('Email flags are for install/reconfigure only')
    os.umask(0o077)
    if ROOT.is_symlink():p.error('Refusing symlink node directory')
    if a.command=='status':
        print(json.dumps(load('state.json',{}),indent=2));return
    if a.command in ['adopt','disable-timers'] and not a.apply:
        listing=inventory()
        for ctid in a.ctids or list(listing):
            if listing.get(ctid)!='running':print('CT '+ctid+': not running; skipped');continue
            print('PREVIEW CT '+ctid+': '+json.dumps(ct(ctid,'inspect')))
        return
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(ROOT,0o700)
    with (ROOT/'lock').open('w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=load('state.json',dict(managed={},quarantine={},excluded=[],incidents={},cursor=''))
        c=None
        try:
            if a.command=='install':
                c=dict(DEFAULTS,**load('config.json',{}))
                if a.email:c['email']=a.email
                if a.sender:c['sender']=a.sender
                if a.reply_to is not None:c['reply_to']=a.reply_to
                if not address(c.get('email')) or not address(c.get('sender')):p.error('--email and --sender required on first install')
                install(validate(c))
            elif a.command=='run':c=config();once(c,state)
            elif a.command=='status':print(json.dumps(state,indent=2))
            else:
                targets=a.ctids or list(inventory())
                listing=inventory()
                if a.command in ['restore','release'] and not a.ctids:p.error('Explicit CTIDs required')
                for ctid in targets:
                    try:
                        if listing.get(ctid)!='running':print('CT '+ctid+': not running/local; skipped');continue
                        if re.search(r'(?m)^lock:',run(['pct','config',ctid])):
                            print('CT '+ctid+': locked; skipped');continue
                        if a.command=='release':state.setdefault('quarantine',{}).pop(ctid,None);continue
                        if a.command in ['disable-timers','adopt']:
                            if not a.apply:
                                if inventory().get(ctid)!='running':print('CT '+ctid+': not running; skipped');continue
                                print('PREVIEW CT '+ctid+': '+json.dumps(ct(ctid,'inspect')));continue
                            outcome=ct(ctid,'disable-timer')
                            if outcome['status']=='transferred':
                                state.setdefault('managed',{})[ctid]={'node_managed':True}
                                state['excluded']=[x for x in state.get('excluded',[]) if x!=ctid]
                            print('CT '+ctid+': '+outcome['status'])
                        else:
                            print('CT '+ctid+': '+ct(ctid,'restore')['status'])
                            state.setdefault('managed',{}).pop(ctid,None)
                            if ctid not in state.setdefault('excluded',[]):state['excluded'].append(ctid)
                    except (OSError,RuntimeError,ValueError):
                        print('CT '+ctid+': control operation failed; inspect this CT before retry. Continuing other local containers.',flush=True)
                        state.setdefault('batch_failures',{})[ctid]={'time':time.time(),'command':a.command}
            save('state.json',state)
        except Exception:
            if not c:
                try:c=load('alert-fallback.json',{})
                except (OSError,ValueError):c=None
            if c:incident(c,state,'Scheduler failure','Host control/config/inventory operation failed; inspect node journal')
            save('state.json',state);raise

if __name__=='__main__':
    try:main()
    except (OSError,RuntimeError,ValueError,BlockingIOError):
        try:
            fallback=load('alert-fallback.json',{})
            if address(fallback.get('email')) and address(fallback.get('sender')):
                try:state=load('state.json',{})
                except (ValueError,OSError):state={}
                incident(fallback,state,'Scheduler failure','Host control/config/inventory operation failed; inspect node journal')
        except Exception:pass
        print('Node operation failed; inspect journal/state. No forced container stop requested.',file=sys.stderr);sys.exit(1)

PYTHON
)" "$0" "$@"
