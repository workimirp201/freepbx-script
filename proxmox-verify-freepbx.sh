#!/bin/bash
set -euo pipefail
exec python3 -c "$(cat <<'PYTHON'
import sys
if sys.argv[0]=='-c':sys.argv=sys.argv[1:]
"""Read-only node-local r9 migration verification; nonzero for incomplete evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HASHES={'freepbx-care.sh': '88962969b47757b0a32159249b468623c7ee7edba07a0d3eb4b6f5d10838894f', 'freepbx-voicemail.py': 'f0316a610b52c845178dbeec0524b4fc22997dd81132666d6788e89b2663890b', 'freepbx-voicemail-ami.py': '8acacb15c8eac45869d251325203d1cc190d82e5faaa09d0e7ff3125fea10edf'}
NODE_HASH='d6b6ada2837da81899725744f2ca8d004840e90c0664c9c18be3f06779b50057'
AUDIT=r'''
import hashlib,json,pathlib,re,subprocess,time
P=pathlib.Path
expected=json.loads(__import__('sys').argv[1])
def read(path):return json.loads(path.read_text()) if path.is_file() else {}
def ctl(unit,prop):
    r=subprocess.run(['systemctl','show',unit,'-p',prop,'--value'],capture_output=True,text=True,timeout=15)
    return r.stdout.strip()
if not P('/etc/freepbx.conf').is_file():
    print(json.dumps({'status':'not-freepbx'}));raise SystemExit()
issues=[];checks={}
targets={'freepbx-care.sh':'/root/freepbx-care.sh','freepbx-voicemail.py':'/usr/local/lib/freepbx-care/voicemail.py','freepbx-voicemail-ami.py':'/usr/local/lib/freepbx-care/voicemail_ami.py'}
for name,path in targets.items():
    p=P(path);checks[name]=p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest()==expected[name]
    if not checks[name]:issues.append('missing/outdated '+name)
etc=P('/etc/freepbx-care');state=P('/var/lib/freepbx-care')
if not (etc/'config.json').is_file():issues.append('initial Care configuration required')
if not (etc/'node-managed.json').is_file():issues.append('node scheduling ownership marker absent')
if ctl('freepbx-care.timer','ActiveState')!='inactive' or ctl('freepbx-care.timer','UnitFileState') not in ['disabled','masked','masked-runtime']:
    issues.append('container Care timer is still scheduled or unverified')
for name,command in [('freepbx-care.service','ExecStart=/bin/bash /root/freepbx-care.sh check'),('freepbx-care.timer','Unit=freepbx-care.service')]:
    p=P('/etc/systemd/system')/name
    if not p.is_file() or command not in p.read_text():issues.append('missing/custom '+name)
    if (p.parent/(name+'.d')).exists() or (P('/run/systemd/system')/(name+'.d')).exists():issues.append('unit override requires review: '+name)
legacy=['/usr/local/bin/asterisk-monitor.sh','/usr/local/bin/extension_monitor.sh']
for name in legacy:
    if P(name).exists():issues.append('legacy monitor remains: '+name)
cron=subprocess.run(['crontab','-l'],capture_output=True,text=True,timeout=15)
if cron.returncode and 'no crontab' not in cron.stderr.lower():issues.append('root crontab inspection failed')
def active_reference(text):return any(not line.lstrip().startswith('#') and any(p in line for p in legacy) for line in text.splitlines())
if active_reference(cron.stdout):issues.append('legacy root cron scheduling remains')
for p in P('/etc/cron.d').glob('*'):
    if p.is_file() and active_reference(p.read_text(errors='replace')):issues.append('legacy system cron requires review: '+p.name)
for folder in ['/var/spool/cron/crontabs','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly','/etc/cron.monthly']:
    for p in P(folder).glob('*'):
        if p.is_file() and p.name!='root' and active_reference(p.read_text(errors='replace')):issues.append('additional legacy scheduling requires review: '+str(p))
for folder in ['/etc/systemd/system','/lib/systemd/system','/run/systemd/system']:
    for p in P(folder).glob('*.service'):
        if p.is_file() and active_reference(p.read_text(errors='replace')):issues.append('legacy/custom systemd monitor remains: '+p.name)
vm=read(etc/'voicemail.json');profiles=vm.get('mailboxes',{})
vm_active=any(p.get('enabled') for p in profiles.values())
if vm:
    for unit in ['freepbx-voicemail.service','freepbx-voicemail.timer','freepbx-voicemail-listener.service']:
        if not (P('/etc/systemd/system')/unit).is_file():issues.append('missing voicemail unit: '+unit)
        if (P('/etc/systemd/system')/(unit+'.d')).exists() or (P('/run/systemd/system')/(unit+'.d')).exists():issues.append('voicemail unit override requires review: '+unit)
    if vm_active and (not vm.get('ops_email') or not vm.get('listener',{}).get('secret')):issues.append('voicemail AMI/error-email setup required (menu 19)')
    if ctl('freepbx-voicemail.timer','ActiveState')=='active':
        listener=read(state/'voicemail/listener-health.json')
        if listener.get('status')!='healthy' or time.time()-listener.get('time',0)>90:issues.append('voicemail listener is unhealthy/stale')
else:
    for unit in ['freepbx-voicemail.service','freepbx-voicemail.timer','freepbx-voicemail-listener.service']:
        if (P('/etc/systemd/system')/unit).exists():issues.append('orphan voicemail unit without configuration: '+unit)
saved=read(state/'state.json')
health=saved.get('last_check_result',{})
print(json.dumps(dict(status='complete' if not issues else 'incomplete',issues=issues,components=checks,
                     monitoring_enabled=read(etc/'monitoring.json').get('enabled',True),
                     health_status=health.get('status','not yet recorded'),
                     health_checked_at=health.get('checked_at'),voicemail_profiles=len(profiles))))
'''

def run(args):
    p=subprocess.run(args,capture_output=True,text=True,timeout=90)
    if p.returncode:raise RuntimeError('Control/audit command failed; inspect node/CT journal')
    return p.stdout.strip()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('ctids',nargs='*');p.add_argument('--all-local',action='store_true')
    a=p.parse_args()
    if os.geteuid()!=0 or not shutil.which('pct'):p.error('Root on this Proxmox node required')
    if a.ctids and a.all_local:p.error('Choose CTIDs or --all-local')
    if not a.ctids and not a.all_local:p.error('Specify CTIDs or --all-local')
    if any(not x.isdigit() for x in a.ctids):p.error('Numeric CTIDs only')
    listing={}
    for line in run(['pct','list']).splitlines()[1:]:
        row=line.split()
        if len(row)>=2 and row[0].isdigit():listing[row[0]]=row[1]
    summary={'complete':[],'incomplete':[],'deferred':[],'not-freepbx':[]}
    for ctid in a.ctids or list(listing):
        if listing.get(ctid)!='running':summary['deferred'].append(ctid);print('CT '+ctid+': stopped/not local; unverified');continue
        try:
            if re.search(r'(?m)^lock:',run(['pct','config',ctid])):raise RuntimeError('locked')
            result=json.loads(run(['pct','exec',ctid,'--','python3','-c',AUDIT,json.dumps(HASHES)]))
            summary[result['status']].append(ctid);print('CT '+ctid+': '+json.dumps(result),flush=True)
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
            summary['incomplete'].append(ctid);print('CT '+ctid+': audit failed; completion not proven',flush=True)
    node=Path('/root/proxmox-care-scheduler.sh')
    node_ok=node.is_file() and hashlib.sha256(node.read_bytes()).hexdigest()==NODE_HASH
    for unit in ['proxmox-care.service','proxmox-care.timer']:
        path=Path('/etc/systemd/system')/unit
        expected='ExecStart=/bin/bash /root/proxmox-care-scheduler.sh run' if unit.endswith('.service') else 'AccuracySec=2s'
        node_ok=node_ok and path.is_file() and expected in path.read_text()
        node_ok=node_ok and not (path.parent/(unit+'.d')).exists() and not (Path('/run/systemd/system')/(unit+'.d')).exists()
    c=Path('/var/lib/proxmox-care/config.json')
    if not c.is_file():node_ok=False
    else:
        cfg=json.loads(c.read_text());node_ok=node_ok and bool(cfg.get('sender')) and bool(cfg.get('email'))
    active=run(['systemctl','show','proxmox-care.timer','-p','ActiveState','--value'])
    node_ok=node_ok and active=='active'
    print('Node scheduler migration verified: '+str(node_ok))
    print('Migration summary: '+json.dumps(summary))
    return bool(not node_ok or summary['incomplete'] or summary['deferred'])

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        print('Audit failed; migration completeness is unverified.',file=sys.stderr);sys.exit(1)

PYTHON
)" "$0" "$@"
