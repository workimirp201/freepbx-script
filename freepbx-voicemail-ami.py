#!/usr/bin/env python3
"""Dedicated loopback AMI listener and durable native-voicemail capture for v9.

AMI supplies call identity/events, not audio. Never select a latest recording or
guess an inbound DID from caller ID. No API, SMS, SMTP or PBX restart in listener.
"""
from contextlib import contextmanager
import configparser
import copy
import fcntl
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import time

HERE=Path(__file__).resolve().parent
source=HERE/'voicemail.py'
if not source.is_file(): source=HERE/'freepbx-voicemail.py'
spec=importlib.util.spec_from_file_location('care_voicemail_runtime',source)
vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
CALL_TTL=7200
MAX_CALLS=5000
ALLOWED_EVENTS={'Newchannel','NewCallerid','NewExten','VarSet','DialBegin','MessageWaiting','Hangup'}
DID_VARIABLES={'FROM_DID','CDR(did)','DID'}


def number(value,country='1'):
    value=str(value or '').strip()
    if vm.PHONE.fullmatch(value): return value
    if re.fullmatch(r'[0-9]{10}',value) and country=='1': return '+1'+value
    if re.fullmatch(r'[0-9]{11}',value) and value.startswith('1') and country=='1': return '+'+value
    return ''


def parse_frame(raw):
    fields={}
    if len(raw)>65536: raise vm.Problem('AMI frame exceeded limit')
    for line in raw.decode('utf-8',errors='replace').split('\r\n'):
        if ': ' in line:
            key,value=line.split(': ',1)
            if key in fields and fields[key]!=value: raise vm.Problem('Ambiguous AMI frame')
            fields[key]=value
    return fields


class Tracker:
    def __init__(self,calls=None,clock=time.time):
        self.calls=calls or {};self.clock=clock;self.last_prune=0
    def prune(self):
        now=self.clock()
        if now-self.last_prune<30 and len(self.calls)<=MAX_CALLS:return
        self.last_prune=now
        self.calls={k:v for k,v in self.calls.items() if now-v.get('seen',0)<CALL_TTL}
        if len(self.calls)>MAX_CALLS:
            keep=sorted(self.calls,key=lambda k:self.calls[k].get('seen',0))[-MAX_CALLS:]
            self.calls={k:self.calls[k] for k in keep}
    def event(self,e):
        if e.get('Event') not in ALLOWED_EVENTS: return None
        uid=e.get('Uniqueid','')
        if not uid or len(uid)>100: return self.mailbox(e)
        call=self.calls.setdefault(uid,dict(uniqueid=uid,started=self.clock()))
        call['seen']=self.clock()
        for field,key in [('Linkedid','linkedid'),('Channel','channel'),('CallerIDNum','caller_number'),('CallerIDName','caller_name')]:
            if e.get(field):
                if key.startswith('caller_'):call.setdefault(key,str(e[field])[:200])
                else:call[key]=str(e[field])[:200]
        if e.get('Event')=='NewExten':
            ctx=e.get('Context','')
            if ctx.startswith('ext-did') or ctx in ['from-trunk','from-pstn']:
                if ctx.startswith('ext-did'):call['route_context']=ctx[:100]
                candidate=number(e.get('Exten'))
                if candidate and not call.get('did_source'):
                    call.update(inbound_did=candidate,did_source='inbound dialplan extension')
            if e.get('Application','').lower()=='voicemail':
                argument=e.get('AppData','').split(',',1)[0]
                if re.fullmatch(r'[0-9]+@[A-Za-z0-9_-]+',argument):call['voicemail_target']=argument
        if e.get('Event')=='VarSet':
            variable=e.get('Variable','').lstrip('_')
            if variable in DID_VARIABLES:
                candidate=number(e.get('Value'))
                if candidate:
                    old=call.get('inbound_did')
                    if old and old!=candidate:
                        call['ambiguous_did']=True
                    else:call.update(inbound_did=candidate,did_source=variable)
        # Linkedid connects Local/ring-group/transfer legs without persisting
        # arbitrary dialplan variables, application data, passwords or tokens.
        linked=call.get('linkedid')
        if linked:
            root=self.calls.setdefault(linked,dict(uniqueid=linked,seen=self.clock()))
            if root is not call:
                for key in ['inbound_did','did_source','route_context','ambiguous_did']:
                    if key in call:
                        if key=='inbound_did' and root.get(key) and root[key]!=call[key]:root['ambiguous_did']=True
                        else:root[key]=call[key]
        if e.get('Event')=='Hangup':call['ended']=self.clock()
        self.prune()
        return self.mailbox(e)
    @staticmethod
    def mailbox(e):
        if e.get('Event')!='MessageWaiting':return None
        match=re.fullmatch(r'([0-9]+)@([A-Za-z0-9_-]+)',e.get('Mailbox',''))
        return match[2]+'/'+match[1] if match else None
    def match(self,meta):
        uid=meta.get('uniqueid','')
        call=copy.deepcopy(self.calls.get(uid,{}))
        if not call and meta.get('callerchan'):
            matches=[c for c in self.calls.values() if c.get('channel')==meta['callerchan']]
            if len(matches)==1:call=copy.deepcopy(matches[0])
        linked=call.get('linkedid')
        if linked and linked in self.calls:
            root=self.calls[linked]
            for key in ['inbound_did','did_source','route_context','ambiguous_did']:
                if key in root:
                    if key=='inbound_did' and call.get(key) and call[key]!=root[key]:call['ambiguous_did']=True
                    else:call[key]=root[key]
        if call.get('ambiguous_did'):call['inbound_did']=''
        return call


@contextmanager
def job_lock(ident,blocking=False):
    if not re.fullmatch(r'[a-f0-9]{64}',ident):raise vm.Problem('Invalid job identity')
    directory=vm.STATE/'locks';directory.mkdir(mode=0o700,exist_ok=True)
    fd=os.open(directory/(ident+'.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        fcntl.flock(f,fcntl.LOCK_EX|(0 if blocking else fcntl.LOCK_NB))
        try:yield
        finally:fcntl.flock(f,fcntl.LOCK_UN)


def metadata_snapshot(path):
    if not path.resolve().is_relative_to(vm.SPOOL.resolve()):raise vm.Problem('Metadata outside voicemail spool')
    if any(p.is_symlink() for p in [path,*list(path.parents)[:4]]):raise vm.Problem('Symlink metadata refused')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
        st=os.fstat(f.fileno());raw=f.read(65537)
        if not stat.S_ISREG(st.st_mode) or len(raw)>65536:raise vm.Problem('Invalid voicemail metadata')
    parser=configparser.RawConfigParser(strict=False);parser.read_string(raw.decode(errors='replace'))
    meta=dict(parser['message'])
    if not str(meta.get('origtime','')).isdigit():raise vm.Problem('Metadata timestamp missing')
    return meta,raw,st


def signature(st):return (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)


def atomic_audio(path,data):
    import tempfile
    fd,temp=tempfile.mkstemp(prefix='.audio-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            os.fchmod(f.fileno(),0o600);f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def capture(key,profile,path,tracker,c):
    meta,raw,mstat=metadata_snapshot(path)
    if int(meta['origtime'])<max(profile['since'],time.time()-30*86400):return False
    ident=vm.identity(key,meta)
    if not meta.get('msg_id'):
        if not meta.get('uniqueid'):raise vm.Problem('No native message ID/call ID; recording requires manual review')
        # Continue an existing r8 job, otherwise use the call ID rather than
        # colliding on caller/time/duration when simultaneous calls are identical.
        if not (vm.STATE/(ident+'.json')).exists():ident=hashlib.sha256((key+'\0call:'+meta['uniqueid']).encode()).hexdigest()
    target=vm.STATE/(ident+'.json')
    with job_lock(ident):
        job=vm.load(target,{})
        if job.get('done') or job.get('snapshot'):return False
        wav=path.with_suffix('.wav');before=wav.stat()
        data=vm.audio_bytes(wav)
        # Match both names and open-file identity over the entire capture.
        after,raw_after,mstat_after=metadata_snapshot(path)
        if signature(mstat)!=signature(mstat_after) or raw!=raw_after or signature(before)!=signature(wav.stat()):
            raise vm.Problem('Voicemail changed during capture; retry without sending')
        usage=sum(p.stat().st_size for p in vm.STATE.glob('*.wav'))
        if usage+len(data)>int(c.get('queue_max_mb',256))*1024*1024:
            raise vm.Problem('Voicemail durable queue quota reached; original message untouched')
        atomic_audio(vm.STATE/(ident+'.wav'),data)
        call=tracker.match(meta)
        detail={k:meta.get(k,'') for k in ['uniqueid','msg_id','callerid','callerchan','origtime','origdate','duration','origmailbox','context','exten']}
        detail.update(call)
        did=detail.get('inbound_did','')
        routes=c.get('inbound_routes',{})
        detail['route_name']=routes.get(did,{}).get('description','Unknown/not observed')
        job.update(snapshot=True,mailbox=key,metadata=detail,created=job.get('created',time.time()),
                   audio_sha256=hashlib.sha256(data).hexdigest(),capture_source='AMI-correlated native voicemail')
        job.setdefault('deliveries',{})
        vm.atomic(target,job)
        return True


def ingest(key,c,tracker):
    profile=c['mailboxes'].get(key)
    if not profile or not profile.get('enabled'):return 0
    context,ext=key.split('/',1);root=vm.SPOOL/context/ext
    captured=0;failed=False
    # Reconciliation handles missed events/reconnects and moves during capture.
    for folder in ['INBOX','Old','Urgent','Work','Family','Friends','Cust1','Cust2','Cust3','Cust4','Cust5']:
        paths=list(itertools.islice((root/folder).glob('msg*.txt'),10001))
        if len(paths)>10000:
            failed=True
            vm.atomic(vm.STATE/'capture-health.json',dict(status='degraded',mailbox=key,
                reason='Mailbox folder exceeds 10000 messages; review native retention',time=time.time()))
            continue
        for path in sorted(paths):
            if not re.fullmatch(r'msg[0-9]+\.txt',path.name):continue
            try:
                if capture(key,profile,path,tracker,c):captured+=1
            except BlockingIOError:continue
            except (OSError,ValueError,configparser.Error,vm.Problem):
                failed=True
                # Aggregate safe failure status; worker sends operational email.
                vm.atomic(vm.STATE/'capture-health.json',dict(status='degraded',mailbox=key,
                    reason='Recording unavailable/changing, invalid metadata, or queue quota; review capture',time=time.time()))
            if captured>=4:break
        if captured>=4:break
    if not failed:
        previous=vm.load(vm.STATE/'capture-health.json',{})
        if previous.get('mailbox') in [None,key]:
            vm.atomic(vm.STATE/'capture-health.json',dict(status='healthy',mailbox=key,time=time.time()))
    return captured


class Session:
    def __init__(self,sock):self.sock=sock;self.buffer=b''
    def send(self,fields):
        if any('\r' in str(v) or '\n' in str(v) for v in fields.values()):raise vm.Problem('Invalid AMI field')
        self.sock.sendall(('\r\n'.join(k+': '+str(v) for k,v in fields.items())+'\r\n\r\n').encode())
    def frame(self,timeout=1):
        if b'\r\n\r\n' not in self.buffer:
            ready,_,_=select.select([self.sock],[],[],timeout)
            if not ready:return None
            data=self.sock.recv(32768)
            if not data:raise vm.Problem('AMI disconnected')
            self.buffer+=data
            if len(self.buffer)>1024*1024:raise vm.Problem('AMI stream exceeded buffer limit')
        if b'\r\n\r\n' not in self.buffer:return None
        raw,self.buffer=self.buffer.split(b'\r\n\r\n',1)
        return parse_frame(raw)


def listen():
    vm.prepare_directories(worker=True)
    tracker=Tracker(vm.load(vm.STATE/'calls.json',{}))
    fd=os.open(vm.STATE/'listener.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        while True:
            try:
                c=vm.validate(vm.config());a=c.get('listener',{})
                if a.get('host','127.0.0.1') not in ['127.0.0.1','::1']:raise vm.Problem('AMI must be loopback-only')
                if not a.get('username') or not a.get('secret'):raise vm.Problem('Dedicated AMI credentials missing; run listener setup')
                with socket.create_connection((a.get('host','127.0.0.1'),int(a.get('port',5038))),10) as sock:
                    session=Session(sock)
                    session.send(dict(Action='Login',ActionID='care-listener-login',Username=a['username'],Secret=a['secret'],Events='on'))
                    deadline=time.monotonic()+15;authenticated=False
                    while time.monotonic()<deadline:
                        e=session.frame()
                        if e and e.get('ActionID')=='care-listener-login':
                            authenticated=e.get('Response')=='Success';break
                    if not authenticated:raise vm.Problem('Dedicated AMI authentication failed')
                    last_save=0;last_reconcile=0;last_config=0;dirty=set(c['mailboxes'])
                    while True:
                        e=session.frame()
                        if e:
                            key=tracker.event(e)
                            if key:dirty.add(key)
                        now=time.time()
                        if now-last_config>10:c=vm.validate(vm.config());last_config=now
                        if now-last_reconcile>60:dirty.update(c['mailboxes']);last_reconcile=now
                        if dirty:
                            key=dirty.pop();ingest(key,c,tracker)
                        if now-last_save>15:
                            tracker.prune();vm.atomic(vm.STATE/'calls.json',tracker.calls)
                            vm.atomic(vm.STATE/'listener-health.json',dict(status='healthy',time=now,tracked_calls=len(tracker.calls)))
                            last_save=now
            except (OSError,ValueError,vm.Problem):
                vm.atomic(vm.STATE/'listener-health.json',dict(status='failed',time=time.time(),reason='AMI connection/auth/configuration unavailable; retrying'))
                time.sleep(10)


if __name__=='__main__':listen()
