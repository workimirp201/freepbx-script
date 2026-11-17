#!/usr/bin/env python3
"""Optional FreePBX Care voicemail transcription and recipient notifications.

No dialplan changes, hooks, PBX restarts or caller-ID-directed SMS. Python stdlib.
"""
import argparse
import base64
import configparser
import datetime
import email.message
import email.utils
import fcntl
import getpass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import wave

ETC = Path('/etc/freepbx-care')
STATE = Path('/var/lib/freepbx-care/voicemail')
SPOOL = Path('/var/spool/asterisk/voicemail')
AST = Path('/etc/asterisk')
SELF = Path('/usr/local/lib/freepbx-care/voicemail.py')
VERSION = '2026.11.17-local-care-r9'
MAX_AUDIO = 24 * 1024 * 1024
PHONE = re.compile(r'\+[1-9][0-9]{7,14}\Z')
EMAIL = re.compile(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\Z')
COMPONENT = re.compile(r'[A-Za-z0-9_-]{1,80}\Z')


class Problem(RuntimeError):
    """Safe-to-log error; never contains API response bodies or credentials."""
    def __init__(self,message,status=None):
        super().__init__(message);self.status=status


def atomic(path, value):
    path = Path(path)
    if path.is_symlink(): raise Problem('Refusing symlink output')
    fd, temp = tempfile.mkstemp(prefix='.vm-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(value, f, ensure_ascii=False, indent=2)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def load(path, default):
    path = Path(path)
    if not path.exists(): return default
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o077:
        raise Problem('Voicemail configuration/state must be root-owned mode 600')
    with path.open(encoding='utf-8') as f: return json.load(f)


def config():
    return load(ETC/'voicemail.json', dict(model='gpt-transcribe', mailboxes={},event_mode=True,queue_max_mb=256))


def ami_module():
    import importlib.util
    path=SELF.parent/'voicemail_ami.py'
    if not path.is_file():path=Path(__file__).parent/'freepbx-voicemail-ami.py'
    spec=importlib.util.spec_from_file_location('care_vm_ami',path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    result.vm=sys.modules.get(__name__,result.vm)
    return result


def validate(c):
    if type(c.get('event_mode',True)) is not bool:raise Problem('Invalid voicemail event mode')
    if type(c.get('queue_max_mb',256)) is not int or not 16<=c.get('queue_max_mb',256)<=2048:raise Problem('Queue capacity must be 16..2048 MiB')
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', c.get('model', '')):
        raise Problem('Invalid transcription model')
    if not isinstance(c.get('mailboxes'), dict) or len(c['mailboxes']) > 100:
        raise Problem('At most 100 mailbox profiles are supported')
    for key, p in c['mailboxes'].items():
        if not isinstance(p,dict) or type(p.get('enabled')) is not bool:raise Problem('Invalid mailbox profile enable flag')
        if key != p['context']+'/'+p['extension'] or not COMPONENT.fullmatch(p['context']) or not re.fullmatch(r'[0-9]{1,20}', p['extension']):
            raise Problem('Invalid mailbox identity')
        for field, pattern in [('sms', PHONE), ('emails', EMAIL)]:
            if not isinstance(p.get(field), list) or len(p[field]) > 20 or not all(pattern.fullmatch(x) for x in p[field]):
                raise Problem('Invalid recipient list (maximum 20 per channel)')
        if p.get('enabled') and not (p['sms'] or p['emails']):
            raise Problem('An enabled profile needs an SMS or email recipient')
        if p['emails'] and not EMAIL.fullmatch(c.get('sender_email', '')):
            raise Problem('A valid sender email is required')
        if len(p.get('label', '')) > 100 or re.search(r'[\r\n]', p.get('label','')):
            raise Problem('Invalid site label')
        if p.get('sender_mode','custom') not in ['custom','called_did']:raise Problem('Invalid SMS sender mode')
        if p.get('sms_from') and not PHONE.fullmatch(p['sms_from']):raise Problem('Invalid custom sender')
        if not isinstance(p.get('allowed_dids',[]),list) or len(p.get('allowed_dids',[]))>20 or not all(PHONE.fullmatch(x) for x in p.get('allowed_dids',[])):raise Problem('Invalid authorized inbound DID')
    if c.get('ops_email') and not EMAIL.fullmatch(c['ops_email']):raise Problem('Invalid operations email')
    if c.get('reply_to') and not EMAIL.fullmatch(c['reply_to']):raise Problem('Invalid Reply-To')
    return c


def required_credentials(c):
    active = [p for p in c['mailboxes'].values() if p.get('enabled')]
    if active and not c.get('openai_key'): raise Problem('OpenAI API key is missing')
    if any(p['sms'] for p in active):
        if not all(c.get(k) for k in ['bandwidth_account', 'bandwidth_application', 'bandwidth_client', 'bandwidth_secret', 'bandwidth_from']):
            raise Problem('Bandwidth OAuth/SMS settings are missing')
        if not re.fullmatch(r'[0-9]{7}', c['bandwidth_account']): raise Problem('Bandwidth account must be seven digits')
        if not PHONE.fullmatch(c['bandwidth_from']): raise Problem('Bandwidth sender must be E.164')
        if not re.fullmatch(r'[A-Za-z0-9-]{1,100}', c['bandwidth_application']): raise Problem('Invalid application ID')


def mailboxes():
    """Read mailbox names only, never display PINs. Honor native includes/contexts."""
    found, visited = {}, set()
    def parse(path, context='default'):
        path = path.resolve()
        if not path.is_relative_to(AST.resolve()) or path in visited or len(visited) >= 128: return context
        visited.add(path)
        if not path.is_file(): return context
        for raw in path.read_text(errors='replace').splitlines():
            line = raw.split(';', 1)[0].strip()
            inc = re.fullmatch(r'#(?:try)?include\s+["<]?([^">]+)[">]?', line)
            if inc:
                candidate = Path(inc[1].strip())
                candidate = candidate if candidate.is_absolute() else path.parent/candidate
                if '*' in str(candidate):
                    for item in sorted(candidate.parent.glob(candidate.name)): context = parse(item, context)
                else: context = parse(candidate, context)
                continue
            section = re.fullmatch(r'\[([^\]]+)\].*', line)
            if section:
                context = section[1]; continue
            entry = re.match(r'([0-9]{1,20})\s*(?:=>|=)\s*(.*)', line)
            if entry and COMPONENT.fullmatch(context) and context not in ['general','zonemessages']:
                fields = entry[2].split(',')
                found[context+'/'+entry[1]] = dict(context=context, extension=entry[1],
                    name=fields[1].strip()[:80] if len(fields)>1 else '',configured=True,
                    retains_audio=not bool(re.search(r'(?:^|\|)delete\s*=\s*(?:yes|true|1)(?:\||$)',fields[4] if len(fields)>4 else '',re.I)))
        return context
    parse(AST/'voicemail.conf')
    # Existing custom voicemail contexts are also discoverable from the spool.
    for inbox in SPOOL.glob('*/*/INBOX'):
        context, ext = inbox.parent.parent.name, inbox.parent.name
        if COMPONENT.fullmatch(context) and re.fullmatch(r'[0-9]{1,20}', ext):
            found.setdefault(context+'/'+ext, dict(context=context, extension=ext, name='UNVERIFIED historical/custom spool mailbox',configured=False))
    return found


def metadata(path):
    if path.is_symlink() or path.stat().st_size > 65536: raise Problem('Invalid message metadata')
    parser = configparser.RawConfigParser(strict=False)
    parser.read_string(path.read_text(errors='replace'))
    if not parser.has_section('message'): raise Problem('Missing voicemail metadata section')
    v = dict(parser['message'])
    if not str(v.get('origtime','')).isdigit(): raise Problem('Missing voicemail timestamp')
    return v


def identity(key, meta):
    unique = meta.get('msg_id') or '|'.join(meta.get(k,'') for k in ['origtime','callerid','duration','origmailbox'])
    return hashlib.sha256((key+'\0'+unique).encode()).hexdigest()


def audio_bytes(path):
    if not path.resolve().is_relative_to(SPOOL.resolve()): raise Problem('Audio outside voicemail spool')
    # Reject aliases at any mailbox path component.
    if any(p.is_symlink() for p in [path, *list(path.parents)[:4]]): raise Problem('Symlink voicemail path refused')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or not 44 < before.st_size <= MAX_AUDIO:
            raise Problem('WAV missing/empty or over 24 MiB')
        if time.time()-before.st_mtime < 10: raise Problem('Recording is still settling; retry later')
        data = f.read(MAX_AUDIO+1)
        after = os.fstat(f.fileno())
    if (before.st_mtime_ns,before.st_size) != (after.st_mtime_ns,after.st_size):
        raise Problem('Recording changed while reading')
    try:
        with wave.open(io.BytesIO(data)) as wav:
            if wav.getnframes() <= 0: raise Problem('Empty WAV')
    except (wave.Error, EOFError): raise Problem('Requires a standard PCM .wav recording') from None
    return data


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def request(url, payload, headers, timeout=30):
    req = urllib.request.Request(url, data=payload, headers=headers, method='POST')
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=timeout) as r:
            data = r.read(1024*1024+1)
            if len(data)>1024*1024: raise Problem('API response exceeded size limit')
            value=json.loads(data)
            if not isinstance(value,dict):raise Problem('API response must be an object; acceptance may be unknown')
            return value
    except urllib.error.HTTPError as e:
        # Do not expose server response bodies, URLs, secrets or transcript text.
        request_id=e.headers.get('X-Request-Id','') if e.headers else ''
        request_id=re.sub(r'[^A-Za-z0-9_.-]','',request_id)[:80]
        raise Problem(f'API HTTP {e.code}; request ID {request_id or "not supplied"}; inspect authorization/application/rate limits',status=e.code) from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise Problem('API connection/timeout/invalid response; acceptance may be unknown') from None


def transcribe(c, audio):
    boundary = 'care-'+uuid.uuid4().hex
    parts = []
    for k,v in [('model',c['model']),('response_format','json')]:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    parts += [f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="voicemail.wav"\r\nContent-Type: audio/wav\r\n\r\n'.encode(),
              audio, f'\r\n--{boundary}--\r\n'.encode()]
    r = request('https://api.openai.com/v1/audio/transcriptions', b''.join(parts),
                {'Authorization':'Bearer '+c['openai_key'], 'Content-Type':'multipart/form-data; boundary='+boundary}, 90)
    if not isinstance(r.get('text'),str) or not r['text'].strip(): raise Problem('Transcription returned no text')
    return r['text'].strip()[:30000]


def bandwidth_token(c,force=False):
    cache = {} if force else load(STATE/'oauth.json', {})
    fingerprint = hashlib.sha256((c['bandwidth_client']+'\0'+c['bandwidth_secret']).encode()).hexdigest()
    if cache.get('fingerprint') == fingerprint and cache.get('until',0)>time.time()+60:
        return cache['token']
    basic = base64.b64encode((c['bandwidth_client']+':'+c['bandwidth_secret']).encode()).decode()
    r = request('https://api.bandwidth.com/api/v1/oauth2/token', b'grant_type=client_credentials',
                {'Authorization':'Basic '+basic, 'Content-Type':'application/x-www-form-urlencoded'})
    if not isinstance(r.get('access_token'),str): raise Problem('OAuth response has no access token')
    atomic(STATE/'oauth.json', dict(token=r['access_token'], until=time.time()+int(r.get('expires_in',3600)), fingerprint=fingerprint))
    return r['access_token']


def sms(c, recipient, text, token, tag):
    # One recipient/request prevents group messaging and recipient disclosure.
    body = dict(applicationId=c['bandwidth_application'], to=[recipient],
                **{'from':c['bandwidth_from']}, text=text, tag=tag[:100])
    def send(access):
        return request('https://messaging.bandwidth.com/api/v2/users/'+c['bandwidth_account']+'/messages',
                json.dumps(body).encode(), {'Authorization':'Bearer '+access, 'Content-Type':'application/json; charset=utf-8'})
    try:r=send(token)
    except Problem as e:
        if e.status!=401:raise
        r=send(bandwidth_token(c,force=True))
    mid = r.get('id') or r.get('messageId')
    if not isinstance(mid,str) or not mid: raise Problem('SMS response has no message ID; acceptance unknown')
    return mid


def mail(c, recipient, subject, body, audio=None):
    msg = email.message.EmailMessage()
    msg['To'], msg['From'], msg['Subject'] = recipient, c['sender_email'], subject
    msg['Date']=email.utils.formatdate(localtime=True)
    msg['Message-ID']=email.utils.make_msgid(domain=c['sender_email'].rsplit('@',1)[-1])
    if c.get('reply_to'):msg['Reply-To']=c['reply_to']
    msg.set_content(body)
    if audio is not None: msg.add_attachment(audio, maintype='audio', subtype='wav', filename='voicemail.wav')
    try:
        p = subprocess.run(['/usr/sbin/sendmail','-oi','-f',c['sender_email'],'--',recipient],
                           input=msg.as_bytes(), capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired): raise Problem('Email queue acceptance unknown') from None
    if p.returncode: raise Problem('Email queue rejected message')
    return 'accepted-by-local-mail-queue'


def delivery(jpath, job, key, send):
    state = job.setdefault('deliveries',{})
    if key in state: return
    # Persist BEFORE sending: do not duplicate SMS if acceptance is ambiguous.
    state[key] = dict(result='review', reason='Delivery interrupted or acceptance unknown')
    atomic(jpath, job)
    try:
        result = send()
        state[key] = dict(result='accepted', reference=result)
        print('Voicemail delivery accepted:', key.split(':',1)[0], flush=True)
    except Problem as e:
        state[key] = dict(result='rejected' if e.status and 400<=e.status<500 else 'review', reason=str(e))
        print('Voicemail delivery requires review:', key.split(':',1)[0], str(e), flush=True)
    atomic(jpath, job)


def sms_text(body):
    suffix='\n[SMS shortened; listen to voicemail for full details.]'
    if len(body.encode('utf-16-le'))//2 <= 600: return body
    clipped=body.encode('utf-16-le')[:(600-len(suffix))*2].decode('utf-16-le',errors='ignore')
    return clipped+suffix


def sender_for(c,profile,metadata):
    if profile.get('sender_mode','custom')=='custom':
        value=profile.get('sms_from') or c.get('bandwidth_from','')
    else:
        value=metadata.get('inbound_did','')
        if metadata.get('ambiguous_did') or value not in profile.get('allowed_dids',[]):
            raise Problem('Inbound DID is unknown/ambiguous or not an approved Bandwidth sender; email details retained')
    if not PHONE.fullmatch(value):raise Problem('SMS sender unavailable')
    return value


def ops(c,key,reason,resolved=False):
    recipient=c.get('ops_email')
    if not recipient:return
    path=STATE/'operations.json';state=load(path,{})
    previous=state.get(key,{})
    status='resolved' if resolved else 'open'
    if resolved and previous.get('status')!='open':return
    if previous.get('status')==status and previous.get('reason')==reason and time.time()-previous.get('sent',0)<3600:return
    subject=f'[Care][{"RESOLVED" if resolved else "ACTION REQUIRED"}][{socket.gethostname()}] Voicemail {key}'
    try:
        mail(c,recipient,subject,reason+'\nNo credentials or transcript are included. Review voicemail status and provider delivery records.')
        state[key]=dict(status=status,reason=reason,sent=time.time());atomic(path,state)
    except Problem:
        print('Operations email not accepted; inspect local SMTP queue/service.',flush=True)


def queued_audio(ident,job):
    path=STATE/(ident+'.wav')
    if path.is_symlink():raise Problem('Unsafe queued audio')
    with path.open('rb') as f:data=f.read(MAX_AUDIO+1)
    if len(data)>MAX_AUDIO or hashlib.sha256(data).hexdigest()!=job.get('audio_sha256'):
        raise Problem('Queued audio integrity check failed')
    return data


def process(c, key, profile, path, queued=None):
    meta = queued['metadata'] if queued else metadata(path)
    if int(meta['origtime']) < max(profile['since'],time.time()-30*86400): return False
    ident = path.stem if queued else identity(key, meta)
    jpath = STATE/(ident+'.json')
    job = queued if queued is not None else load(jpath, {})
    if job.get('done') or job.get('blocked'): return False
    if job.get('next_try',0) > time.time(): return False
    audio = None
    try:
        if 'transcript' not in job:
            audio = queued_audio(ident,job) if queued else audio_bytes(path.with_suffix('.wav'))
            job.update(mailbox=key, created=job.get('created',time.time()))
            job.setdefault('deliveries',{})
            job['transcript'] = transcribe(c,audio)
            atomic(jpath,job)
        transcript = job['transcript']
        caller = str(meta.get('caller_name') or meta.get('callerid','Unknown caller')).replace('\r',' ').replace('\n',' ')[:200]
        recorded=datetime.datetime.fromtimestamp(int(meta['origtime'])).astimezone().strftime('%Y-%m-%d %H:%M %Z')
        details='\n'.join(f'{label}: {meta.get(field) or "Unknown / not observed"}' for field,label in [
            ('caller_number','Caller number'),('inbound_did','Called inbound DID'),('route_name','Inbound route'),
            ('route_context','Inbound route context'),('uniqueid','Call Uniqueid'),('linkedid','Linkedid'),
            ('msg_id','Voicemail message ID'),('duration','Duration (seconds)'),('channel','Channel')])
        body = f"{profile['label']} - voicemail for {profile['extension']}@{profile['context']}\nPBX: {socket.gethostname()}\nCaller: {caller}\nRecorded: {recorded}\n{details}\n\nTranscript (automatic; verify important details):\n{transcript}"
        sms_body=f"{profile['label']} VM {profile['extension']}: From: {meta.get('caller_number') or caller}. Called DID: {meta.get('inbound_did') or 'unknown'}. {recorded}\nTranscript: {transcript}"
        targets=['email:'+r for r in profile['emails']]+['sms:'+r for r in profile['sms']]
        pending=[t for t in targets if t not in job.get('deliveries',{})][:4]
        token=None
        for target in pending:
            kind,recipient=target.split(':',1)
            if kind=='email':
                if profile.get('attach_audio') and audio is None: audio=queued_audio(ident,job) if queued else audio_bytes(path.with_suffix('.wav'))
                subject=f"[Voicemail][{profile['label']}][{profile['extension']}@{profile['context']}] {recorded}"
                delivery(jpath,job,target,lambda r=recipient: mail(c,r,subject,body,audio if profile.get('attach_audio') else None))
            else:
                if token is None: token=bandwidth_token(c)
                sender=sender_for(c,profile,meta)
                delivery(jpath,job,target,lambda r=recipient: sms(dict(c,bandwidth_from=sender),r,sms_text(sms_body),token,'care-vm-'+ident[:32]))
        job['done'] = all(t in job.get('deliveries',{}) for t in targets)
        atomic(jpath,job)
        reviews=[x for x in job['deliveries'].values() if x.get('result') in ['review','rejected']]
        if reviews:ops(c,key+' / '+ident,'SMS/email delivery failed or acceptance is uncertain; review job '+ident)
        elif job['done']:
            ops(c,key+' / '+ident,'All queued recipients accepted',resolved=True)
            if queued:(STATE/(ident+'.wav')).unlink(missing_ok=True)
        print('Voicemail processed:', key, ident[:12], flush=True)
    except (Problem, FileNotFoundError) as e:
        # Bounded pre-delivery retry. Delivery ambiguity is retained, never retried automatically.
        job.update(mailbox=key, attempts=job.get('attempts',0)+1, error=str(e) if isinstance(e,Problem) else 'Recording unavailable')
        job['blocked'] = job['attempts'] >= 3
        job['next_try'] = time.time()+300
        atomic(jpath,job)
        print('Voicemail processing deferred/requires review:', key, ident[:12], job['error'], flush=True)
        ops(c,key+' / '+ident,job['error']+'; job '+ident)
    return True


def worker():
    c = validate(config()); required_credentials(c)
    if c.get('event_mode',True):return durable_worker(c)
    # Old jobs cannot be replayed: recordings older than the same retention are excluded.
    for path in STATE.glob('*.json'):
        if re.fullmatch(r'[a-f0-9]{64}\.json',path.name) and time.time()-path.stat().st_mtime > 30*86400:
            path.unlink()
    # One new/pending recording per invocation: bounded CPU, memory and API load.
    for key,p in c['mailboxes'].items():
        if not p.get('enabled'): continue
        inbox = SPOOL/p['context']/p['extension']/'INBOX'
        if inbox.is_symlink() or not inbox.resolve().is_relative_to(SPOOL.resolve()): raise Problem('Unsafe inbox')
        paths = sorted(inbox.glob('msg*.txt'))
        if len(paths)>10000: raise Problem('Inbox too large; review retention')
        for path in paths:
            if not re.fullmatch(r'msg[0-9]+\.txt',path.name): continue
            try:
                wav=path.with_suffix('.wav')
                if wav.exists() and time.time()-wav.stat().st_mtime < 10: continue
                if process(c,key,p,path): return
            except (Problem, ValueError, configparser.Error):
                print('Voicemail metadata unavailable/invalid:',key,path.name,flush=True)


def pressure_reason():
    for kind in ['cpu','memory','io']:
        path=Path('/proc/pressure')/kind
        if path.is_file():
            for line in path.read_text().splitlines():
                fields=dict(x.split('=',1) for x in line.split()[1:])
                if float(fields.get('avg10',0))>25:return 'Host/container '+kind+' pressure; queued audio retained'
    return ''


def durable_worker(c):
    reason=pressure_reason()
    if reason:
        ops(c,'pressure',reason);return
    ops(c,'pressure','Pressure cleared',resolved=True)
    listener=load(STATE/'listener-health.json',{})
    if listener.get('status')!='healthy' or time.time()-listener.get('time',0)>60:
        ops(c,'AMI listener','Listener is disconnected/stale; native queue recovery will reconcile after reconnect')
    else:ops(c,'AMI listener','AMI listener healthy',resolved=True)
    capture=load(STATE/'capture-health.json',{})
    if capture.get('status')=='degraded':ops(c,'recording capture',capture.get('reason','Capture failed'))
    elif capture.get('status')=='healthy':ops(c,'recording capture','Recording capture healthy',resolved=True)
    api=ami_module();jobs=[]
    for path in STATE.glob('*.json'):
        if not re.fullmatch(r'[a-f0-9]{64}\.json',path.name):continue
        job=load(path,{})
        if time.time()-job.get('created',path.stat().st_mtime)>30*86400:
            path.unlink();(STATE/(path.stem+'.wav')).unlink(missing_ok=True);continue
        if job.get('done') or job.get('blocked') or not job.get('snapshot'):continue
        if job.get('next_try',0)>time.time():continue
        jobs.append((job.get('last_processed',0),job.get('created',0),path,job))
    # Least recently processed job first provides fairness across all mailboxes.
    for _,__,path,job in sorted(jobs,key=lambda x:(x[0],x[1])):
        profile=c['mailboxes'].get(job['mailbox'])
        if not profile or not profile.get('enabled'):continue
        try:
            with api.job_lock(path.stem):
                job=load(path,{})
                job['last_processed']=time.time();atomic(path,job)
                process(c,job['mailbox'],profile,path,queued=job)
                return
        except BlockingIOError:continue


def yesno(label,default=False):
    while True:
        value=ask(label,'y' if default else 'n').lower()
        if value in ['y','yes']:return True
        if value in ['n','no']:return False
        print('Enter y or n.')


def email_prompt(label,default=''):
    while True:
        value=ask(label,default)
        if EMAIL.fullmatch(value):return value
        print('Enter a valid email address; this field is required.')


def setup_listener(c):
    import secrets
    import grp
    username='care-voicemail'
    listener=c.setdefault('listener',{})
    listener.update(host='127.0.0.1',port=int(listener.get('port',5038)),username=username)
    listener.setdefault('secret',secrets.token_urlsafe(40))
    manager=AST/'manager.conf';custom=AST/'manager_custom.conf'
    if not manager.is_file() or not re.search(r'(?m)^\s*#(?:try)?include\s+["<]?manager_custom\.conf',manager.read_text()):
        raise Problem('manager.conf does not include manager_custom.conf; review native AMI includes before setup')
    if custom.is_symlink():raise Problem('Refusing symlink manager custom config')
    old=custom.read_text() if custom.exists() else ''
    fragment=AST/'manager_care_voicemail.conf'
    if fragment.is_symlink():raise Problem('Refusing symlink listener account config')
    if fragment.exists():
        existing=fragment.read_text()
        if '; Managed by FreePBX Care v9' not in existing:raise Problem('Unrecognized AMI listener fragment; preserve for review')
    backup=STATE/('ami-setup-'+str(time.time_ns()));backup.mkdir(mode=0o700)
    for source in [custom,fragment]:
        if source.exists():(backup/source.name).write_bytes(source.read_bytes())
    gid=grp.getgrnam('asterisk').gr_gid
    content=('; Managed by FreePBX Care v9\n['+username+']\nsecret = '+listener['secret']+
             '\ndeny = 0.0.0.0/0.0.0.0\npermit = 127.0.0.1/255.255.255.255\nread = call,dialplan,user\nwrite = none\n')
    for event in ['Newchannel','NewCallerid','NewExten','VarSet','DialBegin','MessageWaiting','Hangup']:
        content+='eventfilter = Event: '+event+'\n'
    fragment.write_text(content);os.chmod(fragment,0o640);os.chown(fragment,0,gid)
    include='#include manager_care_voicemail.conf'
    if include not in old:
        original=custom.stat() if custom.exists() else None
        custom.write_text(old.rstrip()+'\n'+include+'\n')
        os.chmod(custom,stat.S_IMODE(original.st_mode) if original else 0o640)
        os.chown(custom,original.st_uid if original else 0,original.st_gid if original else gid)
    atomic(ETC/'voicemail.json',c)
    result=subprocess.run(['asterisk','-rx','manager reload'],capture_output=True,text=True,timeout=20)
    if result.returncode:raise Problem('Manager reload failed; inspect AMI setup backup and service state')
    print('Dedicated read-only loopback AMI account configured; Asterisk was not restarted.')


def refresh_routes(c):
    code=r'''$bootstrap_settings['skip_astman']=true;ob_start();try{require '/etc/freepbx.conf';
    $r=\FreePBX::Database()->query('SELECT extension,cidnum,description FROM incoming')->fetchAll(\PDO::FETCH_ASSOC);
    ob_end_clean();echo json_encode($r);}catch(\Throwable $e){while(ob_get_level())ob_end_clean();exit(1);}'''
    result=subprocess.run(['php','-r',code],capture_output=True,text=True,timeout=20)
    if result.returncode:raise Problem('Cannot read inbound route inventory; existing cache retained')
    rows=json.loads(result.stdout);routes={}
    api=ami_module()
    for r in rows:
        did=api.number(r.get('extension'))
        if not did:continue
        record=dict(description=str(r.get('description',''))[:150],caller_match=str(r.get('cidnum',''))[:80])
        if did in routes and routes[did]!=record:
            routes[did]={'description':'Multiple CID-specific routes; see observed dialplan context','caller_match':'multiple'}
        else:routes[did]=record
    c['inbound_routes']=routes;atomic(ETC/'voicemail.json',c)
    print('Inbound DID/route labels cached:',len(routes))


def ask(label, default=''):
    value = input(label+(f' [{default}]' if default else '')+': ').strip()
    return value or default


def recipients(label, old, pattern):
    value = ask(label+' (comma-separated; no = none; Enter keeps)', ', '.join(old) if old else 'no')
    if value.lower() in ['no','none','n']: return []
    result = list(dict.fromkeys(x.strip() for x in value.split(',') if x.strip()))
    if len(result)>20 or not all(pattern.fullmatch(x) for x in result): raise Problem('Invalid recipients; use E.164 SMS numbers or email addresses')
    return result


def secret(c, field, label, force=False):
    if force or not c.get(field):
        value = getpass.getpass(label+(' (Enter keeps existing)' if c.get(field) else '')+': ').strip()
        if value: c[field]=value
        if not c.get(field) or re.search(r'[\r\n]',c[field]): raise Problem('Credential missing/invalid')


def credentials(c, force=False):
    core=load(ETC/'config.json',{})
    c['ops_email']=email_prompt('Operations/error notification email',c.get('ops_email',core.get('email','')))
    c['sender_email']=email_prompt('Email sender authorized by this PBX relay',c.get('sender_email',core.get('sender','')))
    secret(c,'openai_key','OpenAI API key',force)
    c['model']=ask('Transcription model',c.get('model','gpt-transcribe'))
    wants_sms=any(p.get('enabled') and p['sms'] for p in c['mailboxes'].values())
    if force:
        wants_sms=ask('Configure/update Bandwidth OAuth and sender settings? y/n','y' if c.get('bandwidth_client') else 'n').lower()=='y'
    if wants_sms:
        for field,label in [('bandwidth_account','Bandwidth seven-digit account ID'),
                            ('bandwidth_application','Messaging application ID'),('bandwidth_from','Bandwidth SMS sender (+countrycode number)')]:
            if force or not c.get(field): c[field]=ask(label,c.get(field,''))
        secret(c,'bandwidth_client','Bandwidth OAuth Client ID',force)
        secret(c,'bandwidth_secret','Bandwidth OAuth Client Secret',force)
    validate(c); required_credentials(c)


def install(enable=True):
    if not (ETC/'voicemail.json').is_file(): raise Problem('Configure a mailbox first')
    c=validate(config()); required_credentials(c)
    if enable and not any(p.get('enabled') for p in c['mailboxes'].values()): raise Problem('No enabled mailbox profile')
    if enable and not c.get('ops_email'):raise Problem('Configure an operations email before activation')
    if enable and not c.get('listener',{}).get('secret'):raise Problem('Use option 8 to set up the dedicated AMI listener first')
    if not os.access('/usr/sbin/sendmail',os.X_OK):
        raise Problem('Configure PBX SMTP (Care menu 3) before enabling email delivery')
    SELF.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if Path(__file__).resolve()!=SELF.resolve():
        if SELF.is_symlink(): raise Problem('Refusing symlink worker')
        SELF.write_bytes(Path(__file__).read_bytes()); os.chmod(SELF,0o700)
    for name,text in {
        'freepbx-voicemail.service':'''[Unit]
Description=FreePBX Care voicemail transcription notifications
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/freepbx-care/voicemail.py work
TimeoutStartSec=300
UMask=0077
Nice=15
IOSchedulingClass=idle
MemoryMax=256M
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadOnlyPaths=/var/spool/asterisk/voicemail
''',
        'freepbx-voicemail-listener.service':'''[Unit]
Description=FreePBX Care read-only AMI voicemail listener
After=network-online.target freepbx.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/lib/freepbx-care/voicemail_ami.py
Restart=on-failure
RestartSec=10
UMask=0077
Nice=15
MemoryMax=128M
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadOnlyPaths=/var/spool/asterisk/voicemail
[Install]
WantedBy=multi-user.target
''',
        'freepbx-voicemail.timer':'''[Unit]
Description=Check configured voicemail inboxes (no PBX health probes)
[Timer]
OnBootSec=90s
OnUnitInactiveSec=60s
AccuracySec=5s
RandomizedDelaySec=10s
Unit=freepbx-voicemail.service
[Install]
WantedBy=timers.target
'''}.items():
        path=Path('/etc/systemd/system')/name
        if path.is_symlink(): raise Problem('Refusing symlink unit')
        path.write_text(text); os.chmod(path,0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True,timeout=20)
    if enable:
        subprocess.run(['systemctl','enable','--now','freepbx-voicemail-listener.service'],check=True,timeout=20)
        subprocess.run(['systemctl','enable','--now','freepbx-voicemail.timer'],check=True,timeout=20)
        print('Voicemail listener/worker enabled. Leave a NEW voicemail and verify SMS/email and call details.')


def status():
    print('Voicemail version:',VERSION)
    c=config()
    print('Credentials present (values hidden):',json.dumps({k:bool(c.get(k)) for k in ['openai_key','bandwidth_client','bandwidth_secret']}))
    print('Model:',c.get('model'))
    print('Listener:',json.dumps(load(STATE/'listener-health.json',{})))
    for key,p in c.get('mailboxes',{}).items():
        print(key, json.dumps({k:p.get(k) for k in ['enabled','label','sms','emails','attach_audio','since']}))
    review=[]
    for path in STATE.glob('*.json'):
        if path.name=='oauth.json': continue
        job=load(path,{})
        if job.get('blocked') or any(x.get('result') in ['review','rejected'] for x in job.get('deliveries',{}).values()):
            review.append(dict(job=path.stem,mailbox=job.get('mailbox'),error=job.get('error'),
                               deliveries={k:v['result'] for k,v in job.get('deliveries',{}).items()}))
    print('Jobs requiring review (no transcript):',json.dumps(review,indent=2))


def review_job():
    status()
    ident=ask('Job ID from status')
    if not re.fullmatch(r'[a-f0-9]{64}',ident): raise Problem('Invalid job ID')
    path=STATE/(ident+'.json')
    if not path.is_file(): raise Problem('Job not found')
    job=load(path,{})
    print('Check Bandwidth message records/mail queue before retrying. A timeout can mean the message was accepted.')
    if ask('Confirmed these review deliveries were NOT accepted, and approve retry? y/n','n').lower()!='y': return
    job['deliveries']={k:v for k,v in job.get('deliveries',{}).items() if v.get('result')=='accepted'}
    job.update(done=False,blocked=False,attempts=0,next_try=0)
    atomic(path,job)
    print('Reviewed retry queued from the durable snapshot. Accepted deliveries remain skipped.')


def menu():
    while True:
        print('\nVoicemail transcription\n1 Add new extension/mailbox\n2 Edit existing profile\n3 Update API credentials/model/SMS sender\n4 Status (secrets/transcripts hidden)\n5 Install/enable AMI listener and queue worker\n6 Disable voicemail notifications\n7 Review/retry failed delivery\n8 Configure dedicated loopback AMI account\n9 Refresh inbound DID/route descriptions\n10 Delete mailbox notification profile\n0 Return')
        choice=ask('Choose','0')
        if choice=='0': return
        try:
            c=config()
            if choice in ['1','2']:
                available=mailboxes() if choice=='1' else {k:v for k,v in c['mailboxes'].items()}
                keys=sorted(available)
                if not keys: raise Problem('No mailboxes found; enable voicemail for the extension in FreePBX first')
                for i,key in enumerate(keys,1): print(i,key,available[key].get('name',available[key].get('label','')))
                selected=int(ask('Select mailbox number'))
                if not 1<=selected<=len(keys): raise Problem('Selection out of range')
                key=keys[selected-1]
                if choice=='1' and key in c['mailboxes']: raise Problem('Profile exists; choose Edit')
                if choice=='1' and available[key].get('retains_audio') is False:
                    raise Problem('This mailbox deletes recordings after native email. Turn off Delete Voicemail in FreePBX before real-time capture.')
                if choice=='1' and available[key].get('configured') is False:
                    if not yesno('This is an unverified custom/historical spool. Confirm this is the active mailbox?',False):continue
                p=dict(c['mailboxes'].get(key,dict(context=available[key]['context'],extension=available[key]['extension'],since=int(time.time()),enabled=True,sms=[],emails=[])))
                p['label']=ask('Property/company name',p.get('label',socket.gethostname()))
                p['sms']=recipients('SMS transcript recipients',p['sms'],PHONE)
                p['emails']=recipients('Email transcript recipients',p['emails'],EMAIL)
                if p['sms']:
                    while True:
                        p['sender_mode']=ask('SMS sender mode: custom or called_did',p.get('sender_mode','custom'))
                        if p['sender_mode'] in ['custom','called_did']:break
                        print('Choose custom or called_did.')
                    if p['sender_mode']=='custom':
                        while True:
                            p['sms_from']=ask('Custom Bandwidth SMS sender (+countrycode)',p.get('sms_from',c.get('bandwidth_from','')))
                            if PHONE.fullmatch(p['sms_from']):break
                            print('Enter an E.164 sender.')
                    else:
                        p['allowed_dids']=recipients('Approved Bandwidth inbound DIDs for this application',p.get('allowed_dids',[]),PHONE)
                        if not p['allowed_dids']:raise Problem('Authorize at least one inbound SMS sender DID')
                p['attach_audio']=yesno('Attach recording to transcript email? y/n',p.get('attach_audio',False))
                was_enabled=p.get('enabled',True)
                p['enabled']=yesno('Enable this profile? y/n',was_enabled)
                if p['enabled'] and not was_enabled: p['since']=int(time.time())
                c['mailboxes'][key]=p
                credentials(c)
                print('Uploads NEW voicemail audio to OpenAI and sends transcripts to the listed recipients only.')
                if not yesno('Save these settings? y/n',False): continue
                atomic(ETC/'voicemail.json',c)
                print('Saved. Existing messages before initial setup/re-enable are excluded. Use option 5 to enable worker.')
            elif choice=='3':
                credentials(c,True); atomic(ETC/'voicemail.json',c)
                print('Credentials/settings updated; secrets were not displayed.')
            elif choice=='4': status()
            elif choice=='5': install()
            elif choice=='6':
                subprocess.run(['systemctl','disable','--now','freepbx-voicemail.timer'],check=True,timeout=20)
                subprocess.run(['systemctl','disable','--now','freepbx-voicemail-listener.service'],check=True,timeout=20)
                print('New worker starts disabled; an already-running send is not cancelled.')
            elif choice=='7': review_job()
            elif choice=='8':setup_listener(c)
            elif choice=='9':refresh_routes(c)
            elif choice=='10':
                keys=sorted(c['mailboxes'])
                for i,key in enumerate(keys,1):print(i,key)
                index=int(ask('Profile number to delete'))
                if not 1<=index<=len(keys):raise Problem('Invalid selection')
                if yesno('Delete profile? Saved queued data follows retention; it will not be sent.',False):
                    del c['mailboxes'][keys[index-1]];atomic(ETC/'voicemail.json',c)
            else: print('Choose a listed option')
        except Problem as e:
            print('Voicemail setup:',str(e))
        except (ValueError,subprocess.SubprocessError):
            print('Settings not completed. Check selection, recipient format, credentials or service state; no secrets displayed.')


def prepare_directories(worker=False):
    for path in [ETC,STATE]:
        if path.is_symlink(): raise Problem('Refusing symlink private directory')
        if worker:
            # ProtectSystem=full deliberately makes /etc read-only. Setup has
            # already created these directories; runtime must only validate.
            s=path.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode & 0o077:
                raise Problem('Voicemail private directories must be root-owned mode 700; rerun setup')
        else:
            path.mkdir(mode=0o700,parents=True,exist_ok=True)
            os.chmod(path,0o700)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',nargs='?',default='menu',choices=['menu','work','status','install'])
    a=parser.parse_args()
    if os.geteuid()!=0: raise Problem('Run as root')
    os.umask(0o077)
    if a.command=='status':status();return
    prepare_directories(worker=a.command=='work')
    with (STATE/'lock').open('w') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            if a.command=='work': return
            raise Problem('Voicemail worker/setup is busy; retry shortly') from None
        if a.command=='menu': menu()
        elif a.command=='work': worker()
        elif a.command=='status': status()
        else: install()


def fatal(error):
    reason=str(error) if isinstance(error,Problem) else ('Local '+type(error).__name__+'; errno '+str(getattr(error,'errno','unavailable')))
    print('Voicemail operation failed:',reason,file=sys.stderr)
    try:
        c=config()
        if not c.get('ops_email'):
            core=load(ETC/'config.json',{});c['ops_email']=core.get('email');c.setdefault('sender_email',core.get('sender'))
        ops(c,'worker failure',reason)
    except Exception:print('Error email unavailable; review node journal and local mail queue.',file=sys.stderr)

if __name__=='__main__':
    try: main()
    except (Problem,OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
        fatal(e);sys.exit(1)
