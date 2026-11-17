#!/usr/bin/env python3
"""Optional FreePBX Care voicemail transcription and recipient notifications.

No dialplan changes, hooks, PBX restarts or caller-ID-directed SMS. Python stdlib.
"""
import argparse
import base64
import configparser
import datetime
import email.message
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
MAX_AUDIO = 24 * 1024 * 1024
PHONE = re.compile(r'\+[1-9][0-9]{7,14}\Z')
EMAIL = re.compile(r'[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\Z')
COMPONENT = re.compile(r'[A-Za-z0-9_-]{1,80}\Z')


class Problem(RuntimeError):
    """Safe-to-log error; never contains API response bodies or credentials."""


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
    return load(ETC/'voicemail.json', dict(model='gpt-transcribe', mailboxes={}))


def validate(c):
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,80}', c.get('model', '')):
        raise Problem('Invalid transcription model')
    if not isinstance(c.get('mailboxes'), dict) or len(c['mailboxes']) > 100:
        raise Problem('At most 100 mailbox profiles are supported')
    for key, p in c['mailboxes'].items():
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
                    name=fields[1].strip()[:80] if len(fields)>1 else '')
        return context
    parse(AST/'voicemail.conf')
    # Existing custom voicemail contexts are also discoverable from the spool.
    for inbox in SPOOL.glob('*/*/INBOX'):
        context, ext = inbox.parent.parent.name, inbox.parent.name
        if COMPONENT.fullmatch(context) and re.fullmatch(r'[0-9]{1,20}', ext):
            found.setdefault(context+'/'+ext, dict(context=context, extension=ext, name='existing spool mailbox'))
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
            return json.loads(data)
    except urllib.error.HTTPError as e:
        # Do not expose server response bodies, URLs, secrets or transcript text.
        raise Problem(f'API HTTP {e.code}; inspect account settings before retry') from None
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


def bandwidth_token(c):
    cache = load(STATE/'oauth.json', {})
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
    r = request('https://messaging.bandwidth.com/api/v2/users/'+c['bandwidth_account']+'/messages',
                json.dumps(body).encode(), {'Authorization':'Bearer '+token, 'Content-Type':'application/json; charset=utf-8'})
    mid = r.get('id') or r.get('messageId')
    if not isinstance(mid,str) or not mid: raise Problem('SMS response has no message ID; acceptance unknown')
    return mid


def mail(c, recipient, subject, body, audio=None):
    msg = email.message.EmailMessage()
    msg['To'], msg['From'], msg['Subject'] = recipient, c['sender_email'], subject
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
        state[key] = dict(result='review', reason=str(e))
        print('Voicemail delivery requires review:', key.split(':',1)[0], str(e), flush=True)
    atomic(jpath, job)


def sms_text(body):
    suffix='\n[SMS shortened; listen to voicemail for full details.]'
    if len(body.encode('utf-16-le'))//2 <= 600: return body
    clipped=body.encode('utf-16-le')[:(600-len(suffix))*2].decode('utf-16-le',errors='ignore')
    return clipped+suffix


def process(c, key, profile, path):
    meta = metadata(path)
    if int(meta['origtime']) < max(profile['since'],time.time()-30*86400): return False
    ident = identity(key, meta)
    jpath = STATE/(ident+'.json')
    job = load(jpath, {})
    if job.get('done') or job.get('blocked'): return False
    if job.get('next_try',0) > time.time(): return False
    audio = None
    try:
        if 'transcript' not in job:
            audio = audio_bytes(path.with_suffix('.wav'))
            job.update(mailbox=key, created=time.time(), deliveries={})
            job['transcript'] = transcribe(c,audio)
            atomic(jpath,job)
        transcript = job['transcript']
        caller = str(meta.get('callerid','Unknown caller')).replace('\r',' ').replace('\n',' ')[:200]
        recorded=datetime.datetime.fromtimestamp(int(meta['origtime'])).astimezone().strftime('%Y-%m-%d %H:%M %Z')
        body = f"{profile['label']} - voicemail for {profile['extension']}\nFrom: {caller}\nRecorded: {recorded}\n\nTranscript (automatic; verify important details):\n{transcript}"
        targets=['email:'+r for r in profile['emails']]+['sms:'+r for r in profile['sms']]
        pending=[t for t in targets if t not in job.get('deliveries',{})][:4]
        token=None
        for target in pending:
            kind,recipient=target.split(':',1)
            if kind=='email':
                if profile.get('attach_audio') and audio is None: audio=audio_bytes(path.with_suffix('.wav'))
                delivery(jpath,job,target,lambda r=recipient: mail(c,r,'Voicemail transcript - '+profile['extension'],body,audio if profile.get('attach_audio') else None))
            else:
                if token is None: token=bandwidth_token(c)
                delivery(jpath,job,target,lambda r=recipient: sms(c,r,sms_text(body),token,'care-vm-'+ident[:32]))
        job['done'] = all(t in job.get('deliveries',{}) for t in targets)
        atomic(jpath,job)
        print('Voicemail processed:', key, ident[:12], flush=True)
    except (Problem, FileNotFoundError) as e:
        # Bounded pre-delivery retry. Delivery ambiguity is retained, never retried automatically.
        job.update(mailbox=key, attempts=job.get('attempts',0)+1, error=str(e) if isinstance(e,Problem) else 'Recording unavailable')
        job['blocked'] = job['attempts'] >= 3
        job['next_try'] = time.time()+300
        atomic(jpath,job)
        print('Voicemail processing deferred/requires review:', key, ident[:12], job['error'], flush=True)
    return True


def worker():
    c = validate(config()); required_credentials(c)
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
    if any(p['emails'] for p in c['mailboxes'].values()) or (force and c.get('sender_email')):
        c['sender_email']=ask('Email sender (use the PBX configured relay sender)',c.get('sender_email',''))
    validate(c); required_credentials(c)


def install():
    if not (ETC/'voicemail.json').is_file(): raise Problem('Configure a mailbox first')
    c=validate(config()); required_credentials(c)
    if not any(p.get('enabled') for p in c['mailboxes'].values()): raise Problem('No enabled mailbox profile')
    if any(p.get('enabled') and p['emails'] for p in c['mailboxes'].values()) and not os.access('/usr/sbin/sendmail',os.X_OK):
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
    subprocess.run(['systemctl','enable','--now','freepbx-voicemail.timer'],check=True,timeout=20)
    print('Voicemail worker enabled. Care health timer is unchanged. Leave a NEW voicemail for a pilot test.')


def status():
    c=config()
    print('Credentials present (values hidden):',json.dumps({k:bool(c.get(k)) for k in ['openai_key','bandwidth_client','bandwidth_secret']}))
    print('Model:',c.get('model'))
    for key,p in c.get('mailboxes',{}).items():
        print(key, json.dumps({k:p.get(k) for k in ['enabled','label','sms','emails','attach_audio','since']}))
    review=[]
    for path in STATE.glob('*.json'):
        if path.name=='oauth.json': continue
        job=load(path,{})
        if job.get('blocked') or any(x.get('result')=='review' for x in job.get('deliveries',{}).values()):
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
    job['deliveries']={k:v for k,v in job.get('deliveries',{}).items() if v.get('result')!='review'}
    job.update(done=False,blocked=False,attempts=0,next_try=0)
    atomic(path,job)
    print('Reviewed retry queued; the matching recording/metadata must still be in INBOX. Accepted deliveries remain skipped.')


def menu():
    while True:
        print('\nVoicemail transcription\n1 Add new extension/mailbox\n2 Edit existing profile\n3 Update API credentials/model/SMS sender\n4 Status (secrets/transcripts hidden)\n5 Install/enable lightweight worker\n6 Disable lightweight worker\n7 Review/retry failed delivery\n0 Return')
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
                p=dict(c['mailboxes'].get(key,dict(context=available[key]['context'],extension=available[key]['extension'],since=int(time.time()),enabled=True,sms=[],emails=[])))
                p['label']=ask('Property/company name',p.get('label',socket.gethostname()))
                p['sms']=recipients('SMS transcript recipients',p['sms'],PHONE)
                p['emails']=recipients('Email transcript recipients',p['emails'],EMAIL)
                p['attach_audio']=ask('Attach recording to transcript email? y/n','y' if p.get('attach_audio') else 'n').lower()=='y'
                was_enabled=p.get('enabled',True)
                p['enabled']=ask('Enable this profile? y/n','y' if was_enabled else 'n').lower()=='y'
                if p['enabled'] and not was_enabled: p['since']=int(time.time())
                c['mailboxes'][key]=p
                credentials(c)
                print('Uploads NEW voicemail audio to OpenAI and sends transcripts to the listed recipients only.')
                if ask('Save these settings? y/n','n').lower()!='y': continue
                atomic(ETC/'voicemail.json',c)
                print('Saved. Existing messages before initial setup/re-enable are excluded. Use option 5 to enable worker.')
            elif choice=='3':
                credentials(c,True); atomic(ETC/'voicemail.json',c)
                print('Credentials/settings updated; secrets were not displayed.')
            elif choice=='4': status()
            elif choice=='5': install()
            elif choice=='6':
                subprocess.run(['systemctl','disable','--now','freepbx-voicemail.timer'],check=True,timeout=20)
                print('New worker starts disabled; an already-running send is not cancelled.')
            elif choice=='7': review_job()
            else: print('Choose a listed option')
        except Problem as e:
            print('Voicemail setup:',str(e))
        except (ValueError,subprocess.SubprocessError):
            print('Settings not completed. Check selection, recipient format, credentials or service state; no secrets displayed.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',nargs='?',default='menu',choices=['menu','work','status','install'])
    a=parser.parse_args()
    if os.geteuid()!=0: raise Problem('Run as root')
    os.umask(0o077)
    for path in [ETC,STATE]:
        if path.is_symlink(): raise Problem('Refusing symlink private directory')
        path.mkdir(mode=0o700,parents=True,exist_ok=True); os.chmod(path,0o700)
    with (STATE/'lock').open('w') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            if a.command=='work': return
            raise Problem('Voicemail worker/setup is busy; retry shortly') from None
        if a.command=='menu': menu()
        elif a.command=='work': worker()
        elif a.command=='status': status()
        else: install()


if __name__=='__main__':
    try: main()
    except Problem as e:
        print('Voicemail operation failed:',str(e),file=sys.stderr)
        sys.exit(1)
    except (Problem,OSError,ValueError,subprocess.SubprocessError):
        print('Voicemail operation failed. Inspect private settings/service state; no secrets displayed.',file=sys.stderr)
        sys.exit(1)
