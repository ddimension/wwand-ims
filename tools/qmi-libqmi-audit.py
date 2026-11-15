#!/usr/bin/env python3
# qmi-libqmi-audit.py LIBQMI_DATA SCHEMA.json... [--idl IDL.json]
#
# Lists every QMI message and TLV id in wwand's / wwand-ims's schemas that
# libqmi 1.38 does not define (LIBQMI_DATA = libqmi's data/ directory), and
# with --idl looks each one up in a vendor IDL dump (tools/qmi-idl-dump.py).
# The schema JSON comes from tools/qmi-libqmi-audit.sh. The result is the
# table in ../wwand-ims-core/docs/qmi-beyond-libqmi.md.
import json,re,sys
args=sys.argv[1:]
idl=None
if '--idl' in args:
    i=args.index('--idl'); idl=json.load(open(args[i+1])); del args[i:i+2]
J=args[0]
def load(p): return json.loads(re.sub(r'^\s*//.*$','',open(p).read(),flags=re.M))
common={}
for x in load(J+'/qmi-common.json'):
    if 'common-ref' in x and 'id' in x: common[x['common-ref']]=x['id']
SVC={0x00:'ctl',0x01:'wds',0x02:'dms',0x03:'nas',0x05:'wms',0x09:'voice',0x0b:'uim',0x10:'loc',0x12:'ims',0x1a:'wda',0x21:'imsa',0x24:'pdc',0x2a:'dsd',0x0a:None,0x18:None}
lib={}
for sid,name in SVC.items():
    if not name: continue
    d=load(f'{J}/qmi-service-{name}.json')
    refs=dict(common)
    for x in d:
        if 'common-ref' in x and 'id' in x: refs[x['common-ref']]=x['id']
    msgs={}
    for x in d:
        if x.get('type') not in ('Message','Indication'): continue
        mid=int(x['id'],16)
        def tl(lst):
            out={}
            for t in lst or []:
                i=t.get('id') or refs.get(t.get('common-ref'))
                if i: out[int(i,16)]=t.get('name') or t.get('common-ref')
            return out
        e=msgs.setdefault(mid,{})
        if x['type']=='Message': e['name']=x['name']; e['req']=tl(x.get('input')); e['resp']=tl(x.get('output'))
        else: e['iname']=x['name']; e['ind']=tl(x.get('output'))
    lib[sid]=msgs
rows=[]
sch={}
for f in args[1:]:
    sch.update(json.load(open(f)))
if True:
    for mod,S in sch.items():
        sid=S['service']
        for k,m in S['messages'].items():
            mid=m['id']
            L=lib.get(sid)
            if L is None: rows.append((mod,k,mid,'*','whole service not in libqmi')); continue
            lm=L.get(mid)
            if not lm: rows.append((mod,k,mid,'*','message not in libqmi')); continue
            for part in ('req','resp','ind'):
                for fld,t in (m.get(part) or {}).items():
                    if t is None: continue
                    if part=='resp' and t==2: continue
                    if t not in (lm.get(part) or {}):
                        rows.append((mod,k,mid,f'{part}:{fld}=0x{t:02X}','TLV not in libqmi'))
def in_idl(mod,name,mid,what):
    if idl is None: return ''
    svc=idl.get(f"0x{sch[mod]['service']:02X}")
    if not svc: return 'service not in IDL'
    m=sch[mod]['messages'][name]
    if what=='*':
        out=[]
        for p in ('req','resp','ind'):
            if m.get(p) is None: continue
            got=svc['msgs'][p].get(f'0x{mid:04X}')
            if got is None: out.append(p+': message not in IDL'); continue
            miss=[f'0x{t:02X}' for t in m[p].values() if t is not None and f'0x{t:02X}' not in got]
            out.append(p+': '+(('missing '+','.join(miss)) if miss else 'all TLVs in IDL'))
        return '; '.join(out)
    p,rest=what.split(':'); tid=rest.split('=')[1]
    got=svc['msgs'][p].get(f'0x{mid:04X}') or {}
    return ('IDL '+got[tid]) if tid in got else 'TLV not in IDL'
for r in rows: print(f'{r[0]:13} {r[1]:32} 0x{r[2]:04X} {r[3]:34} {r[4]:28} {in_idl(r[0],r[1],r[2],r[3])}')
