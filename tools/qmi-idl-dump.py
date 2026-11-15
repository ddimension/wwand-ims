#!/usr/bin/env python3
# qmi-idl-dump.py LIB READELF [SVC:TYPE:TABLE ...]
#
# Decode the QMI IDL encoder tables (qmi_idl_lib v6) of a Qualcomm
# libqmiservices.so pulled from a shipping Android vendor partition (aarch64;
# RELR relocations, so pointers are stored in place). Without type arguments
# it prints JSON
#   { "0xSS": { name, msgs: { req|resp|ind: { "0xMMMM": { "0xTT": desc } } } } }
# where desc is the wire element: u8/u16/u32/u64, e8/e16 (1-/2-byte enum),
# str, agg#TYPE@TABLE, with [N] fixed or [<= N] variable arrays. With
# SVC:TYPE:TABLE arguments it expands those aggregate types instead.
# Table N > 0 of a TYPE88/TYPE16 reference is read as referenced table N-1
# here (it decodes every message of this build). A referenced table that
# lives in another library (pointer 0 here, e.g. the voice common types) is
# not followed. Used for docs/qmi-beyond-libqmi.md; the OnePlus 8T dump of
# 2026-11-15 is research/op8t-20261113/idl-libqmiservices.json.
import struct,sys,json,subprocess
lib=sys.argv[1]; readelf=sys.argv[2]
d=open(lib,'rb').read()
segs=[]
for l in subprocess.run([readelf,'-l','-W',lib],capture_output=True,text=True).stdout.splitlines():
    p=l.split()
    if p and p[0]=='LOAD': segs.append((int(p[1],16),int(p[2],16),int(p[4],16)))
syms=[]
for l in subprocess.run([readelf,'--dyn-syms','-W',lib],capture_output=True,text=True).stdout.splitlines():
    p=l.split()
    if len(p)>=8 and p[7].endswith('qmi_idl_service_object_v01') or (len(p)>=8 and p[7].endswith('qmi_idl_service_object_v02')):
        syms.append((p[7],int(p[1],16)))
def fo(va):
    for off,v,sz in segs:
        if v<=va<v+sz: return va-v+off
    raise KeyError(hex(va))
def ptr(va): return struct.unpack_from('<Q',d,fo(va))[0]
TN=['u8','u16','u32','u64','e8','e16','str','agg']
def ttobj(tt):
    n_types,n_msgs,n_ref=struct.unpack_from('<HHB',d,fo(tt))
    return dict(types=ptr(tt+8),msgs=ptr(tt+16),refs=ptr(tt+24),n_ref=n_ref)
def elem(i):
    t=d[i]; i+=1
    if t&0x80: off=d[i]|d[i+1]<<8; i+=2
    else: off=d[i]; i+=1
    desc=TN[t&7]; 
    if t&0x40:
        if t&0x20: n=d[i]|d[i+1]<<8; i+=2
        else: n=d[i]; i+=1
        if t&0x10:
            desc=f'{desc}[<= {n}]'+(' u16-count' if t&0x20 else '')
            if (t&7)!=6: i+=1
        else: desc=f'{desc}[{n}]'
    if t&7==7:
        tb,ti=d[i],d[i+1]; i+=2
        desc+=f'#{tb|((ti&0xf0)<<4)}@{ti&0xf}'
    return desc,i
def msg(enc):
    i=fo(enc); out={}
    while True:
        f=d[i]; i+=1
        if f&0x40: tlv=d[i]; i+=1
        else: tlv=f&0x0f
        desc,i=elem(i)
        out[f'0x{tlv:02X}']=desc
        if f&0x80 or len(out)>120: break
    return out
res={}
for name,so in syms:
    o=fo(so)
    sid=struct.unpack_from('<I',d,o+8)[0]; n=struct.unpack_from('<HHH',d,o+16)
    tt=ttobj(ptr(so+48))
    e={'name':name,'msgs':{}}
    for kind,k in (('req',0),('resp',1),('ind',2)):
        tab=ptr(so+24+8*k); e['msgs'][kind]={}
        for j in range(n[k]):
            mid,tid,ml=struct.unpack_from('<HHH',d,fo(tab+6*j))
            table=tid>>12; idx=tid&0xfff
            t=tt
            if table:
                t=ttobj(ptr(tt['refs']+8*(table-1)))
            try:
                enc=ptr(t['msgs']+16*idx+8)
                e['msgs'][kind][f'0x{mid:04X}']=msg(enc) if enc else {}
            except Exception as ex:
                e['msgs'][kind][f'0x{mid:04X}']={'err':str(ex)}
    res[f'0x{sid:02X}']=res.get(f'0x{sid:02X}') or e
    if res[f'0x{sid:02X}'] is not e: res[f'0x{sid:02X}:'+name]=e
if len(sys.argv)<4: json.dump(res,sys.stdout,indent=0)

def typedump(sid,tidx,table,depth=0):
    for name,so in syms:
        if struct.unpack_from('<I',d,fo(so)+8)[0]==sid: break
    tt=ttobj(ptr(so+48))
    if table: tt=ttobj(ptr(tt['refs']+8*(table-1)))
    sz=struct.unpack_from('<I',d,fo(tt['types']+16*tidx))[0]; enc=fo(ptr(tt['types']+16*tidx+8))
    i=enc; fields=[]
    while d[i]!=0x00 or not fields:
        if d[i]==0 and fields: break
        desc,i=elem(i); fields.append(desc)
        if len(fields)>30: break
    return sz,fields
if len(sys.argv)>=4:
    for a in sys.argv[3:]:
        s,t,tb=[int(x,0) for x in a.split(":")]; print(a, typedump(s,t,tb))
