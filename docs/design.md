# wwand-ims — design

_Draft of 2026-11-13, direction changed 2026-11-14 (section 1)._

## 1. Who speaks IMS

**Since 2026-11-14: the router does, with its own IMS UE.** The modem
is asked only for what the host cannot do itself: the attach, an IMS PDN
on a host mux, the USIM over the raw APDU channel, and the cell for
`P-Access-Network-Info`. Its own IMS stack is switched off.

The first draft had rejected a host-side client: the modem already carries
a complete IMS stack, tested by the operator. The measurements of
2026-11-13/14 turned that around:

- **Firmware gates:** the RG650E on A05 computes IMS voice off in its own
  settings engine although every host input is right; the registration
  carries no MMTEL feature tag (research/rg650e-245/NOTES.md, F3 trace).
- **No audio path:** the 5G modules have no working host PCM (section
  5.3). With the router as the UE the voice is RTP over the IMS PDN, and
  UAC, QPCMV and the PCM pins drop out of the picture.
- **The MBN problem disappears:** the operator settings are a profile on
  the router, not an MBN on the modem. A data-only module becomes
  voice-capable if the network grants the IMS APN and AKA works through
  the card.

The dedicated QCI 1 bearer is set up by the network (P-CSCF → PCRF), but
the eNB sets it up only for a UE that reports VoLTE support. The RG650E
ships with LTE FGI 3 and 7 (RLC UM) off. That is a "no VoLTE" UE, and every
call ended in `503 … ASR: BEARER_RELEASED`, on every SIM (section 5.4). With
`AT+QNWCFG="lte_fgi_fdd"` plus 3 and 7 the bearer comes up and calls work
both ways (research/rg650e-245/NOTES.md, 2026-11-14). A host UE needs this
override on such a module just as the modem's own IMS would.

Decisions (2026-11-14):

| Topic | Decision |
|---|---|
| Operator settings | profiles in `/etc/config/wwand_ims`; the modem's carrier MBN is a **source** for them, read by an import tool (MBN -> profile), with an override layer on top (GDSP). At run time only the profile counts |
| Media | the codecs are passed through 1:1, no transcoding: the relay only moves RTP/RTCP between the LAN phone and the IMS PDN address. The LAN phone must speak what the network speaks (AMR-WB/AMR, RFC 4867) |
| IPsec (sec-agree) | kernel ESP in transport mode, SAs and policies over **NETLINK_XFRM** from a small native module (`src/xfrm`), no `ip xfrm` CLI, no IKE daemon |
| Isolation | the IMS PDN in a VRF of its own (or its own routing table with rules): the UE's sockets, the relay and the xfrm selectors live there, nothing of the LAN or the data PDN reaches it |
| Emergency calls | not yet. sipd recognises the emergency numbers and refuses them audibly instead of letting them die silently |
| VoWiFi (ePDG, IKEv2 + EAP-AKA through the card) | phase 2, with a strongSwan plugin; the OpenWrt strongSwan package builds no eap-aka at all, which is a task of its own |

The QMI call-control plugin (`plugins/ims.uc`) stays: for a modem whose
own IMS works (EG25-G) it is the cheaper path, and sipd can sit on either
backend.

## 2. Components

| Component | Runs | Talks to |
|---|---|---|
| `ue/aka.uc` | in the UE | the USIM over `wwand modem_apdu` (own logical channel); AUTHENTICATE, AUTS; Digest AKAv1-MD5 nonce; IMPI/IMPU from the IMSI |
| `ue/secagree.uc` | in the UE | Security-Client/-Server/-Verify, ESP keys from CK/IK, the four SAs of TS 33.203 7.1 |
| `src/xfrm` (C, ucode module `wwand_ims_xfrm`) | in the UE | NETLINK_XFRM: reserve SPIs, add/update/delete SAs and policies |
| UE (planned) | own procd service, in the IMS VRF | P-CSCF over UDP/TCP: REGISTER, reg-event, INVITE with preconditions, PRACK, UPDATE |
| `sipd/` | own procd service | LAN phones (SIP/UDP+TCP); B2BUA to the UE or to the QMI plugin |
| RTP relay (planned) | per call | LAN phone <-> IMS PDN address and the ports in our SDP (the QCI 1 TFT matches them) |
| `plugins/ims.uc` | in the wwand daemon | QMI IMSA/IMS/NAS/Voice: the modem-IMS backend, and IMS off for the host UE |
| `mcfg` (C) | CLI | MBN files: unpack, read the IMS items for the import |
| `tools/efs-dump.sh` | CLI | modem EFS items, read-only |

What the wwand core needs (neutral, no voice code):
- the P-CSCF addresses of a PDN (PCO, WDS runtime settings) in the
  interface status, so the UE finds its P-CSCF;
- a guarantee that the attach-profile code never touches the IMS profile,
  backed by a test.

## 2a. Phases

| Phase | Content | State |
|---|---|---|
| 1 spike | IMS PDN on a host mux in the IMS VRF, P-CSCF, AKA over APDU, sec-agree over netlink, REGISTER -> 200 OK | AKA and sec-agree written and host-tested (incl. a real kernel in a netns), 2026-11-14 |
| 1 calls | MO/MT, PRACK, preconditions towards the network, plain SDP towards the phone | |
| 1 media | RTP/RTCP relay, codecs passed through | |
| 1 robustness | PDN loss, re-auth with new SAs (TS 33.203 7.4), network de-registration, modem reset | |
| 2 | VoWiFi: strongSwan with an EAP-AKA card plugin over the same APDU path, the tunnel as an XFRM interface in the IMS VRF | |

Blocker on the hardware: the test kernels (Chateau 6.18.55, NR7101 6.18.60)
have no `xfrm_user`/`esp4`/`esp6`, and the snapshot feeds carry no
matching kmods. The spike device needs an image (or kmods from the same
kernel build) with IPsec; build project: `/vol/release/wwand-ims`.

## 3. Profiles: where each GDSP setting goes

Source: "Vodafone IoT 90128 Variant Settings.xlsx", column c-IoT, read
2026-11-13. "Open" means libqmi 1.38 or libmbim 1.32 define the message.

| Setting | GDSP value | How it gets into the modem |
|---|---|---|
| IMS APN | `ims.iot` | IMS PDN profile, WDS Modify Profile (open). RG650E: profile 2, APN `ims` under Commercial-DT-VOLTE (EFS `/Data_Profiles/Profile2`, measured 2026-11-13) |
| IP version | IPv4v6 (network gives IPv4 only, 172.23.0.0/16) | same profile |
| P-CSCF discovery | PCO | 3GPP default; check in the IMS items |
| Voice domain | PS preferred, CS secondary | NAS SSP Voice Domain Preference (open); EFS `voice_domain_pref` = 03 (libqmi enum: PS preferred) under DT |
| UE usage | data-centric | NAS SSP Usage Preference (open) |
| SMS domain | PS | EFS `sms_domain_pref` (01 under DT); WMS route if open |
| IMS / VoLTE / SMSoIP on | yes | IMS `0x008F` (open), Quectel `AT+QCFG="ims"` |
| IMPU / IMPI / domain | derived from the USIM, `ims.mnc028.mcc901.3gppnetwork.org` | 3GPP TS 23.003 derivation, no setting if the modem derives |
| Auth / IPsec | AKAv1-MD5, hmac-sha-1-96, null/AES | MBN IMS items |
| SIP T1 / T2 / T4 | 2000 ms / 16 s / 17 s | MBN IMS items (`ims_sip_config` starts 2000, 16000, ..., 5000 LE under DT: to be confirmed by a second snapshot) |
| Registration expiry | 3600 s | network decides; MBN item for the request |
| Session-Expires | UAC 1800 s | MBN IMS items |
| Preconditions, early media, reg-event | yes | MBN IMS items |
| SIP MTU | 1430 | MBN IMS items |
| Codecs | AMR-NB, AMR-WB | MBN IMS items |
| Ut / XCAP | no | MBN IMS items |
| Emergency | IMS where available | MBN IMS items |


A profile can be made from what is in use (LuCI Network → VoLTE, *Clone
current settings*; sipd ubus `profile_snapshot`): the IMS profile of the
modem's carrier config (APN, PDP type), its voice domain and usage
settings, the registration's sec-agree algorithms, the P-CSCF port, the
SMS centre (`AT+CSCA?`), with the SIM's IMSI prefix as `match_imsi`.
## 4. The MBN problem, in three steps

The plugin tries them in order, per profile (`option mbn`):

1. **No MBN change** (`auto` or a named MBN). Apply what is open: IMS on,
   the IMS profile APN, voice domain, usage, SMS domain. Most GDSP values
   are 3GPP defaults or derived from the SIM, so a generic MBN may register.
   This has to be shown, not assumed.
2. **Patch the modem's own MBN** (`patch`). Write the profile's values
   into the IMS items of `mbn_base`, repack, and load it as a new
   configuration named by `mbn_name` (for GDSP:
   `Commercial-Vodafone-GDSP-VoLTE`), via PDC Load/Select/Activate Config (open) or
   `AT+QMBNCFG="Add"`. Nothing foreign is shipped: the input is the
   customer's own modem configuration.
   Two prerequisites:
   - the item layouts: from the official API documentation once it is
     here, and from our own snapshot diffs;
   - whether the firmware accepts an MBN whose signature was stripped.
     sbaresearch/mbn-mcfg-tools reports that the modems they tried checked
     the hashes only; mcfg_tools warns that a modem enforcing signatures
     refuses it. Unknown on the RG650E.
3. **A vendor MBN** for 90128. When Quectel supplies one, `option mbn`
   names it and the plugin only selects it.

**Direct EFS writes** (`AT+QNVFW`) are the fallback for step 2 if MBN
loading is refused. The cost: an MBN re-selection, by the modem's auto
selection on a SIM change or by us, overwrites the items again, so the
plugin has to re-apply them after every MBN change.

### MBN tooling candidates (checked 2026-11-13)

| Tool | Language | Licence | Notes |
|---|---|---|---|
| github.com/Biktorgj/mcfg_tools e1293b5 (2022-09-04) | C, ~1.6k lines + nvitems.h | GPL-3.0 | unpack/pack, SHA-256; strips signatures; packing hard-coded for mdm9x07 ELF/program headers (EG25-G); RG650E needs other headers |
| github.com/fenrir-naru/mbn_utils 65f86ca (2022-03-22) | Ruby, ~280 lines | BSD-3-Clause | items.txt round trip; README: the MCFG digest (32 bytes in the trailer item) must match, and the modem keeps digest versions under `/nv/item_files/mcfg/` |
| github.com/sbaresearch/mbn-mcfg-tools 0026d88 (2024-07-31) | Python | GPL-3.0 | FORMAT.md documents secure-boot header v3/v5 and MCFG; hash check; item parsers auto-generated from EfsTools, "often inaccurate" by its own README |

For on-device use the C tool fits, generalised to the header layout the
target's MBNs carry. FORMAT.md is the format reference.

## 5. Measurements so far

`research/rg650e-245/dump-commercial-dt-volte/`: RG650E-EU
RG650EEU00AAR01A04G8G on the Chateau (2026-11-13). The snapshot holds:
- the MBN Commercial-DT-VOLTE (auto-selected for the Telekom SIM), with
  IMS off (`ims 0,0`, `IMS_enable` 00);
- 55 items read and 9 absent. Most IMS items read back as exactly 1024
  bytes. Whether that is their size or the read limit of `AT+QNVFR` is
  open: compare with an item known to be larger (the XML files read 1.4 to
  3.5 kB, so the limit is not 1024 for all paths).

Next snapshot: the same modem under a second MBN, e.g.
`Germany-VoLTE-Vodafone`. That needs an MBN switch, which counts as
disruptive on the Chateau and needs the user's go.

Audio and MBNs on the other test modems, read 2026-11-13: all four Quectel
modems answer `AT+QPCMV?` and carry the UAC field in `AT+QCFG="USBCFG"`
(currently 0). VoLTE MBNs:
- RG650E: 11 (2023–2024);
- RG502Q: 20, IMS already on;
- EG25-G: 24;
- EG06: 11 (2017–2020).

None of them carries a Vodafone IoT MBN.

### 5.3 Audio paths per module and bus (checked 2026-11-13)

The PCIe/MHI bus itself carries no audio: Qualcomm holds a patent for
voice streams over PCIe (US2019/0251056), but no modem is documented to
implement it, and mainline MHI knows only IP/control/diag channels. So
audio is **not a bus question but a module-and-board question**:

| Path | Needs | Works when attached via |
|---|---|---|
| USB UAC (ALSA) / QPCMV (tty) | the M.2 slot's USB pins wired — common even on PCIe boards (the WH3000 Pro wires its M.2 slot to USB, `board.uc`) | USB or PCIe |
| PCM/I2S pins on the M.2 connector | a voice-capable module **and** board routing of those pins to the host I2S/PCM controller | any bus |

Per module:

| Modem | PCM pins | USB voice | Voice verdict |
|---|---|---|---|
| RG650E | n/a (USB module) | QPCMV + UAC field, measured | dials work (0456d9b) |
| RG502Q | not checked | QPCMV + UAC field, measured | open |
| EG25-G | yes (classic voice module) | QPCMV + UAC field, measured | yes |
| EG06 | not checked | QPCMV + UAC field, measured | open |
| RG520N | PCM + I2S (SLIC/Codec, Bluetooth) | yes | Quectel's voice M.2; VoLTE optional per SKU |
| RM520N-EU | pins 20/22/24/28 | yes | voice possible |
| RM520N-GL | pins RESERVED (GL variant) | ttyUSB PCM, experimental App Note | Quectel: data-only |
| FM350-GL | none | USB 2.0 debug only | data-only (docomo cert: CS Voice NS, VoLTE NS) |

Consequence for `mediad`: three PCM sources — UAC via ALSA, the QPCMV
tty, and the host I2S/PCM controller for voice-capable modules whose
board routes the pins. On a PCIe-only board with a data SKU (FM350-GL,
RM520N-GL) there is no audio path at all: the silicon, not the bus, is
the limit.

### 5.4 What the modem needs from the AP (checked 2026-11-13)

The RG650E calls (research/rg650e-245/NOTES.md) and a stock Android RIL
captured on a OnePlus 8T (research/op8t-20261113/FINDINGS.md) agree.

| AP action | Needed | Source of the format | Evidence |
|---|---|---|---|
| IMS Set IMS Services Enabled Setting 0x008F, volte 0x10 = 1 | **yes**, once; the modem keeps it across resets | libqmi 1.38 | RG650E: without it every MO call is refused locally; with 0 IMS does not even register. 8T: the RIL sends 0x008F, the modem re-applies the stored state at bring-up |
| further 0x008F fields (UT, SMS, USSD, service) | no; the MBN's values stand | libqmi 1.38 | RG650E: calls with volte alone |
| TLV 0x12 in 0x008F | no; not in the public message | – | 8T RIL never sends it |
| Voice Bind Subscription 0x0044 | no | Gobi API | RG650E: calls without; 8T RIL: never sent |
| Dial Call 0x20: number with `+`, call type 0x10 = 0 (voice), audio 0x18 = TX\|RX, video 0x19 = 0 | sent like this since 2026-11-13 | Gobi API | 8T RIL dials exactly so; the RG650E calls the same with or without the attributes |

- **Call mode 6:** the normal first state of a call: "undetermined", the
  Gobi API's "Unknown". It is followed by mode 4 (LTE) once call control
  is done.
- **Set once:** on the 8T, flipping the subscription's VoLTE flag later
  changes only the framework's own gate and sends no QMI item to the
  modem, even across an airplane-mode cycle. The modem keeps the voice
  state it was given at provisioning (FINDINGS.md, section 7). For
  wwand-ims that confirms writing `volte 1` on every open: idempotent, and
  the only point where the AP sets it.
- **IMS services at bring-up:** they are reported disabled first and
  re-enabled within about a second with no AP request (8T). sipd must not
  treat that flap as a lost registration.
- **What is not the AP's job:** the dedicated QCI 1 bearer. On the GDSP SIM
  the network never sets it up and the IMS core aborts every call with
  `503 … ASR …`, MO and MT alike (NOTES.md, 2026-11-13 15:50–16:44 UTC).

### 5.5 VoWiFi and handover (stock RIL, checked 2026-11-13)

Captured on the OnePlus 8T with a congstar eSIM (Telekom network), see
research/op8t-20261113/FINDINGS.md, section 6.

- **Enabling:** the framework's WFC toggle (`wfc_ims_enabled`) goes through
  the RIL into IMS 0x008F as the VoWiFi switch, TLV 0x14 "IMS Voice WiFi
  Service Enable" (libqmi 1.38). The RIL also sends WFC settings to its
  NAS module. Voice then shows as enabled on IWLAN.
- **A first enable is not enough:** until the IMS registration on WLAN
  offers voice, calls still go out over LTE (call mode 4). On the 8T, an
  eSIM off/on cycle plus a fresh toggle did it.
- **Handover during a call (Rove-In), 19:52:13–19:52:20:**
  1. the call starts on LTE (mode 4) and alerts on LTE;
  2. after 2.5 s it is handed over to IWLAN;
  3. it ends on WLAN (mode 7).

  The modem announces it with handover status events (start, then
  complete); the call itself keeps its state.

What follows for wwand-ims:

| Part | Effect |
|---|---|
| plugin | call mode 7 is named `wlan`, so a handover shows in the wwand.ims.call events as `mode` changing while `state` stays; the `volte_enable` op takes `wifi` for TLV 0x14 (sent only when given) |
| sipd | reacts to call states only, so a handover is invisible to the LAN phone (host test: mode lte -> wlan mid-call, no SIP message, call stays) |
| audio | the modem keeps the voice path across the handover (8T); to be confirmed on the module once a call connects |

Open for a router:
- **WLAN on a router** would be its fixed-line WAN as the non-3GPP access.
- **ePDG tunnel (wwand-ims-vowifi), HW 2026-11-21, NR7101 / RG502Q,
  Telekom DE:** the router's own UE registers over VoWiFi
  (`ims_modem` option `access 'vowifi'`). charon (the feed's strongswan:
  eap-aka with fips-prf, p-cscf, and the new ext-aka card plugin) is driven
  over vici only: `vowifi/ctl.uc` loads the connection (NAI
  `0<IMSI>@nai.epc…`, no IDr, virtual IPs, if_id 7001), initiates it, takes
  the P-CSCFs from charon's log and the inner address from list-sas,
  and renews the netifd interface `wwvowifi` (proto `wwandvowifi`,
  files/vowifi-proto.sh, on `@imswifi0`): netifd asks sipd (`vowifi_addr`)
  and puts the address and the default route into table 31, with its
  `from`/`to` rules for the inner address. The XFRM interface `imswifi0` is
  netifd's own OpenWrt `proto xfrm` (`ifid 7001`, `mtu 1280`): the daemon
  touches no address, route or link (wwand's invariant), only charon's own
  copy of the virtual IP on the LAN bridge goes. No VRF, unlike the IMS
  PDN: netifd 2026.02.26 (OpenWrt 25.12) sets `disable_ipv6` on every VRF
  port that has no `ipv6` setting of its own (vrf.c "Disable IPv6 for vrf
  ports", removed by 2026.07), and a proto xfrm device cannot carry one —
  the IPv6-only tunnel was dead that way (HW 2026-11-21). The UE's and the
  relay's sockets bind to `imswifi0` and the inner address instead; the
  table and the rules keep the traffic in the tunnel.
  The two interfaces are netifd's dynamic ones since 2026-11-21: sipd
  creates them (`network add_dynamic`, vowifi/ctl.uc net_specs) with the
  XFRM interface's `zone ims` in its data, which firewall4 (2025.03.17)
  takes into the zone at ifup (HW: input/forward/output chains), and
  removes them when it stops; after a netifd restart (which forgets dynamic
  interfaces) sipd's 5 s tick creates them again (HW: ~5 s, registered
  again ~35 s later). `setup` writes neither them nor zone entries. The
  child's dpd_action is `clear`, close_action `none`: the controller, not
  charon, brings the tunnel back, loading the connection anew first (the
  IDr goes out again then). EAP-AKA runs on the modem's USIM: ext-aka execs
  `/usr/libexec/strongswan/ext-aka`, `vowifi/card.uc` does the AUTHENTICATE
  over wwand's APDU channel. What Telekom's ePDG does: IKE_SA_INIT asks for
  MODP_4096 (AES-CBC-256/HMAC-SHA2-512/PRF-SHA2-512 chosen), NAT-T, the
  first IKE_AUTH answer carries its IDr (`nai.epc.mnc001.mcc262.
  3gppnetwork.org`, not the APN) and an EAP-AKA request, no certificate
  (EAP-only), then one IPv6 address and two IPv6 P-CSCFs. What it took:
  - an IDr `ims` makes charon insist on that identity back: no IDr;
  - `remote.auth = eap-aka` (EAP-only), `pubkey` fails the constraint;
  - one charon setting vici cannot carry, shipped as a file by the package:
    `p-cscf.enable.wwand-vowifi` (else no P-CSCF request). charon installs
    the virtual IP a second time where its outer route points (br-lan);
    the controller flushes that copy before it puts the address on the
    XFRM interface, so charon's global settings stay untouched for its
    other connections (with if_id, charon adds no routes to table 220);
  - the tunnel's VRF and XFRM interface in the IMS firewall zone: the reply
    to the protected REGISTER comes to the UE's server port, not as a
    conntrack reply, and fw4 rejected it (ICMP port unreachable carrying
    the decrypted 200 OK);
  - the UE's sockets bound to no device (udp_l3mdev_accept); the sec-agree
    SAs inside the tunnel need no if_id.
  Kept up by `vowifi/ctl.uc`: an IKE or CHILD SA down (vici ike-updown /
  child-updown), charon itself gone (the vici connection closes; a new
  charon has none of our connection) or a start that fails all lead to a
  new load-conn + initiate, after 5 s backing off to 60 s, never giving up.
  charon's log for our connection goes to syslog through vici (level 0/1
  of IKE/CFG/CHD/KNL as info, failures as warn); the card program logs
  there too (ident wwand-ims-vowifi). The ePDG's wants are profile options
  (`vowifi_epdg`, `vowifi_apn`, `vowifi_proposals`, `vowifi_esp_proposals`,
  `vowifi_remote_auth`, `vowifi_pani`), ims_modem's override.
  An incoming call rang the LAN phone and talked through the tunnel
  (2026-11-21). Open: the P-ANI value (`IEEE-802.11` is sent), handover.
- **From the carrier config:** the MBN carries the modem's own IWLAN
  settings as the EFS file `/data/iwlan_s2b_config.xml` (GENERIC_VARIANT /
  ikev2_info: DH groups, IKE/ESP hash lists, rekey timers, DPD, peer id;
  epdg_addr_info: a static ePDG FQDN). `wwandctl ims setup` reads it — from
  `--mbn FILE` (the firmware image's MBN), the modem's EFS over Quectel's
  `AT+QNVFR`, or else over the DIAG port (`ctl/diag.uc`: EFS2 HELLO/STAT/
  OPEN/READ/CLOSE, read-only, any Qualcomm modem; both byte-identical on the
  RG502Q, 3015 bytes, 2026-11-21) — and adds `vowifi_proposals` (the MBN's proposal, then
  charon's defaults), `vowifi_esp_proposals`, `vowifi_rekey_s`,
  `vowifi_esp_rekey_s`, `vowifi_dpd_s`, `vowifi_epdg` to the SIM's operator
  profile (a new `mbn_<PLMN>` one when none matches); what is set there
  already is kept. Read from public MBNs (Pixel 3A, 2026-11-21): Vodafone DE
  DH 14/2/5, rekey 86400/14400 s; Telekom DE DH 2 (5), rekey 64800 s — its
  ePDG demanded MODP_4096 nevertheless, which charon's defaults after the
  MBN's proposal cover.
- **Vodafone DE (262/02, 2026-11-21, NR7101 on the Chateau's card over
  wwand-rsim):** MODP_2048 demanded (INVAL_KE); without IDr the first
  IKE_AUTH answer is N(10500) NETWORK_FAILURE + N(41041) BACKOFF_TIMER; with
  IDr `ims` EAP-AKA succeeds and the ePDG assigns an IPv6 address and two
  P-CSCFs, then answers IDr = its FQDN, which charon refuses (it requires
  the IDr it sent). The feed's strongSwan plugin `epdg-idr` lets charon
  accept it (`docs/strongswan-idr.md`); the IMS APN is now sent as IDr by
  default, for every operator. With it Vodafone registers over VoWiFi
  (sec-agree `hmac-sha-1-96` + `aes-cbc`, which needed the EIP-93
  fallback of 5.9 on the NR7101).
- **GDSP:** the Vodafone product description lists VoWiFi with a separate
  setup; not tested.

### 5.6 One number on two SIMs (Telekom MultiSIM, NR7101, 2026-11-21)

The router's UE and a phone on a second SIM of the same number. With the
router registered, the phone rang only while its display was on; with
sipd stopped it rang in idle too. The caller always heard ringback.

- Both contacts sit in the reg-event NOTIFY with `q="1"`. The network does
  not fork in the S-CSCF: an AS sends one INVITE per device, each with
  `Accept-Contact: *;+sip.instance="<that device>";explicit;require` and
  `Request-Disposition: no-fork`. The router never sees the phone's leg.
- Without preconditions in the offer the UE answered 100 and 180 within
  70 ms. A phone in idle needs 1–3 s of paging before its own 18x, and the
  network did not alert it then (the router's leg rang on until the CANCEL).
- With the 180 held back 4 s (`ims_profile` option `alert_delay_ms '4000'`,
  only the 100 before it; the LAN phone is offered the call at once) the
  phone rang in idle as well. Measured with `option sip_trace`; the lowest
  delay that is enough was not searched for. The default is 4.5 s, for every
  profile (`alert_delay_ms '0'` sends the 180 at once).
- The upper limit: with 6 s and 8 s the network cancelled the router's leg
  after 5.9 s without any 18x from it (`Reason: SIP;cause=480;
  text="CC_NOT_REACHABLE"`), so the call never rang there. sipd warns about
  more than 5 s.

### 5.7 SMS over IP (2026-11-21, not measured yet)

The router's UE can register for SMS (`ims_modem` option `smsip`, off by
default): `+g.3gpp.smsip` in the Contact, and SIP MESSAGE with
`application/vnd.3gpp.sms` both ways (TS 24.341, RP layer TS 24.011,
`ue/smsip.uc`). What arrives is written into the modem's own store
(`ims_modem` option `sms_storage`, ME or SM; wwand `modem_sms_deliver`,
`sms.uc sms_write`: QMI WMS Raw Write + Modify Tag to unread, else
`AT+CMGW=<len>,0`) as if the modem had received it, and is managed there like
any SMS: `wwandctl sms <modem> ME`, the LuCI SMS list, the `sms` event. A
full store answers the network with RP-ERROR cause 22, and it delivers
again later. Raw Write of an SMS-DELIVER measured on the RG502Q (NR7101,
2026-11-21): accepted, stored as MT read, Modify Tag makes it unread; AT
CMGW not measured.
wwand's `modem_sms_send` goes over IMS while the UE has `smsip` on and is
registered (the plugin's `sms_send` hook -> sipd's ubus `sms_send`).

Open, to be measured with `option sip_trace` before anything relies on it:
the response the network expects for an MT MESSAGE (200 is sent), the
Request-URI of an MO MESSAGE (`tel:<SC>` unless a profile sets `sms_psi`),
whether the delivery report must carry more headers, and the SC (profile
`sms_smsc`, else the one an SMS came from, else `AT+CSCA?`). With one
number on several SIMs (§5.6) the network may deliver the SMS to the
router instead of the phone once `smsip` is registered.

### 5.8 Forwarded calls (2026-11-21, not measured yet)

A call forwarded to the router's number (CDIV, TS 24.604) carries the
diversion in `History-Info` (RFC 7044): one entry per hop, the new target of
a diversion with the RFC 4458 `cause` URI parameter, its parent (`index`
minus the last component) the diverting user. sipd passes the header to the
LAN as it came and adds `Diversion` (RFC 5806) for phones and PBXs that read
that one (`sip.uc` `history_info` / `diversions`, the cause mapping of RFC
6044: 302 unconditional, 486 user-busy, 408 no-answer, 480/487 deflection,
503 unavailable, 404 unknown); a `Diversion` of the network's own is passed
instead. No filtering: the network applies `Privacy: history` itself.
Open: what Telekom sends for a landline forwarded to the mobile number.

### 5.9 Kernel crypto: MT7621's EIP-93 (2026-11-21)

Vodafone DE's P-CSCF offers sec-agree only as `hmac-sha-1-96` +
`aes-cbc`. On the NR7101 (MT7621, OpenWrt 25.12, kernel 6.12) every such
SA failed with EINVAL: the EIP-93 driver (`crypto_hw_eip93`, the old MTK
driver of ramips patch 860) registers `authenc(hmac(sha1|md5|sha256),
cbc(aes))` at priority 1500, above the software ones, and rejects every
key for them (`ip xfrm state add … auth-trunc hmac(sha1) … enc cbc(aes)`
fails in transport and tunnel mode, IPv4 and IPv6; the same with the
module unloaded works). charon's tunnel (`hmac(sha2_512)`, which the
driver lacks) was never affected.

Runtime fallback (`ue/kcrypto.uc`): sipd probes the encrypted
combinations it offers at start (an SA on 2001:db8::/32 for an instant);
EINVAL with a known faulty module loaded unloads it (`rmmod`), the
kernel's software crypto takes over. A registration that still meets
EINVAL runs the same check; a module the VoWiFi tunnel holds goes after
the tunnel is taken down. The module comes back at the next boot, where
the check runs again.

**TODO (later):** fix the driver instead — find where the setkey of the
authenc combinations returns EINVAL (`mtk_aead_setkey` /
`mtk_authenc_setkey` in ramips patch 860; OpenWrt main has the upstream
`inside-secure/eip93` driver, which may not have the bug), carry the fix in
our images and offer it upstream; then the fallback only covers images
without it.

## 6. Test device

The Chateau, with two modems. Until 2026-11-19 the RG650E (newest firmware
and MBNs, QMI) carried the IMS PDN on a mux channel next to its data PDN.
Since then the roles are split: the RG650E carries data on the Telekom card
(whose subscription has no IMS: the network refuses the `ims` PDN with ESM
cause 33), and the Huawei E392 (`wwmodem1`) is the **IMS-only modem** with
the GDSP SIM — the IMS PDN (`ims.iot`) is its only PDN, the UE registers and
calls work. What that modem needed:

- **USIM access:** its QMI UIM service has Send APDU but no logical channel
  message, and its AT port no `CCHO`/`CGLA`. wwand's `qmi_apdu` transport
  (core 3488705) opens the channel by hand; `ue/aka.uc` is unchanged.
- **No mux:** raw_ip without QMAP, so one PDN and one `proto wwand`
  interface on the modem, without `mux_id`.
- **MTU:** the PDN's path MTU is about 1450 and the network signals none;
  with wwand's 1500 the first fragment of the REGISTER is lost. `option mtu
  '1400'` on the IMS interface. SIP over TCP for large requests is not built.
- **No modem settings:** the stick has no IMS of its own to switch off and
  no MBN; `wwandctl ims check`/`fix` have nothing to do on it, the profile is
  a `config ims_profile` matched by IMSI.

The EG25-G on the Pi is the second choice (voice path well documented). The
NR7101 is out: its IDEMIA card must stay.

## 7. Open questions

- Licence: integrating mcfg_tools makes the C part GPL-3.0. wwand is
  GPL-2.0-only; a separate package with its own binaries is fine, but the
  package licence has to say so.
- Portal: is the SIM in a VoLTE service profile (GHLR `…VoLTE_PR`,
  `ims.iot` as the second APN, data APN as the default HSS APN)?
- Voice VPN: which numbers are allowed for a test call?
- Emergency calls through the LAN phone: required or not?

## 8. Sources

- The internal Vodafone IoT Voice docs: "Product description IoT Voice and
  VoLTE" (v1.1, 2023-04) and "Vodafone IoT 90128 Variant Settings.xlsx".
  Both are internal and not part of this repo.
- libqmi 1.38, libmbim 1.32 (OpenWrt build tree, read 2026-11-13).
- Our own HW measurements as named above.
- Audio paths (section 5.3): Quectel RM520N Series Hardware Design
  (PCM pins EU-only), Quectel RG520N Hardware Design (PCM + I2S), Quectel
  "RM520N-GL Voice over ttyUSB Application Note V1.0", Quectel forum
  34404 (RM520N data-only), Fibocom FM350-GL Hardware Guide V1.0.8 and
  its docomo certification (CS Voice/VoLTE not supported), Qualcomm
  patent US2019/0251056 (audio over PCIe).
- No Qualcomm-confidential material, by rule.
