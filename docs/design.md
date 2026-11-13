# wwand-ims — design

_Draft of 2026-11-13. Nothing here is implemented yet._

## 1. Who speaks IMS

**The modem does.** Qualcomm modem firmware carries a complete IMS client
(SIP, IMS-AKA, IPsec sec-agree, AMR/AMR-WB, preconditions, SRVCC). What
it lacks for an IoT operator is that operator's settings. The Vodafone
IoT Voice guide (v1.1, April 2023, §3.8) says so: the settings come in a
carrier MBN, consumer and most IoT modules do not carry the Vodafone
90128 one, and the generic defaults "almost never" work.

A host-side IMS client was considered and rejected. It would need IMS-AKA
through the SIM, IPsec through kernel xfrm and AMR-WB transcoding, and the
modem's own IMS would have to be switched off. Emergency calls would then
be ours to get right. All of that is what the modem already does and the
operator has already tested.

So wwand-ims does two things:

1. **Brings the operator settings into the modem**, from a profile
   (section 3). That is the "missing MBN" problem.
2. **Bridges a LAN SIP phone** to the modem's call control (QMI Voice) and
   audio (PCM over USB, or over the module's PCM pins — see section 5.3).

## 2. Components

| Component | Runs | Talks to |
|---|---|---|
| `plugins/ims.uc` | in the wwand daemon (wwand plugin API, `plugins.uc`) | QMI VOICE/IMSA/IMS/WDS/NAS/PDC on the modem; `status` row; ubus ops `dial`, `answer`, `hangup`, `dtmf`, `apply_profile`; events `call`, `ims` |
| `sipd.uc` | own procd service | LAN phones (SIP/UDP+TCP); the plugin over ubus |
| `mediad` (C) | own procd service, started per call | RTP to the phone; PCM from and to the modem (UAC via ALSA, or the QPCMV tty) |
| `mcfg` (C) | CLI, called by the plugin | MBN files: unpack, patch items, pack, hash |
| `tools/efs-dump.sh` | CLI | modem EFS items, read-only |

What the wwand core may need (neutral, no voice code):
- a plugin hook that hands out a QMI client for a given service on a modem
  (check what `deps` already offers);
- a guarantee that the attach-profile code never touches the IMS profile
  (profile 2 on the RG650E), backed by a test.

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

## 6. Test device

The Chateau's RG650E (newest firmware and MBNs, QMI). The GDSP SIM needs
slot 1, which holds the Telekom card that serves as the internet fallback;
proposal: move the Telekom card to the E392 (`wwmodem1`, currently
unplugged). The EG25-G on the Pi is the second choice (voice path well
documented). The NR7101 is out: its IDEMIA card must stay.

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
