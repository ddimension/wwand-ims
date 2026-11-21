# wwand-ims

VoLTE for a LAN SIP phone (or a PBX trunk) through a cellular modem managed by
[wwand](https://github.com/ddimension/wwand). A separate source package, **not
for upstream**: the wwand core stays free of voice code.

**Setup, usage, debugging, prerequisites and an Asterisk example are in the
wwand docs:
[docs/plugin-wwand-ims.md](https://github.com/ddimension/wwand/blob/main/docs/plugin-wwand-ims.md).**

## Status

The **router-UE path works end to end on hardware** (RG650E-EU on a MikroTik
Chateau, Vodafone, 2026-11-15): a full VoLTE MO call with two-way AMR-WB audio,
from the production apk. The router is its own IMS UE — it registers over the
modem's IMS PDN (IMS-AKA through the card, sec-agree ESP, SIP), the modem's own
IMS is switched off, and sipd relays RTP to the LAN. `wwandctl status` shows the
registration; `wwandctl ims call <number>` places a test call.

Since 2026-11-21 also on the NR7101 (RG502Q): **VoWiFi** — the same UE
through an IKEv2/EAP-AKA tunnel to the operator's ePDG over the fixed-line
WAN (package `wwand-ims-vowifi`): Telekom DE with incoming calls and audio,
Vodafone DE registered;
one number on two SIMs (MultiSIM) rings both devices; SMS over IP into the
modem's store; a LuCI app (`luci-app-wwand-ims`).

The alternative **modem-IMS backend** (`plugins/ims.uc`, backend `qmi`) drives
the module's own IMS over QMI; it is why the plugin exists, but on the RG650E
the module refuses every outgoing call internally — hence the router-UE
direction. Details: `docs/design.md`. (The per-device research notes are kept outside the published repository.)

## The idea in one paragraph

The router does the parts a plain SIP phone and a bare modem cannot: it gives
the modem the operator IMS settings it lacks — the "missing MBN" problem every
IoT customer hits — borrows the USIM over wwand's APDU channel to be the IMS UE
itself, runs the IPsec and SIP, and bridges the call and its AMR-WB audio to a
phone on the LAN. The operator settings live in profiles selected by the SIM, so
a new IoT operator is a new profile, not new code.

## Modem settings: the patched MBN is the way

The router UE needs the modem to report VoLTE support to the network (LTE FGI 3
and 7); without them the eNB sets up no voice bearer and every call fails.
There are two ways to set them, and they are not equal:

- **Patched carrier MBN (the way for a deployment):**
  `wwandctl ims [modem] mbn patch --upload` writes the settings into the
  modem's carrier configuration and loads it. That is where the modem keeps
  its operator settings itself, so this is the best way to make the needed
  settings persistent.
- **The AT FGI command (development only):** `wwandctl ims [modem] fix` sets
  the FGIs with the Quectel command `AT+QNWCFG="lte_fgi_fdd"`. It is quick for
  trying things out on a development modem and of no interest beyond that.

## Layout

| Path | Language | What |
|---|---|---|
| `ue/aka.uc` | ucode | IMS-AKA: USIM AUTHENTICATE over wwand's APDU channel, Digest AKAv1-MD5, identities from the IMSI |
| `ue/secagree.uc` | ucode | sec-agree (TS 33.203): headers, ESP keys, the four SAs and their policies, over wwand core's `wwand_io.so` `xfrm` binding |
| `ue/reg.uc`, `ue/call.uc`, `ue/regevent.uc` | ucode | the UE's registration, one call, and its reg-event subscription (the network ending the registration is noticed) |
| `plugins/ims.uc` | ucode, inside the wwand daemon | the modem-IMS backend: IMS state and call control over QMI |
| `ctl/ims.uc` | ucode (wwandctl) | `wwandctl ims check\|fix\|setup\|mbn\|call` — prepares the modem and the router |
| `sipd/` | ucode | SIP registrar + B2BUA; backend `ue` is the router's own IMS UE (operator profile by SIM, P-CSCF failover, RTP relay with a media watchdog, forwarding info to the LAN), backend `qmi` bridges to the plugin |
| `ue/smsip.uc` | ucode | SMS over IP (TS 24.341), stored in the modem through wwand |
| `vowifi/` | ucode | package `wwand-ims-vowifi`: the ePDG tunnel (strongSwan over vici, EAP-AKA on the USIM), kept up; netifd configures its interface |
| `luci/` | JavaScript | package `luci-app-wwand-ims`: status, call list, settings, operator profiles |
| `src/mcfg/` | C | MBN (MCFG) inspection (SHA-2 so far) |
| `tools/` | sh, ucode, python | the UE driver (`ims-register.uc`), call tests, EFS snapshots, modem F3 tracing |
| `files/` | | example config, init script, IMS-PDN + VoWiFi network/firewall example, the netifd proto `wwandvowifi`, Asterisk example |

The NETLINK_XFRM binding sec-agree needs lives in wwand core's own
`wwand_io.so` (sub-namespace `xfrm`); wwand-ims' earlier standalone C module
was dropped. Since 2026-11-14 the router is the IMS UE itself and the modem only
carries the IMS PDN and lends the card (`docs/design.md`, section 1).

## Build / test

`sh tests/run.sh` runs all suites; the `nstest_*` ones run against the real
kernel (xfrm) in a user + network namespace of their own. `BYTECODE=1 sh
tests/run.sh` runs them against the UE and sipd modules compiled to bytecode,
the way the package ships them. Core changes wwand-ims needs are made on
wwand's `main` (see `CLAUDE.md`).

`CMakeLists.txt` is the package build: it lays the shipped ucode files out
under their installed names (`build/ucode/wwand-ims/` → `/usr/share/wwand-ims`,
`build/ucode/wwand/` → `/usr/share/ucode/wwand`) and compiles the ES modules
and the two programs to bytecode with the given ucode (`-DUCODE_COMPILER=`;
the feed passes the SDK's). A ucode that cannot (older than 2026.07.09, as in
the openwrt-25.12 images up to 25.12.6) gets the sources, as does `-DUCODE_PRECOMPILE=OFF`. The require()d scripts (plugin,
`wwandctl ims`, `sipd_core`, `sipd_sip`, `ims_mcfg`) are always source.

## Licence

GPL-2.0-only (the ucode parts); the MBN C tooling would be GPL-3.0 and ships
as a separate package. Open question — see `docs/design.md`, "Licence".
