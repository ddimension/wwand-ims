# wwand-ims — guide for Claude

wwand-ims is a **child project of wwand** (source tree `../wwand`). It's a
separate source package and **not for upstream**: VoLTE for a LAN SIP phone
through a cellular modem (since 2026-11-14 with an IMS UE of its own on the
router). The wwand core stays free of voice code.
Everything IMS-specific lives here.

Read the workspace guide `../CLAUDE.md` and the wwand repo guide
`../wwand/CLAUDE.md` first. Their rules apply here too (English, commit/push
only when asked, test devices only from `../test-devices.txt`, restore the
Chateau internet fallback after every test, never reboot 246 on your own).

## Direction (2026-11-14)
The router is the IMS UE itself; the modem carries the IMS PDN and lends
the USIM (APDU), its own IMS goes off. MBN = source for profiles (import +
override), codecs passed through 1:1 (no transcoding), sec-agree over
NETLINK_XFRM (**never the `ip xfrm` CLI** in code — tests may read it back),
IMS in its own VRF / routing table, no emergency calls yet (refuse them
audibly). VoWiFi/strongSwan = phase 2. Details and phases:
`docs/design.md` sections 1, 2, 2a.

## Layout
| Path | What |
|---|---|
| `ue/aka.uc` | USIM AUTHENTICATE over `wwand modem_apdu` (own logical channel, T=0 61xx/6Cxx), AUTS, Digest AKAv1-MD5 nonce, IMPI/IMPU from the IMSI |
| `ue/call.uc` | one outgoing call (UAC): INVITE in the SAs, PRACK, ACK, BYE/CANCEL, emergency numbers refused |
| `ue/regevent.uc` | the UE's reg-event subscription (RFC 3680): SUBSCRIBE in the SAs, the reginfo NOTIFYs, what they mean for our own binding (terminated, shortened) |
| `ue/smsip.uc` | SMS over IP (TS 24.341): the RP layer (TS 24.011: RP-DATA/ACK/ERROR), MT MESSAGE -> 200 -> wwand's `modem_sms_deliver` (written into the modem's store, `ims_modem` option `sms_storage` ME/SM) -> RP-ACK/RP-ERROR to the SC, MO RP-DATA per part -> 202 -> the network's RP-ACK; on with `ims_modem` option `smsip`, `wwand modem_sms_send` reaches it through the plugin's `sms_send` hook and sipd's ubus `sms_send` |
| `ue/kcrypto.uc` | can the kernel do the encrypted sec-agree SAs we offer? A probe SA per combination (2001:db8::/32); EINVAL with a known faulty crypto driver loaded (MT7621's `crypto_hw_eip93`) unloads it (`rmmod`), sipd retries for 15 s (the xfrm GC frees a tunnel's SAs late) and starts the VoWiFi tunnel only after that. TODO: fix the driver instead (docs/design.md 5.9) |
| `ue/reader.uc` | a SIM card without a modem (`ims_modem` option `card`): wwand-rsim's `rsim-card` (JSON lines, T=0 61xx/6Cxx resolved), ICCID/IMSI/MNC length read from the card, the AKA card interface, `card_apdu` for charon's ext-aka through sipd (`vowifi/card.uc` falls back to it when no modem has the IMSI); VoWiFi only |
| `ue/secagree.uc` | Security-Client/-Server/-Verify, ESP keys (TS 33.203 Annex I), the four SAs + policies (7.1), apply/remove/reserve over the xfrm module |
| `src/xfrm/` | C ucode module `wwand_ims_xfrm` (NETLINK_XFRM: alloc_spi, sa_add/del, policy_add/del, error) |
| `plugins/ims.uc` | wwand plugin, runs **inside the wwand daemon**: IMS state, call control over QMI (IMSA, IMS, NAS, Voice) — the modem-IMS backend. `ubus call wwand modem_plugin '{"modem":…,"plugin":"ims","op":"status\|calls\|dial\|answer\|hangup"}'`; installed at `/usr/share/ucode/wwand/plugins/ims.uc` |
| `ctl/mcfg.uc` | the MCFG carrier config in an MBN: parse, set an EFS item, repack, renew the segment digests (the signature stays the base's). Installed as `/usr/share/ucode/wwand/ims_mcfg.uc`, used by `wwandctl ims mbn` |
| `ctl/diag.uc` | ES module `ims_diag` (bytecode, `/usr/share/wwand-ims/ims_diag.uc`): read-only EFS file read over the modem's DIAG port (HDLC, EFS2 subsystem 0x13/0x3E: HELLO, STAT, OPEN, READ, CLOSE — no write command exists in it), any Qualcomm modem; not while QLog holds the port |
| `ctl/iwlan.uc` | ES module `ims_iwlan`: the carrier config's `/data/iwlan_s2b_config.xml` (read from `--mbn FILE`, `AT+QNVFR`, else DIAG) -> `vowifi_*` profile options; used by `setup` (through the plain `ctl/iwlan_lazy.uc`, since `ctl/ims.uc` is require()d and require() reads source only) and sipd's `profile_snapshot` (LuCI *Clone current settings*) |
| `ctl/ims.uc` | `wwandctl ims [modem] check \| fix \| setup \| mbn`: what the router's own UE needs (VoLTE FGIs, the modem's IMS off, the IMS profile from the MBN) and the router side (IMS PDN, VRF, firewall, sipd line, the VoWiFi interfaces); `setup` is idempotent — run again it adds missing sections and list entries, options that differ only with `--force`; `files/wwand-ims-setup` is `setup` as a script. Installed at `/usr/share/ucode/wwand/ctl/ims.uc` |
| `sipd/lines.uc` | several IMS lines: every `ims_modem` section is a line with an sipd instance of its own (`--line`); what a line uses (interface, VRF/zone, tables, VoWiFi names/if_id/connection, SIP port, RTP range, reqids, files, ubus objects `wwand-ims.<modem>`) derived from its position, the first keeps the old names; `ims_sim` (by ICCID) overrides per card; extensions per line (option line). `setup` derives the same (via `ims_iwlan_lazy`) |
| `sipd/` | `sipd.uc` (entry), `core.uc`, `sip.uc`: SIP registrar + B2BUA for LAN phones or a PBX trunk. Reads `/etc/config/wwand_ims`. Backend `ue` (`ims_modem` option `backend`): `line_ue.uc` (the router's own IMS UE as the line: registration, refresh, MO/MT), `relay.uc` (RTP 1:1 between LAN and the IMS VRF, and the watchdog that ends a call whose media died), `profile.uc` (`config ims_profile`: the one for the SIM by `match_imsi` / `match_iccid`, its values for the UE — SIP timers, expiry, sec-agree algorithms, transport, User-Agent, reg-event, media timeouts); backend `qmi`: the plugin's call control. A forwarded call: the network's History-Info to the LAN, Diversion made from it (`sip.uc`, `sip_gateway` option `redirect_info`) |
| `luci/` | the separate package `luci-app-wwand-ims` (feed Makefile): `view/wwand/ims-status.js` (Status → VoLTE: registration, phones, the running call, the last 10 calls from `ubus call wwand-ims status\|calls`, which sipd publishes), `view/wwand/ims-config.js` (Network → VoLTE: `/etc/config/wwand_ims`), `wwand/imsfmt.js` (pure helpers, `luci/tools/test-imsfmt.js` under node, run by `tests/run.sh`); *Clone current settings* in the profile list calls sipd's `profile_snapshot` |
| `vowifi/` | the package `wwand-ims-vowifi` (VoWiFi, `ims_modem` option `access 'vowifi'`): `vici.uc` (strongSwan's vici protocol, charon driven over it only, no swanctl.conf), `tunnel.uc` (TS 23.003 names, the load-conn tree, P-CSCF from charon's log), `ctl.uc` (load-conn + initiate over vici, kept up with backoff on IKE/CHILD down and charon restarts, charon's log to syslog, renews the netifd interface that takes the inner address — the XFRM interface is netifd's `proto xfrm`, addresses/routes via `files/vowifi-proto.sh` `proto wwandvowifi` into table 31, **no VRF**: netifd 25.12 disables IPv6 on VRF ports; both interfaces are netifd dynamic ones sipd creates at run time, `net_specs`, the XFRM one with `zone ims` for firewall4; only the controller re-establishes the tunnel, charon's dpd/close actions are clear/none; `access()` for line_ue binds to the XFRM interface), `card.uc` + `ext_aka.uc` (the program strongSwan's ext-aka plugin runs: AUTHENTICATE on the modem's USIM), `cli.uc` (`wwand-ims-vowifi up|down|status`), `lazy.uc` (what sipd require()s) |
| `src/mcfg/` | C, MBN (MCFG) inspection; only SHA-2 so far |
| `CMakeLists.txt` | the package build: what ships under which installed name, bytecode for the ES modules and programs (wwand's approach, with a source fallback). **A new `.uc` under `plugins/ ctl/ sipd/ ue/ tools/ vowifi/` must be listed there** (or as unshipped) — the configure fails otherwise |
| `files/` | `wwand_ims.config` (the config model / profiles), `wwand-ims-sipd.init` (procd), `ims-network.example` (IMS PDN in its VRF, firewall; VoWiFi needs no sections), `vowifi-proto.sh` (netifd `proto wwandvowifi`), `vowifi-strongswan.conf` (charon plugins: P-CSCF request, epdg-idr, for our connections only), `vowifi-strongswan-ike.conf` (charon: IKE retransmissions, so a dead tunnel is found within ~50 s), `vowifi-ext-aka.sh` / `wwand-ims-vowifi.sh` (wrappers), `wwand-ims-l3mdev.hotplug` (restores the l3mdev rules netifd flushes), `asterisk-pjsip.example` (sipd as an Asterisk trunk) |
| `tools/` | `efs-dump.sh` (read-only EFS snapshots), `calltest.sh`, `sipcall.uc`, `eg25-voice.uc`, `diag-trace/` (modem F3/SIP tracing over adb), `ims-register.uc` (the UE spike driver: register, call, answer, echo), `rtp-amrwb2wav.py`, `install-sipd.sh`, `qmi-idl-dump.py` (QMI ids and widths from a vendor `libqmiservices.so`), `qmi-libqmi-audit.sh` (every schema id libqmi 1.38 lacks) (lays sipd out for the init script until there is a package) |
| `research/` | per-device notes and EFS snapshots (`rg650e-245/`, `eg25-rpi/`, `op8t-20261113/`). **Local only, in `.gitignore`**: it holds SIM identifiers, traces and vendor material and is never committed (removed from the history 2026-11-15). Real IMSIs, ICCIDs, phone numbers and device serials stay out of code, tests and docs as well |
| `docs/design.md` | design, phases, profile mapping (GDSP), the MBN problem, measurements, open questions (licence!) |
| `docs/qmi-beyond-libqmi.md` | every QMI id the plugin uses that libqmi 1.38 lacks, with source and measurement; what is still on AT and why |

ucode has **no function hoisting** and a `let f = () => f()` cannot refer
to itself: declare first (`let f; f = …`). A closure does not see a `let`
declared later in the same scope either (names resolve at compile time):
declare helpers above the closures that call them. Its regex is POSIX (no `(?:`).
In C modules, `ucv_string_get(v)` is a macro over `&v`: a short string (≤7
bytes) lives inside the value, so never return that pointer from a helper
whose local holds `v` (copy it, see `field_str` in `src/xfrm`).

## wwand core work
Core changes are made and committed in **`../wwand`** on `main` (since
2026-11-19, as the workspace guide says): `git fetch && git merge --ff-only
origin/main`, commit, `git push origin main` — only when the user asks.
Other sessions work in the same tree at the same time, so it usually holds
uncommitted changes that are not yours: stage your own hunks only (never
`git add -A` or a whole file somebody else also touched), and leave the rest
as it is. `../wwand-ims-core`, the git worktree this project used before, is
the colleague's now: **never edit, stage or commit there.** `../wwand/x` is
never touched.

The tests here run against `../wwand/src-ucode` by default (`WWAND_SRC`
overrides it), hwtest with `hwtest/run.sh -r ../wwand` (or a `git archive` of
a commit). `tests/.build/io` is a cmake build of that tree's `io/`: after
pointing `WWAND_SRC` at another tree, remove it, or cmake refuses the cached
source directory ("wwand_io module build failed").

## Build project
`/vol/release/wwand-ims/` (README there): out-of-tree builds, host and
later cross. `tests/run.sh` builds `src/xfrm` into
`/vol/release/wwand-ims/build-host/xfrm` when that folder exists.

## Plugin contract
The plugin API is defined in wwand: `../wwand/src-ucode/plugins.uc` (a plugin
is a plain script under `/usr/share/ucode/wwand/plugins/<name>.uc` and
exports `ops: { <op>: (ref, ext, args, cb) }`). The ubus side is
`modem_plugin` / `modem_plugin_status` in `../wwand/src-ucode/ubus.uc`. The
plugin opens its QMI clients through `deps.qmi_client` on the modem's own
channel. It never takes the control device away from the daemon (a remote
SIM from wwand-rsim must stay up). If this plugin needs something the core
doesn't offer yet, add a **generic** hook in wwand. Don't put IMS code there.

## Invariants
- **QMI messages/TLVs: libqmi 1.38 first** (recommendation, since
  2026-11-15 no longer a hard rule): prefer what
  `data/qmi-service-*.json` and the `qmi-enums-*.h` define. Where libqmi
  lacks a message or TLV, another source is allowed: the Qualcomm IDL
  tables in a shipping RIL's vendor libraries (`libqmiservices.so`), the
  documents under `~/projects/wwand-ims-docs`, observed RIL traffic. A
  wrong id decodes garbage without any error, so such an id names its
  source in a code comment, is measured on hardware before it is relied
  on, and the code keeps a fallback. Every such id is listed in
  `docs/qmi-beyond-libqmi.md` (the plugin's) or `../wwand/docs/
  qmi-beyond-libqmi.md` (the core's); `tools/qmi-libqmi-audit.sh` finds them.
  New decoders get a test with a hand-built wire buffer.
- **EFS/NV is read-only** unless the user explicitly says otherwise. The EFS
  offsets in `research/*/NOTES.md` are hypotheses from diffs. Confirm them
  against official documentation before anything writes. If a test switches
  the MBN, restore the modem afterwards (MBN, `AutoSel`) and note it in the
  research notes.
- Namespaced imports, no hyphens in module paths (the bytecode builds of
  wwand and of this repo, `CMakeLists.txt`, enforce both).
- The licence is still open (mcfg_tools would make the C part GPL-3.0; the
  ucode parts are GPL-2.0-only), see `docs/design.md` §7.

## Tests
`sh tests/run.sh` runs all of them, and they must be green before every
commit. `nstest_*.uc` run under `unshare -rn` against the real kernel
(xfrm), with UE/P-CSCF stand-in addresses on lo; skipped with a note where
unprivileged user namespaces or `xfrm_user` are missing. `BYTECODE=1 sh
tests/run.sh` runs the suite against the modules compiled by `CMakeLists.txt`
(what the package ships); run it after touching a module's imports or exports. It symlinks `tests/wwand` to `../wwand/src-ucode` (override with
`WWAND_SRC`) and uses the host ucode `~/.local/bin/ucode`. A change to the
wwand codec or plugin API can break these tests, so run them after changes
in `../wwand` as well.

## Releases
Two lines, as in wwand (since 2026-11-16): `main` develops and carries the
marker tag `vX.Y.0-dev` of the minor it works on (`v0.2.0-dev`), `stable`
carries the releases, tagged `vX.Y.Z` there and nowhere else (first:
`v0.1.0`). A fix reaches stable by `cherry-pick -x` from main, or is made
there and merged up. The feed (`repository/wwand-ims/Makefile`) pins main on
its main and a stable tag on its stable, through `scripts/bump-source.sh
wwand-ims <ref>`. A release needs a wwand that has what the plugin uses:
v0.1.0 needs wwand 1.9.0 (the xfrm binding in `wwand_io.so`, `option ims`,
P-CSCF in the status).

## State
Hardware status and findings: `research/rg650e-245/NOTES.md` (RG650E on the
Chateau: IMS registers and voice reports available, but the module refuses
outgoing calls internally) and the research commits. Since 2026-11-19 the
Chateau's roles are split (`docs/design.md` §6): the RG650E carries data, the
Huawei E392 is the IMS-only modem with the GDSP SIM — the router's own UE
registers over it and calls work (USIM over wwand's `qmi_apdu` transport, one
PDN without a mux, `option mtu '1400'` on the IMS interface). The EG25-G on
the Pi has working voice over USB/UAC.
