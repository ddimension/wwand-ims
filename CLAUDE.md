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
| `ue/secagree.uc` | Security-Client/-Server/-Verify, ESP keys (TS 33.203 Annex I), the four SAs + policies (7.1), apply/remove/reserve over the xfrm module |
| `src/xfrm/` | C ucode module `wwand_ims_xfrm` (NETLINK_XFRM: alloc_spi, sa_add/del, policy_add/del, error) |
| `plugins/ims.uc` | wwand plugin, runs **inside the wwand daemon**: IMS state, call control over QMI (IMSA, IMS, NAS, Voice) — the modem-IMS backend. `ubus call wwand modem_plugin '{"modem":…,"plugin":"ims","op":"status\|calls\|dial\|answer\|hangup"}'`; installed at `/usr/share/ucode/wwand/plugins/ims.uc` |
| `ctl/mcfg.uc` | the MCFG carrier config in an MBN: parse, set an EFS item, repack, renew the segment digests (the signature stays the base's). Installed as `/usr/share/ucode/wwand/ims_mcfg.uc`, used by `wwandctl ims mbn` |
| `ctl/ims.uc` | `wwandctl ims [modem] check \| fix \| setup \| mbn`: what the router's own UE needs (VoLTE FGIs, the modem's IMS off, the IMS profile from the MBN) and the router side (IMS PDN, VRF, firewall, sipd line); `files/wwand-ims-setup` is `setup` as a script. Installed at `/usr/share/ucode/wwand/ctl/ims.uc` |
| `sipd/` | `sipd.uc` (entry), `core.uc`, `sip.uc`: SIP registrar + B2BUA for LAN phones or a PBX trunk. Reads `/etc/config/wwand_ims`. Backend `ue` (`ims_modem` option `backend`): `line_ue.uc` (the router's own IMS UE as the line: registration, refresh, MO/MT), `relay.uc` (RTP 1:1 between LAN and the IMS VRF); backend `qmi`: the plugin's call control |
| `src/mcfg/` | C, MBN (MCFG) inspection; only SHA-2 so far |
| `files/` | `wwand_ims.config` (the config model / profiles), `wwand-ims-sipd.init` (procd), `ims-network.example` (IMS PDN in its VRF + firewall), `wwand-ims-l3mdev.hotplug` (restores the l3mdev rules netifd flushes), `asterisk-pjsip.example` (sipd as an Asterisk trunk) |
| `tools/` | `efs-dump.sh` (read-only EFS snapshots), `calltest.sh`, `sipcall.uc`, `eg25-voice.uc`, `diag-trace/` (modem F3/SIP tracing over adb), `ims-register.uc` (the UE spike driver: register, call, answer, echo), `rtp-amrwb2wav.py`, `install-sipd.sh`, `qmi-idl-dump.py` (QMI ids and widths from a vendor `libqmiservices.so`), `qmi-libqmi-audit.sh` (every schema id libqmi 1.38 lacks) (lays sipd out for the init script until there is a package) |
| `research/` | per-device notes and EFS snapshots (`rg650e-245/`, `eg25-rpi/`, `op8t-20261113/`) |
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
Core changes go into **`../wwand-ims-core`**, a git worktree of `../wwand`.
The old `ims-pcscf` branch was collapsed into `main` and deleted (2026-11-15),
so this worktree now sits on a **detached HEAD at `main`'s tip** (it cannot
hold `main` itself — the colleague's `../wwand` has it). A colleague works in
`../wwand` itself: never edit, stage or commit there. Keep current with
`git fetch && git checkout --detach origin/main`. Commits land on `main` only
when the user asks: commit on the detached HEAD and `git push origin HEAD:main`
(fast-forward), or make a short-lived branch for the change. Run the tests here
against it with `WWAND_SRC=../wwand-ims-core/src-ucode sh tests/run.sh`, and
hwtest with `hwtest/run.sh -r ../wwand-ims-core` (or a `git archive` of a commit).

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
  `docs/qmi-beyond-libqmi.md` (the plugin's) or `../wwand-ims-core/docs/
  qmi-beyond-libqmi.md` (the core's); `tools/qmi-libqmi-audit.sh` finds them.
  New decoders get a test with a hand-built wire buffer.
- **EFS/NV is read-only** unless the user explicitly says otherwise. The EFS
  offsets in `research/*/NOTES.md` are hypotheses from diffs. Confirm them
  against official documentation before anything writes. If a test switches
  the MBN, restore the modem afterwards (MBN, `AutoSel`) and note it in the
  research notes.
- Namespaced imports, no hyphens in module paths (the wwand bytecode build
  enforces both).
- The licence is still open (mcfg_tools would make the C part GPL-3.0; the
  ucode parts are GPL-2.0-only), see `docs/design.md` §7.

## Tests
`sh tests/run.sh` runs all of them, and they must be green before every
commit. `nstest_*.uc` run under `unshare -rn` against the real kernel
(xfrm), with UE/P-CSCF stand-in addresses on lo; skipped with a note where
unprivileged user namespaces or `xfrm_user` are missing. It symlinks `tests/wwand` to `../wwand/src-ucode` (override with
`WWAND_SRC`) and uses the host ucode `~/.local/bin/ucode`. A change to the
wwand codec or plugin API can break these tests, so run them after changes
in `../wwand` as well.

## State
Hardware status and findings: `research/rg650e-245/NOTES.md` (RG650E on the
Chateau: IMS registers and voice reports available, but the module refuses
outgoing calls internally) and the research commits. The EG25-G on the Pi
has working voice over USB/UAC.
