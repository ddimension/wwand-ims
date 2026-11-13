# wwand-ims

VoLTE for a LAN SIP phone through a cellular modem managed by
[wwand](https://github.com/ddimension/wwand). A separate source package, not
for upstream: the wwand core stays free of voice code.

**Status: early.** No package yet. What exists:
- the design (`docs/design.md`) and the configuration model
  (`files/wwand_ims.config`);
- the wwand plugin `plugins/ims.uc`: IMS registration and service state,
  network IMS voice support and call control over QMI (IMSA, IMS, NAS,
  Voice; libqmi 1.38), as `ubus call wwand modem_plugin
  '{"modem":"…","plugin":"ims","op":"status|calls|dial|answer|hangup"}'`.
  Tests: `sh tests/run.sh`;
- a read-only EFS snapshot tool (`tools/efs-dump.sh`) and the snapshots
  taken with it (`research/`).

Where it stands on the hardware (RG650E-EU on the Chateau, Vodafone Global
IoT SIM, 2026-11-13): IMS registers and reports voice available, but the
module refuses every outgoing call internally. Details in
`research/rg650e-245/NOTES.md`.

## The idea in one paragraph

The modem's own IMS stack registers with the operator and carries the call
(SIP, IMS-AKA, IPsec, AMR-WB). The router does the parts a modem cannot:
it gives the modem the operator settings it lacks, which is the "missing MBN"
problem every IoT customer runs into, and it bridges a plain SIP phone on the
LAN to the modem's call control and audio. The operator settings live in
profiles in a configuration file of their own, selected by the SIM. A new IoT
operator is then a new profile and no new code.

## Layout

| Path | Language | What |
|---|---|---|
| `plugins/ims.uc` | ucode, inside the wwand daemon | IMS state and call control over QMI (exists); applying a profile to the modem (planned) |
| `src-ucode/sipd.uc` | ucode | SIP registrar + B2BUA for the LAN phone(s) |
| `src/mediad/` | C | RTP/RTCP to and from the modem's PCM audio, G.711/G.722, jitter buffer |
| `src/mcfg/` | C | MBN (MCFG) inspection; only the SHA-2 part exists so far |
| `tools/` | sh | snapshots and diffs of the modem's EFS items |
| `files/` | | example config, init script |

## Licence

Open question, see `docs/design.md`, "Licence".
