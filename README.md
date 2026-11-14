# wwand-ims

VoLTE for a LAN SIP phone through a cellular modem managed by
[wwand](https://github.com/ddimension/wwand). A separate source package, not
for upstream: the wwand core stays free of voice code.

**Status: early.** No package yet. What exists:
- the design (`docs/design.md`) and the configuration model
  (`files/wwand_ims.config`);
- the first parts of a router-side IMS UE (`ue/`, `src/xfrm/`): IMS-AKA
  through the card and sec-agree over netlink, host-tested;
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
| `ue/aka.uc` | ucode | IMS-AKA: USIM AUTHENTICATE over wwand's APDU channel, Digest AKAv1-MD5, identities from the IMSI |
| `ue/secagree.uc` | ucode | sec-agree (TS 33.203): headers, ESP keys, the four SAs and their policies |
| `src/xfrm/` | C | ucode module `wwand_ims_xfrm`: SAs and policies over NETLINK_XFRM |
| `plugins/ims.uc` | ucode, inside the wwand daemon | IMS state and call control over QMI (the modem-IMS backend) |
| `sipd/` | ucode | SIP registrar + B2BUA for the LAN phone(s) |
| `src/mcfg/` | C | MBN (MCFG) inspection; only the SHA-2 part exists so far |
| `tools/` | sh, ucode, python | EFS snapshots, call tests, modem F3 tracing |
| `files/` | | example config, init script |

Since 2026-11-14 the router is the IMS UE itself and the modem only
carries the IMS PDN and lends the card (`docs/design.md`, section 1).
Tests: `sh tests/run.sh`; the `nstest_*` ones run against the real kernel
in a user + network namespace of their own.

## Licence

Open question, see `docs/design.md`, "Licence".
