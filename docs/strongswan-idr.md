# Proposal: send the APN as IDr, accept the ePDG's own identity (strongSwan)

Status: option A built (`src/strongswan/epdg_idr` in this repo, built out of strongSwan's tree; the feed packages it as `strongswan-mod-epdg-idr` — a patch to the feed's strongswan, 1001, until 6.0.7-r118) and HW-tested with Vodafone DE on the NR7101, 2026-11-21. Option B is still only a proposal. The plugin relaxes the identity for the lifetime of the peer config only: putting it back once the IKE_SA was up crashed charon, see the comment in the plugin.

## The problem

TS 24.302 7.2.2: the UE sends the APN (`ims`) as IDr in its first IKE_AUTH
request, and the ePDG answers with an IDr of its own, usually its FQDN.
Measured on the NR7101 (RG502Q, VoWiFi over the fixed line):

- **Vodafone DE** (262/02, ePDG `epdg.epc.mnc002.mcc262.pub.3gppnetwork.org`):
  without an IDr the first IKE_AUTH response is `N(10500) N(41041)`
  (NETWORK_FAILURE, BACKOFF_TIMER). With IDr `ims`, EAP-AKA on the USIM
  succeeds, the ePDG assigns an IPv6 address and two P-CSCFs (`CPRP(ADDR6
  PCSCF6 PCSCF6)`), and answers IDr `epdg.epc.mnc002.mcc262.pub.3gppnetwork.org`.
- **Telekom DE** (262/01): answers IDr `nai.epc.mnc001.mcc262.3gppnetwork.org`,
  and accepts a request without IDr — what `vowifi/tunnel.uc` does today.

charon then refuses the tunnel itself:

```
constraint check failed: identity 'ims' (ID_FQDN) required, not matched by
  'epdg.epc.mnc002.mcc262.pub.3gppnetwork.org' (ID_FQDN)
selected peer config 'wwand-vowifi' unacceptable: constraint checking failed
no alternative config found
```

strongSwan 6.0.7 has no setting for "send this IDr, accept another one":

- `remote.id` is both what is sent and what is required
  (`libstrongswan/credentials/auth_cfg.c` `complies()`, AUTH_RULE_IDENTITY).
- AUTH_RULE_IDENTITY_LOOSE (ipsec.conf's `%` prefix, charon-nm, charon-cmd;
  vici has no key for it) suppresses the IDr altogether
  (`libcharon/sa/ikev2/tasks/ike_auth.c` build_i: `!cfg->get(cfg,
  AUTH_RULE_IDENTITY_LOOSE) && idr && !idr->contains_wildcards(idr)`), and
  without a certificate it fails the constraint anyway.
- A second connection with `remote.id = %any` is never tried: alternative
  peer configs are collected only by the responder (`load_cfg_candidates()`
  is called from `process_r`); the initiator has no candidates (tried on the
  NR7101, 2026-11-21).

The ePDG is authenticated by EAP-AKA (mutual, RFC 5998 EAP-only, its AUTH
over the MSK), not by its identity: accepting its own IDr loses nothing.

## Option A (preferred): a plugin, `epdg-idr`, no change to charon itself

A listener plugin next to `ext-aka`, both in this repo's `src/strongswan`
and built against the feed strongswan's headers (its `Build/InstallDev`).

- Setting: `charon.plugins.epdg-idr.connections = wwand-vowifi` (a list of
  connection names), shipped in the existing
  `/etc/strongswan.d/charon/wwand-ims-vowifi.conf`. Nothing else changes for
  charon's other connections.
- `listener_t.message(ike_sa, message, incoming=TRUE, plain=TRUE)` is called
  for every decrypted message before `process_response()`
  (`task_manager_v2.c`). For an IKE_AUTH response of a listed connection
  that carries an IDr different from the configured `remote.id`, the plugin
  replaces AUTH_RULE_IDENTITY in the peer config's remote auth config with
  `%any` (`auth_cfg_t.replace()`), so the constraint check passes. The IDr
  that was sent and the ePDG's AUTH (computed over its own IDr) are
  untouched.
- No putting back: the built plugin leaves the peer config relaxed for its
  lifetime (restoring it from `ike_updown()` once the IKE_SA was up crashed
  charon, HW 2026-11-21). wwand-ims loads the connection anew (vici
  `load-conn`) before every attempt, so each attempt sends `ims` again; a
  restart charon makes on its own (DPD, close action) sends no IDr, which
  the ePDG refuses, and the controller then loads the connection again.
- Logged at level 1: "epdg-idr: accepted responder identity '…' instead of
  '…' (EAP-only)".
- Limits: it changes a shared peer_cfg for the time of one IKE_AUTH; with one
  connection per name (ours) and charon's own job queue that is safe, but
  two IKE_SAs of the same connection at once would race. It applies only to
  EAP-only remote auth (`remote.auth = eap-*`); with a certificate the
  plugin does nothing.
- Size: about 200 lines of C plus the plugin boilerplate; host-testable with
  strongSwan's own test framework only partly, the real test is an ePDG.

wwand-ims then sends the IMS APN as IDr by default (`vowifi_apn`, from the
IMS profile of the carrier config), for Telekom as well.

## Option B: a core patch, upstream material

A new auth rule (e.g. AUTH_RULE_IDENTITY_SEND_ONLY) and a vici/swanctl key
(`remote.id_send_only = yes`, or `remote.id_strict = no`): `ike_auth.c`
build_i sends the configured identity as IDr, `auth_cfg.c` complies() skips
the identity constraint for it. About 40 lines over vici_config.c,
auth_cfg.[ch], ike_auth.c and swanctl.opt; it is the clean fix and can go
upstream (IWLAN/ePDG clients all need it), but it touches libstrongswan's
auth rule enum (an ABI change for every plugin) and has to be carried until
upstream takes it.

## Recommendation

A now (it stays in its own plugin, like ext-aka, and needs no change to
charon's code paths), B as an upstream PR in parallel; once a strongSwan
release has B, the plugin goes and wwand-ims sets the vici key instead.
