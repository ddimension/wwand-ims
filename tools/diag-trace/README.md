# Modem IMS F3 tracing over adb (RG650E / SDX75 "pinnacle")

Captures the modem's own F3 debug messages (the Qualcomm IMS/MMTEL/DPL stack
logs) so the voice-provisioning decision can be read directly, rather than
inferred from QMI/EFS. Built for the A05 VoLTE-voice regression
(research/rg650e-245/NOTES.md).

## Why this shape

- The modem's IMS logic runs on the **mpss (Hexagon)**; it is not visible over
  QMI/AT. Its reasoning is in **F3 (extended debug) messages**.
- The modem's **USB diag** interface (ffs-diag) is **Secure-Diag gated**: an
  external host that sets message masks gets an RSA challenge
  (`-----BEGIN RSA PUBLIC KEY-----`) instead of F3 — needs Quectel's signing
  key. So the external-USB path (scat `-u`/`-T`) yields NAS/LOG packets but no
  F3.
- The **on-target `diag_mdlog`** (run via `adb` on the apps PD) is a trusted
  diag client and is **not** challenged: with a message mask it captures full
  mpss F3. This is the path that works.

## Pieces

- `genmask.py` — generates a `diag_mdlog -f` mask file that enables **all F3
  message levels** for every SSID range the modem reports. The mask file is
  simply the HDLC-framed `DIAG_EXT_MSG_CONFIG` (0x7D, subcmd 0x04) set-mask
  request packets concatenated (built with scat's `diagcmd`/`util`). diag_mdlog
  reads it ("Reading the mask file", no "could not find valid commands") and
  applies it. Output already generated as `f3-allmsg.cfg`.
- `f3-allmsg.cfg` — the ready mask (29 SSID ranges, all levels 0xFFFFFFFF).
- `diagrelay.py` — optional: a transparent USB-diag<->TCP relay on the box the
  modem is attached to, so **scat** can drive masks + QSR4 decode live over
  `-T host:43555`. Only useful for NAS/LOG (secure-diag blocks F3 here); kept
  because it is the live-decode path and the relay itself is reusable.

## Capture (on the Chateau, modem via adb as `SERIAL`)

    # 1. QSR4 message DB (needed to decode F3 hashes) — pull once:
    adb shell "cp /firmware/image/pinnacles/qdsp6m.qdb /tmp/qdsp6m.qdb"
    adb exec-out "cat /tmp/qdsp6m.qdb" > qdsp6m.qdb     # 7.5 MB, UUID 538f56cb-...

    # 2. push the mask, capture across the event of interest (CFUN cycle, call):
    adb push f3-allmsg.cfg /tmp/diag.cfg                # raw copy; the box has no base64
    adb shell "rm -rf /tmp/mdlog; mkdir -p /tmp/mdlog; \
               diag_mdlog -f /tmp/diag.cfg -o /tmp/mdlog & MP=$!; sleep 42; kill $MP"
    # (the modem busybox has no setsid/nohup; keep the adb shell alive for the
    #  whole window. Trigger IMS re-reg with AT+CFUN=0 then AT+CFUN=1 on the AT
    #  port — wwand stopped — which does NOT re-enumerate USB.)
    adb exec-out "cat /tmp/mdlog/*.qmdl" > cap.qmdl

## Decode (workstation, scat at /home/avalentin/projects/scat)

    scat -t qc -d cap.qmdl --qsr4-hash qdsp6m.qdb --msgs -F cap.pcap
    tshark -r cap.pcap -V | grep "GSMTAP libosmocore logging" \
      | sed 's/.*logging ([0-9]*): //' > trace.txt     # ordered file.c:line message

NOTE scat's `util.snprintf` crashes on a C integer precision spec (e.g. `%.3d`)
in a QSR4 format string ("Precision not allowed in integer format specifier").
Local fix applied in scat `util.py` snprintf: map a `.N` precision on
d/u/x/X/p to a zero-padded width. Carry this patch if scat is reinstalled.

## What it showed (A05, 2026-11-14)

The IMS registration advertises only `+g.3gpp.smsip` (+ OptionsEnabler,
RegManager) — **no MMTEL voice feature tag** — so IMSA reports voice
unavailable. `/nv/item_files/ims/MediaProfiles` reads ENOENT;
`qp_ims_service_enablement_config` is read **and rewritten** by the engine
(`qpIO.c` GetItem+PutItem), confirming it is an engine output, not an input
gate. The `rr_nv.c:4123 "Voice calls are disabled by NV"` line is GERAN/2G CS
voice (SSID 4009), a red herring. Full analysis in
`research/rg650e-245/NOTES.md`.
