# QMI beyond libqmi 1.38 (wwand-ims)

libqmi 1.38 is the preferred source for QMI ids, but since 2026-11-15 it is a
recommendation, not a rule. Where libqmi lacks a message or TLV, another
source may supply it. The id then names that source in a code comment, is
measured on hardware before it is relied on, and is listed here (the plugin,
`plugins/ims.uc`) or in `../wwand-ims-core/docs/qmi-beyond-libqmi.md` (the
wwand core schemas, among them WDS 0x2E, the IPv6 P-CSCF list that
`sipd/line_ue.uc` uses).

## Tools

- `tools/qmi-idl-dump.py LIB READELF`: decodes the Qualcomm IDL encoder
  tables in a vendor `libqmiservices.so` (message ids, TLV ids, wire widths).
  The OnePlus 8T dump (OxygenOS 14, 2026-11-15) is
  `research/op8t-20261113/idl-libqmiservices.json` and
  `idl-libqmiextservices.json`.
- `tools/qmi-libqmi-audit.sh [CORE_SRC] [LIBQMI_DATA] [IDL_JSON]`: lists every
  message and TLV id in the core's and the plugin's schemas that libqmi 1.38
  does not define, each with its IDL lookup. A row it prints that neither
  document lists is a gap.

## The plugin's entries

| Service | Message | Id | Not in libqmi | Wire | Sources | Used |
|---|---|---|---|---|---|---|
| NAS 0x03 | Get IMS Preference | 0x0073 | whole message | resp 0x10 { radio interface e8, call types u64 (voice bit 0, SMS bit 1) } | Gobi API 2013-07-31 (`eQMI_NAS_GET_IMS_PREFERENCE`), IDL-8T (type 155: e8 + u64) | status, read only |
| Voice 0x09 | Dial Call | 0x0020 | req 0x10 call type, 0x18 audio attributes, 0x19 video attributes | e8, u64, u64 | Gobi API (`VoiceCallOriginate`), oFono's QMI voice driver (0x10), IDL-8T; stock RIL on the 8T dials with audio 3, video 0 (`research/op8t-20261113`) | sent |
| PDC 0x24 | Get Config | 0x0030 | whole message | req 0x01 type u32, 0x10 token, 0x11 id (u8-counted), 0x12 subscription u32, 0x13 frame index u32; ind 0x01 error u16, 0x10 token, 0x11 frame index (0xFFFFFFFF last), 0x12 frame (u16-counted) | IDL-8T, OP13 `persistent_device_configuration_v01.h`. **HW** RG650E 2026-11-15: accepted. The frames are 4096 data bytes, so a frame's indication is 4133 bytes: it never arrives whole over USB. Blamed first on qmi_wwan's 4096-byte cdc-wdm buffer, but a raw-usbfs read (usbmon-verified, 2026-11-15) hits the same 4096 wall in the modem's own GET_ENCAPSULATED_RESPONSE, so raising the kernel buffer would not help — only a PCIe/MHI modem (32 KB MTU) can read a >4 KB config back. A factory config answers INVALID_ID (49), and a request right after a timed-out one answers 49 as well | `mbn_read`, the base of `mbn patch` where it works |
| PDC 0x24 | Delete Config indication | 0x0025 | whole indication (libqmi has the request only) | 0x01 result (2-byte enum), 0x10 token | IDL-8T (PDC ind 0x0025: e16, u32). **HW** RG650E 2026-11-15: arrived for a delete | `mbn_delete`; a timeout counts as sent |
| Voice 0x09 | All Call Status indication | 0x002E | ind 0x14 call end reasons | u8 count + { call id u8, reason u16 } (max 7) | Gobi API, IDL-8T (array, max 7), IDL-OP13 (`voice_call_end_reason_type_v02`: GENERIC_1_BYTE + 2_BYTE_ENUM) | read; reasons passed on as numbers, never named |

| Where | Not in libqmi | Source |
|---|---|---|
| Voice call mode (`CALL_MODE`) | 5 tdscdma, 6 undetermined, 7 wlan (libqmi names 0..4) | Gobi API `eQMIVoiceCallModes`; 6 is the normal state while call control runs (8T RIL capture) |

IDL-8T is the OnePlus 8T's `/vendor/lib64/libqmiservices.so`
(md5 a062f6bae6caa55fac574e7c8e07e8b1). IDL-OP13 is the Qualcomm
`qcril-qmi-services` source under
`~/projects/wwand-ims-docs/library/aospa-op13-proprietary`.

## Still on AT, and why

| AT | QMI counterpart | State |
|---|---|---|
| `AT+CGCONTRDP` (P-CSCF) | WDS Get Current Settings 0x23 / 0x2E | QMI first since 2026-11-15; AT only for a core without 0x2E |
| `AT+CGEQOSRDP` (QCI 1 poll) | QoS service (0x04) flow reports | libqmi 1.38's QoS service cannot list the flows; the 8T IDL carries the full service. To be decoded and measured |
| `AT+QNWCFG="lte_fgi_fdd"` | none: no QMI message, and no phone RIL sets FGIs | Not needed any more: `wwandctl ims mbn patch --upload --replace` puts `lte/rrc/efs/lte_fgi_r8` into the carrier MBN and loads it over PDC, which is the vendor way (20 Qualcomm MBNs on the 8T carry the item). HW-proven on the RG650E 2026-11-15. AT stays for `fix` and for reading the FGIs back |
| `AT+QCFG="ims"` | IMS Settings (0x12) Set IMS Services Enabled 0x008F (libqmi 1.38) | whether it turns the modem's own IMS off the way `QCFG ims` does is unmeasured |
