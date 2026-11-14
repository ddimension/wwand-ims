import sys
sys.path.insert(0,'/home/avalentin/projects/scat/lib/python3.13/site-packages')
from scat.parsers.qualcomm import diagcmd
import scat.util as util
# SSID ranges reported by the A05 modem (scat "Extended message range")
ranges=[(0,142),(500,506),(1000,1007),(2000,2008),(3000,3014),(4000,4010),
(4500,4584),(4600,4616),(5000,5037),(5500,5517),(6000,6082),(6500,6521),
(7000,7003),(7100,7111),(7200,7201),(8000,8000),(8500,8532),(9000,9008),
(9500,9521),(10200,10210),(10251,10255),(10300,10300),(10350,10377),
(10400,10416),(10500,10505),(10600,10620),(10801,10836),(11057,11079),
(49152,49251)]
mode = sys.argv[2] if len(sys.argv) > 2 else ''
out=bytearray()
# mode "sip": no F3 at all (a quiet capture), only the log items below
for (a,b) in (ranges if mode != 'sip' else []):
    masks=[(s,0xffffffff) for s in range(a,b+1)]
    pkt=diagcmd.create_extended_message_config_set_mask(a,b,*masks)
    out+=util.generate_packet(bytearray(pkt))
# optional second argument "nas": also the LTE log items for RRC OTA and the
# NAS EMM/ESM OTA messages (0xB0C0, 0xB0E0-E3, 0xB0EA-ED), so a capture shows
# the bearer signalling (an Activate Dedicated EPS Bearer Context and the
# answer). The LTE equipment id range of this modem is 2559 items.
if mode in ('nas', 'sip'):
    out+=util.generate_packet(bytearray(diagcmd.log_mask_scat_lte(2559, layers=['rrc', 'nas'])))
# mode "sip": also the 1x equipment's items scat uses, among them 0x156E IMS
# SIP Message: the modem's own IMS stack's SIP, in clear (scat writes it as
# SIP over UDP into the pcap)
if mode == 'sip':
    out+=util.generate_packet(bytearray(diagcmd.log_mask_scat_1x()))
open(sys.argv[1],'wb').write(bytes(out))
print("wrote %d bytes, mode %s" % (len(out), mode or "f3"))
