#!/usr/bin/env python3
# Transparent relay: modem USB diag (ffs-diag, if0) <-> TCP, so scat on the
# workstation can drive masks + QSR4 decode over the network (scat -t qc -T host:port).
import sys, socket, threading, logging, time
sys.path.insert(0, "/usr/lib/python3.14/site-packages")
from edlclient.Library.Connection.usblib import usb_class

VID, PID, ITF = 0x2c7c, 0x0122, 0
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 43555

cdc = usb_class(portconfig=[[VID, PID, ITF]], loglevel=logging.ERROR)
if not cdc.connect(-1, -1):
    print("USB diag connect FAILED", flush=True); sys.exit(1)
print("USB diag connected", flush=True)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT)); srv.listen(1)
print("listening on %d" % PORT, flush=True)

while True:
    conn, addr = srv.accept()
    print("client %s" % str(addr), flush=True)
    stop = threading.Event()

    def tcp_to_usb():
        try:
            while not stop.is_set():
                d = conn.recv(65536)
                if not d:
                    break
                cdc.usbwrite(d)
        except Exception as e:
            print("t2u end: %s" % e, flush=True)
        stop.set()

    th = threading.Thread(target=tcp_to_usb, daemon=True); th.start()
    try:
        while not stop.is_set():
            d = cdc.usbread(0x4000, timeout=100)
            if d:
                conn.sendall(bytes(d))
            else:
                time.sleep(0.002)
    except Exception as e:
        print("u2t end: %s" % e, flush=True)
    stop.set()
    try: conn.close()
    except Exception: pass
    print("client gone", flush=True)
