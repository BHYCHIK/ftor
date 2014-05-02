import socket
import struct
import time
import os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 27016))
s.listen(1)
while True:
    conn, addr = s.accept()
    pid = os.fork()
    if pid == 0:
        s.close()
        break
    else:
        conn.close()
a = conn.recv(512)
conn.send(struct.pack("!B", 0))
lenta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lenta.connect(('192.168.0.1', 80))
while True:
    a = conn.recv(2048)
    print a
    if len(a) > 0:
        lenta.send(a)
    else:
        lenta.close()
        conn.close()
        break
    while True:
        try:
            a = lenta.recv(2048)
        except Exception:
            break
        print a
        if len(a) > 0:
            conn.send(a)
        else:
            lenta.close()
            conn.close()
            break
    break

conn.close()
