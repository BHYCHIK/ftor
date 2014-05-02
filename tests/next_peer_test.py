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
while True:
    lenta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lenta.connect(('81.19.85.88', 80))
    a = conn.recv(2048)
    lenta.send(a)
    a = lenta.recv(10000)
    print a
    conn.send(a)
    break

conn.close()
