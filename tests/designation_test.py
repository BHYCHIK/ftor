import socket
import struct
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 27017))
s.listen(1)
while True:
    conn, addr = s.accept()
    conn.send("tesk done")
    conn.close()
s.close()
