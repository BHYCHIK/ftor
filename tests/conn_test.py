import socket
import struct
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 27015))
s.send(struct.pack('BBHIBB', 55, 25, 5, 21, 0, 0))
time.sleep(2)
s.send(struct.pack('BBHIBB', 55, 25, 5, 21, 0, 0))
a = s.recv(1024)
print a
s.close()
