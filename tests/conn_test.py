import socket
import struct
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 27015))
s.send(struct.pack('IIB', 0, 0, 0))
a = s.recv(8)
print a
time.sleep(5)
a = s.recv(1024)
s.send("HELLO WORLD")
print a
s.close()
