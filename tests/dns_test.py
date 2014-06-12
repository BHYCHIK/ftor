import socket
import os
import sys
import struct
import time

t1 = time.time()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('127.0.0.1', 27018))
domain1="iremen.ru"
domain2="iremen.ru"
request = struct.pack('!IIHH', 12 + len(domain1) + len(domain2), 0, len(domain1), len(domain2)) + domain1 + domain2
sock.send(request)

header_size = 17
packet_len_size = 4

reply = ""
while len(reply) < packet_len_size:
    received = sock.recv(packet_len_size - len(reply))
    if len(received) == 0:
        raise Exception()
    reply = reply + received
reply_size = struct.unpack('!I', reply)[0]
if reply_size <= header_size:
    raise Exception()
while len(reply) < reply_size:
    received = sock.recv(reply_size - len(reply))
    if len(received) == 0:
        raise Exception()
    reply = reply + received
(reply_size, flags, ip1, ip2, pubkey1_len, pubkey2_len) = struct.unpack('!IBIIHH', request[0:17])
pkey1 = reply[17:17+pubkey1_len]
pkey2 = reply[17+pubkey1_len:17+pubkey1_len+pubkey2_len]
t2 = time.time()
print pkey1
print pkey2
print t2 - t1
