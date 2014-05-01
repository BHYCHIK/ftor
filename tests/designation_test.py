import socket
import struct
import time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', 27017))
s.listen(1)
while True:
    domain1 = "iremen.ru"
    domain2 = "iremen.ru"
    domain1_len = len(domain1)
    domain2_len = len(domain2)
    total_packet_len = 4 + 2 + 2 + domain1_len + domain2_len
    conn, addr = s.accept()
    conn.send(struct.pack("!IHH", total_packet_len, domain1_len, domain2_len))
    conn.send(domain1)
    conn.send(domain2)
    conn.close()
s.close()
