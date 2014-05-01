import dns.resolver
import socket
import os
import sys
import struct
import ipaddr

def get_info(domain, type):
    answer = dns.resolver.query(domain, type)
    for rdata in answer:
        return rdata
    return None

def get_public_key(domain):
    print(domain)
    domain_key_obj = get_info('ftor_key.'+domain, 'TXT')
    if domain_key_obj is None:
        raise Exception()
    domain_key = str(domain_key_obj)
    domain_key = domain_key.replace('"', '')
    domain_key = domain_key.replace(' ', '')
    domain_parts = [domain_key[i:i+64] for i in range(0, len(domain_key), 64)]
    domain_key = ''
    for i in domain_parts:
        domain_key = domain_key + i + '\n'
    domain_key = '-----BEGIN PUBLIC KEY-----\n' + domain_key + '-----END PUBLIC KEY-----\n'
    return domain_key

def make_reply(conn):
    header_size = 12
    packet_len_size = 4

    request = ''
    while len(request) < packet_len_size:
        received = conn.recv(packet_len_size - len(request))
        if len(received) == 0:
            raise Exception()
        request = request + received
    request_size = struct.unpack('!I', request)[0]
    if request_size <= header_size:
        raise Exception()
    while len(request) < request_size:
        received = conn.recv(request_size - len(request))
        if len(received) == 0:
            raise Exception()
        request = request + received
    (request_size, flags, strsize1, strsize2) = struct.unpack('!IIHH', request[0:12])
    if request_size != 12 + strsize1 + strsize2:
        raise Exception()
    domain1 = request[12 : 12 + strsize1]
    domain2 = request[header_size + strsize1 : header_size + strsize1 + strsize2]

    pubkey1 = get_public_key(domain1)
    pubkey2 = get_public_key(domain2)
    ip1 = int(ipaddr.IPv4Address(str(get_info(domain1, 'A'))))
    ip2 = int(ipaddr.IPv4Address(str(get_info(domain2, 'A'))))

    result_packet_len = 17 + len(pubkey1) + len(pubkey2)
    reply = struct.pack('!IBIIHH', result_packet_len, 0, ip1, ip2, len(pubkey1), len(pubkey2))
    reply = reply + pubkey1 + pubkey2
    return reply


def process_request(conn):
    reply = ''
    try:
        reply = make_reply(conn)
    except Exception:
        reply = struct.pack('!IB', 5, 1)
    try:
        conn.send(reply)
        conn.close()
    except Exception:
        pass

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 27018))
    sock.listen(1)
    while True:
        conn, addr = sock.accept()
        pid=os.fork()
        if pid == 0:
            sock.close()
            process_request(conn)
            sys.exit(0)
        else:
            conn.close()

if __name__ == '__main__':
    main()
