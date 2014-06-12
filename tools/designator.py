import socket
import struct
import json
import memcache
import os
import random
import sys

middle_nodes = ["iremen.ru"]
end_nodes = ["iremen.ru"]

with_memcached = True

def finish_subtasks():
    while True:
        try:
            res = os.waitpid(-1, os.WNOHANG)
        except Exception:
            break
        if res == (0, 0):
            break

def check_cache(mc_conn, ip_addr):
    if mc_conn is None:
        return (False, None, None)
    cached_json = None
    try:
        cached_json = mc_conn.get('DESIGNATOR__' + ip_addr)
    except Exception as e:
        print e
        return (False, None, None)
    if cached_json is None:
        return (False, None, None)
    print 'found for %s in cache: %s' % (ip_addr, cached_json)
    cached = json.loads(cached_json)
    return (True, cached['middle_node'].encode('utf-8'), cached['end_node'].encode('utf-8'))

def store_to_mc(mc_conn, ip_addr, domain1, domain2):
    if mc_conn is None:
        return
    cached = dict()
    cached['ip'] = ip_addr
    cached['middle_node'] = domain1
    cached['end_node'] = domain2
    cached_json = json.dumps(cached)
    mc_conn.set(key = 'DESIGNATOR__' + ip_addr, val = cached_json, time = 3 * 60)
    print 'for %s stored %s' % (ip_addr, cached_json)

def process_request(conn, ip_addr):
    found_in_cache = False
    mc_conn = None
    if with_memcached:
        mc_conn = memcache.Client(['127.0.0.1:11211'], debug=0)
        (found_in_cache, domain1, domain2) = check_cache(mc_conn, ip_addr)
    if not found_in_cache:
        domain1 = random.choice(middle_nodes)
        domain2 = random.choice(end_nodes)
        if with_memcached:
            store_to_mc(mc_conn, ip_addr, domain1, domain2)
    if mc_conn is not None:
        mc_conn.disconnect_all()
        mc_conn = None
    domain1_len = len(domain1)
    domain2_len = len(domain2)
    total_packet_len = 4 + 2 + 2 + domain1_len + domain2_len
    conn.send(struct.pack('!IHH', total_packet_len, domain1_len, domain2_len))
    conn.send(domain1)
    conn.send(domain2)
    conn.close()
    sys.exit(0)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 27017))
    s.listen(1)
    while True:
        finish_subtasks()
        conn, addr = s.accept()
        finish_subtasks()
        pid = os.fork()
        if pid == 0:
            s.close()
            process_request(conn, addr[0])
        else:
            conn.close()
    s.close()

if __name__ == '__main__':
    main()
