#!/usr/bin/env python

import time
import json
import argparse
import os.path as path
from socket import *
from struct import *

def udp_send_search_cmd():
    cs = socket(AF_INET, SOCK_DGRAM)
    cs.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    cs.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    pkg = pack('2I31Q', 0xf05a5a41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

    cs.sendto(pkg, ('<broadcast>', 6667))
    cs.close()

def show_title():
    print('{:<4} {:<12}{:^6} {:<12}{:<}'.format('ID', 'IP', 'TEMP', 'UPTIME', 'VERSION'))

def parse_data(data):
    unpack_data = unpack('2I32s32s32s32s5i32s32s32si', data)
    (_, _, _ip, _mask, _gw, _mac, _, temp, _, _, uptime, _version, _host, _, _) = unpack_data
    ip = _ip.decode().strip()
    mask = _mask.decode().strip()
    gw = _gw.decode().strip()
    mac = _mac.decode().strip()
    version = _version.decode().strip()
    host = _host.decode().strip()
    return (ip, mask, gw, mac, temp, uptime, version, host)

def handle_response(no, addr, data):
    # NO IP MASK GW MAC UPTIME TEMP MINER_VERSION HOST
    data_info = parse_data(data)
    uptime_h = data_info[5] // 3600
    uptime_m = data_info[5] // 60 % 60
    uptime_s = data_info[5] % 60
    uptime = '{}H{}M{}S'.format(uptime_h, uptime_m, uptime_s)
    if data_info[6][0] != 'c':
        version = ' UNKNOWN'
    else:
        version = data_info[6]
    fmt_msg = '{:<4} {:<20} {:^6} {:<12} {:<}'.format(no, data_info[0], data_info[4], uptime, version)
    print(fmt_msg.replace('\n', ''))

def udp_rcv_online_response(GETIP):
    ss = socket(AF_INET, SOCK_DGRAM)
    ss.bind(('0.0.0.0', 6667))
    ss.settimeout(0.2)

    if not GETIP:
        show_title()
        no = 1
    else:
        addr_lst = []
    while True:
        try:
            data, addr = ss.recvfrom(512)
            if GETIP:
                addr_lst.append(addr[0])
            else:
                handle_response(no, addr, data[:256])
                no += 1
        except timeout:
            break

    ss.close()
    if GETIP:
        return addr_lst

def tcp_request_miner(sip):
    cs = socket(AF_INET, SOCK_STREAM)
    cs.settimeout(0.05)

    try:
        cs.connect((sip, 4029))
    except:
        return (False, None)

    cs.send('{"parameter": "", "command": "devs"}'.encode('UTF-8'))

    data = ''
    data += cs.recv(1024).decode()
    data += cs.recv(1024).decode()
    data += cs.recv(1024).decode()
    data += cs.recv(1024).decode()
    data += cs.recv(1024).decode()

    cs.close()

    running = json.loads(data[:-1])['STATUS'][0]['STATUS'] == 'S'

    return (running, data[:-1])

def tcp_request_monitor(sip):
    cs = socket(AF_INET, SOCK_STREAM)
    cs.settimeout(0.05)
    try:
        cs.connect((sip, 4350))
    except:
        return False

    # Just check if the monitor is running
    return True

def tcp_get_one_machine_status(test_ip):
    res = tcp_request_miner(test_ip)
    if res[0] == False:
        if tcp_request_monitor(test_ip):
            print('{} {}'.format(test_ip, 'STOPPED'))
    else:
        print('{} {}'.format(test_ip, 'RUNNING'))

def tcp_get_machines_status(ip1r, ip2r, ip3r, ip4r):
    for i in range(ip1r[0], ip1r[1]+1):
        for j in range(ip2r[0], ip2r[1]+1):
            for k in range(ip3r[0], ip3r[1]+1):
                for l in range(ip4r[0], ip4r[1]+1):
                    test_ip = '{}.{}.{}.{}'.format(i, j, k, l)
                    tcp_get_one_machine_status(test_ip)

def udp_get_machines_status(GETIP=False):
    udp_send_search_cmd()
    return udp_rcv_online_response(GETIP)

def parse_iprange(iprng):
    iprng_lst = iprng.split('.')
    ipflds = [ipfld.split('-') for ipfld in iprng_lst]
    ipflds_int = []
    for ipfld in ipflds:
        if len(ipfld) != 2:
            ipflds_int += [[int(ipfld[0]), int(ipfld[0])]]
        else:
            ipflds_int += [[int(x) for x in ipfld]]
    return ipflds_int

def update_request(mip, pkg_size):
    cs = socket(AF_INET, SOCK_STREAM)
    cs.settimeout(0.1)
    cs.connect((mip, 4350))
    pkg_data_extra = [0] * 1016
    req = pack('4i3I1016b', htonl(1), htonl(1036), htonl(1), htonl(6), htonl(8), pkg_size >> 32, pkg_size & 0xffffffff, *pkg_data_extra)
    cs.send(req)
    time.sleep(0.2)
    return cs

def update_check_response(mip, sock):
    try:
        resp = sock.recv(1024)
        unpack_resp = unpack('3s', resp[8:11])
        update_ret = unpack_resp[0].decode()
        if update_ret == '200':
            print('Update {} Success'.format(mip))
        else:
            print('Update {} Failed'.format(mip))
    except:
        print('Update {} Failed'.format(mip))
    finally:
        sock.close()

def update_transfer_package(mip, pkg):
    cs = socket(AF_INET, SOCK_STREAM)
    cs.settimeout(1)
    cs.connect((mip, 2425))
    with open(pkg, 'rb') as f:
        l = f.read(64*1024)
        while l:
            cs.send(l)
            l = f.read(64*1024)
    cs.close()

def update_one_miner(mip, pkg, pkg_size):
    sock = update_request(mip, pkg_size)
    update_transfer_package(mip, pkg)
    update_check_response(mip, sock)

def update_miners(args):
    package = args[-1]
    if not path.isfile(package):
        print('No such package to update machines')
        return
    # update all machines
    if len(args) == 1:
        iplst = udp_get_machines_status(True)
    # update specified machine(s)
    else:
        iplst = args[:-1]

    pkg_size = path.getsize(package)
    for mip in iplst:
        update_one_miner(mip, package, pkg_size)

def main():
    parser = argparse.ArgumentParser(description='IbeLink Miner Tool')
    parser.add_argument('iprange', nargs = '?', help='e.g.: 192.168.1-5.0-255')
    parser.add_argument('-u', '--update', nargs='+', required=False, help='e.g.: 192.168.1.100 update.tar.gz; 192.168.1.100 192.168.1.200 ... update.tar.gz')
    args = parser.parse_args()

    if args.update != None:
        update_miners(args.update)
        return

    if args.iprange != None:
        ipfld = parse_iprange(args.iprange)
        tcp_get_machines_status(ipfld[0], ipfld[1], ipfld[2], ipfld[3])
    else:
        udp_get_machines_status()

if __name__ == '__main__':
    main()
