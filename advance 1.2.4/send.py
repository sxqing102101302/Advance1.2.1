#!/usr/bin/env python3
import socket
import sys
import random

from scapy.all import (
    IP,
    TCP,
    UDP,
    Ether,
    Packet,
    bind_layers,
    get_if_hwaddr,
    get_if_list,
    sendp
)
from scapy.fields import *

def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class SourceRoute(Packet):
    fields_desc = [BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)

def main():
    if len(sys.argv) < 3:
        print('pass 3 arguments: <destination> <packet_type>')
        print('packet_type: ip / source_route')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    packet_type = sys.argv[2]

    if packet_type not in ['ipv4', 'source_route']:
        print('Invalid packet_type. Choose from "ipv4" or "source_route"')
        exit(1)

    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))

    while True:
        if packet_type == 'ipv4':
            print()
            s = str(input('Type "Enter" to send a pocket or "q" to quit: '))
            if s == "q":
                break
            print()
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[3]
            

        elif packet_type == 'source_route':
            print()
            s = str(input('Type space separated port nums '
                      '(example: "2 3 2 2 1") or "q" to quit: '))
            if s == "q":
                break
            print()
            pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            i = 0
            for p in s.split(" "):
                try:
                    pkt = pkt / SourceRoute(bos=0, port=int(p))
                    i = i + 1
                except ValueError:
                    pass
            if pkt.haslayer(SourceRoute):
                pkt.getlayer(SourceRoute, i).bos = 1
            pkt = pkt / IP(dst=addr) / UDP(dport=4321, sport=1234)

        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
