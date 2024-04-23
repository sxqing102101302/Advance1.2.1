#!/usr/bin/env python3
import sys
import os

from scapy.all import Ether, IPOption, Packet, bind_layers, get_if_list, sniff
from scapy.fields import *
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

def handle_ip_packet(pkt):
    print("Received an IPv4 packet")
    pkt.show2()
    sys.stdout.flush()

def handle_source_route_packet(pkt):
    print("Received a source-routed packet")
    pkt.show2()
    sys.stdout.flush()

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

class SourceRoutingTail(Packet):
   fields_desc = [ XShortField("etherType", 0x800)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, SourceRoutingTail, bos=1)

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="(tcp port 1234) or (udp port 4321) or (ether proto 0x1234) or (ether proto 0x800)", iface=iface,
          prn=lambda x: handle_ip_packet(x) if x.haslayer(Ether) and x[Ether].type == 0x800 else handle_source_route_packet(x))

if __name__ == '__main__':
    main()
