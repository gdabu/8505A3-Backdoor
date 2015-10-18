#!/usr/bin/python

import sys, os, argparse, socket, subprocess, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

KNOCK = [1000, 2000, 3000]
FILTER = "udp and (dst port {0} or {1} or {2} or 80)".format(KNOCK[0], KNOCK[1], KNOCK[2])


def remoteExecute(pkt):
    print "==============================================="
    print pkt.show
    print ""

    pkt2 = IP(src=pkt["IP"].dst, dst=pkt["IP"].src)/UDP(dport=pkt['UDP'].sport,sport=pkt['UDP'].dport)/'yyyy'
    print pkt2.show
    print "==============================================="
    send(pkt2)

def stopfilter(pkt):
    return True

def main():

    while 1:
        sniff(filter=FILTER, prn=remoteExecute, stop_filter=stopfilter)

if __name__ == '__main__':
    main()
