#!/usr/bin/python

import sys, os, argparse, socket, subprocess, setproctitle, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

KNOCK = [1000, 2000, 3000]
FILTER = "udp and (dst port {0} or {1} or {2} or 80)".format(KNOCK[0], KNOCK[1], KNOCK[2])


def remoteExecute(pkt):
    print pkt['Raw'].load

    pkt = IP(dst="192.168.0.15")/UDP(dport=pkt['UDP'].sport,sport=pkt['UDP'].dport)/'yyyy'
    send(pkt)

def main():
    sniff(filter=FILTER, prn=remoteExecute)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt, AttributeError:
        print 'Exiting..'
