#!/usr/bin/python

import sys, os, argparse, socket, subprocess, setproctitle, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

knock = [2000,2001,2002]
count = 0

def remoteExecute(pkt):
    global count
    dstIP = pkt[1].dst
    wnd = pkt[2].window
    if wnd == 4096:
        port = pkt[2].sport
        if port == knock[0]:
            count +=1
        if port == knock[1]:
            count +=1
        if port == knock[2]:
            count +=1
        if count == 3:
            print 'Authenticated!..Establishing Connection..'
            createServer(dstIP, 8505)
    elif count < 3:
        return

def main():
    sniff(count= 5, filter="ip and tcp", prn=remoteExecute)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt, AttributeError:
        print 'Exiting..'
