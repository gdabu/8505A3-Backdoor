#!/usr/bin/python

import sys, os, argparse, socket, subprocess, setproctitle, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

knock = [2000,2001,2002]
count = 0

def remoteExecute(pkt):
    

def main():
    sniff(filter="ip and tcp", prn=remoteExecute)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt, AttributeError:
        print 'Exiting..'
