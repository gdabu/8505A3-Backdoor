#!/usr/bin/python

import sys, os, argparse, socket, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def remoteExecute(pkt):
	print pkt

def main():
	pkt = IP(dst="192.168.0.9")/UDP(dport=1000, sport=2000)/'zzzz'
	send(pkt)
	sniff(filter="ip and host 192.168.0.9", prn=remoteExecute)

if __name__ == '__main__':
	main()
