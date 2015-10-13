#!/usr/bin/python

import sys, os, argparse, socket, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *




def main():
	pkt = IP(dst="192.168.0.9")/UDP()
	send(pkt)


if __name__ == '__main__':
	main()

