##################################################################################
##  SOURCE FILE:    AesEncryption.py
##
##  AUTHOR:         Geoff Dabu
##
##  PROGRAM:
##
##
##  FUNCTIONS:      stopfilter(packet)
##					main()
##
##  DATE:           October 17, 2015
##
##################################################################################
import sys, os, argparse, socket, logging
from scapy.all import *
from AesEncryption import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

##################################################################################
##  FUNCTION
##
##  Name:       	stopfilter
##  Parameters:		packet - a packet that is passed in through sniffed
##  Return Values:	boolean - true, if sniff function ends. false, if sniff
##					function continues.
##  Description:	Determines whether the client continues to sniff for packets.
##					The client only continues if there is a pkt with payload.
##################################################################################
def stopfilter(pkt):
	if ARP in pkt:
		return False
	if Raw in pkt and UDP in pkt:
		print decrypt(pkt['Raw'].load)
		return True

##################################################################################
##  FUNCTION
##
##  Name:       	main
##  Parameters:		n/a
##  Return Values:	n/a
##  Description:	Prompts the user for a command, encrypts it and sends it to
##					the server.
##################################################################################
def main():

	cmdParser = argparse.ArgumentParser(description="8505A3-PortKnock Client")
	cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
	cmdParser.add_argument('-s','--srcIp',dest='srcIp', help='Source address of the host thats sending.', required=True)
	cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
	args = cmdParser.parse_args();

	while 1:
		payload = raw_input("Some input please: ")
		pkt = IP(dst=args.dstIp, src=args.srcIp)/UDP(dport=int(args.dstPort), sport=8000)/encrypt(payload)
		send(pkt)
		sniff(filter="udp and (src port " + args.dstPort + " and src " + args.dstIp + ")", stop_filter=stopfilter)

if __name__ == '__main__':
	main()
