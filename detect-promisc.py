#!/usr/bin/python
# script that detects hosts in promisc mode on a LAN segment


from scapy.all import *

# asks for user input for a network
# CIDR notation - 192.168.1.0/24

network=str(raw_input("Enter network address to scan (CIDR):"))

#network="192.168.1.0/24"

# Sends an ARP packet with a fake MAC to every host on the network
# Timeout of 0.1 otherwise it will go on for too long
# creates a list of replys called ans

ans,unans = srp(Ether(dst="FF:FF:FF:FF:FF:FE")/ARP(pdst=network), timeout=0.1,retry=0)

# if there is a reply, print all replys
if ans.summary()!=None:
    print ans.summary()





