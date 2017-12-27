#!/usr/bin/python
from scapy.all import *
import sys
import socket

offers = 0
def pkt_callback(pkt):
    global offers  
    #pkt.show() # debug statement
    if (offers == 0):
        offers += 1
        dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
            IP(src="0.0.0.0",dst="255.255.255.255") / \
            scapy.all.UDP(sport=68,dport=67) / \
            scapy.all.BOOTP(chaddr=mac) / \
            scapy.all.DHCP(options=[("message-type","request"),("server_id", pkt['IP'].src), ("requested_addr", ip), "end"])
        scapy.all.sendp(dhcp_request)       

def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False

if __name__ == "__main__":

    if (len(sys.argv) != 4) :
        print "Usage: python mini_dhcp_client.py <mac> <current ip> <wireless interface>"
        exit()
    mac = sys.argv[1].replace(":", "", 5).decode('hex')

    ip = sys.argv[2]
    if(not valid_ip(ip)):
        print "Invalid ip address."
        exit()
    interface = sys.argv[3]
    
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0",dst="255.255.255.255") / \
        scapy.all.UDP(sport=68,dport=67) / \
        scapy.all.BOOTP(chaddr=mac) / \
        scapy.all.DHCP(options=[("message-type","discover"), (161, "http://storm.cis.fordham.edu/~rieger/mud/mock.json"), "end"])

    counts = 0
    while(offers == 0 and counts < 5):
        wrpcap("test.pcap", dhcp_discover)
        scapy.all.sendp(dhcp_discover)
        sniff(iface=interface, prn=pkt_callback, filter="port 68 and port 67", timeout=2)
        counts += 1
