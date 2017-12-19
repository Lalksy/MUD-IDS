#!/usr/bin/python
from scapy.all import *


if __name__ == "__main__":
    
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0",dst="255.255.255.255") / \
        scapy.all.UDP(sport=68,dport=67) / \
        scapy.all.BOOTP(chaddr=RandString(12, "0123456789abcdef")) / \
        scapy.all.DHCP(options=[("message-type","discover"), (161, "http://160.39.149.190:8000/mud/pi-cam2.json"), "end"])

    wrpcap("test.pcap", dhcp_discover)

