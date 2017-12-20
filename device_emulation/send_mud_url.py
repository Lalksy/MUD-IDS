#!/usr/bin/python
from scapy.all import *

offers = 0

def pkt_callback(pkt):
    pkt.show() # debug statement
    if (offers == 0):
        global offers
        offers += 1
        dhcp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
            IP(src="0.0.0.0",dst="255.255.255.255") / \
            scapy.all.UDP(sport=68,dport=67) / \
            scapy.all.BOOTP(chaddr='\x78\x4f\x43\x67\xb2\xcb') / \
            scapy.all.DHCP(options=[("message-type","request"),("server_id", pkt['IP'].src), ("requested_addr", pkt['BOOTP'].yiaddr), "end"])
        scapy.all.sendp(dhcp_request)       


if __name__ == "__main__":
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0",dst="255.255.255.255") / \
        scapy.all.UDP(sport=68,dport=67) / \
        scapy.all.BOOTP(chaddr='\x78\x4f\x43\x67\xb2\xcb') / \
        scapy.all.DHCP(options=[("message-type","discover"), (161, "http://localhost:8000/mud/pi-cam2.json"), "end"])
    while(offers == 0):
        wrpcap("test.pcap", dhcp_discover)
        scapy.all.sendp(dhcp_discover)
        sniff(iface="en0", prn=pkt_callback, filter="port 68 and port 67", timeout=2)
#    print "Found other dhcp server at: %s %s" % (ans[Ether].src, ans[IP].src)   

#        scapy.all.DHCP(options=[("message-type","discover"),"end"])
