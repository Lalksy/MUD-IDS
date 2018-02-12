#!/usr/bin/python
#date             :01-01-2018
#==============================================================================
from scapy.all import *
import argparse
import time
import threading
from threading import Semaphore
import pickle
import numpy as np
from db_config.mongo_ops import *
from pprint import pprint
from utils import *
from upload_download.upload import upload
from collections import defaultdict


# Packet Call Back function
def get_target_traffic(addr_list, iter_seq):
    def filter(pkt):
                
        # Parsing DHCP transaction
        try:
            standard_dhcp_callback(pkt, dhcp_trans_history)
        except Exception as e:
            print("Error: Parsing DHCP transaction")
            pass
        
        # Cannot handle ARP or other None IP protocols for now
        if pkt.getlayer(IP) == None:
            return
          
    return filter

def capture_traffic(addr_list, iter_seq):
    start_time = time.time()
    # Choose proper sniffing interface, time out parameter
    sniff(iface='enx687f7429badf',timeout=10, prn=get_target_traffic(addr_list, iter_seq))
    print("capture traffic takes %f seconds" % (time.time() - start_time))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--time", help="the period to run the learner", default="600")

    args = parser.parse_args()

    ips = get_ip_list()

    window_time = int(args.time)
    global num_iter
    num_iter = window_time / 10

    global dhcp_trans_history
    global dhcp_list
    dhcp_trans_history = defaultdict(lambda: [])

    print("Initiate Data Capture")

    for i in range(num_iter):
        
        try:
            capture_traffic(ips, i)
        except Exception as e:
            print("uncaught parsing error during traffic capturing")
            pass

        #update data structures after each capture
       ips = get_ip_list()
