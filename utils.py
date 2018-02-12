#!/usr/bin/python
#date             :01-01-2018
#==============================================================================
from __future__ import print_function
from scapy.all import *
import argparse
import json
import requests
import imp
from db_config.mongo_ops import *
from static_profile.mud_controller import *
from collections import defaultdict
manuf = imp.load_source("manuf", "manuf/manuf/manuf.py")
from manuf import main
import pika, os, logging
logging.basicConfig()

# The following block are for web app
# Parse CLODUAMQP_URL
url = 'amqp://unmntdbc:cOLaTd5JrnOdbxMSnVUwABRAZRZhXSlZ@fish.rmq.cloudamqp.com/unmntdbc'
params = pika.URLParameters(url)
params.socket_timeout = 5
# Connect to CloudAMQP
connection = pika.BlockingConnection(params) 
# start a channel
channel = connection.channel() 
# Declare a queue
channel.queue_declare(queue='deviceip') 

def layer_expand(packet):
    yield packet.name
    while packet.payload:
        packet = packet.payload
        yield packet.name

# Parsing DHCP Discover packet and use Fingerbank API for device information
# Please refer to Lalka's work for more details
def get_device_dhcp_info(pkt):

    mac_address = pkt.src
    static_profile = ["QUARANTINE"]
    
    try:
        options = pkt[BOOTP][DHCP].options
    except Exception as e:
        try:
            options = pkt['BOOTP']['DHCP'].options
        except Exception as e:
            raise e
    
    for option in options:
        if type(option) is tuple:
            opt_name = option[0]
            opt_value = option[1]
            if opt_name == 161:
                print(opt_value)
                ver = radius(opt_value)
                if (ver == 0):
                    static_profile = read_json()
                else:
                    static_profile = ["QUARANTINE"]

    
    return static_profile


def check_dhcp_type(pkt):
    if pkt[BOOTP][DHCP].options[0][0] == 'message-type':
        if pkt[BOOTP][DHCP].options[0][1] == 1:
            return 'DISCOVER'
        if pkt[BOOTP][DHCP].options[0][1] == 2:
            return 'OFFER'
        if pkt[BOOTP][DHCP].options[0][1] == 3:
            return 'REQUEST'
        if pkt[BOOTP][DHCP].options[0][1] == 4:
            return 'DECLINE'
        if pkt[BOOTP][DHCP].options[0][1] == 5:
            return 'ACK'
        if pkt[BOOTP][DHCP].options[0][1] == 6:
            return 'NAK'
        if pkt[BOOTP][DHCP].options[0][1] == 7:
            return 'RELEASE'
        if pkt[BOOTP][DHCP].options[0][1] == 8:
            return 'INFORM'
    else:
        return 'NOT DHCP'

# DHCP Packet parsing
def standard_dhcp_callback(pkt, dhcp_msgs_dict, exception_list=None):
    
    layers = list(layer_expand(pkt))
    if 'BOOTP' in layers:
        
        # Discover message parsing, store transacation
        if check_dhcp_type(pkt) == 'DISCOVER':
            print("DHCP DISCOVER Observed")
            dhcp_msgs_dict[pkt[Ether].src].append(('DISCOVER', pkt.time))
            profile = None
            profile = get_device_dhcp_info(pkt)

            if profile:
                device_dict = dict()
                device_dict['mac_address'] = pkt[Ether].src
                endpts = []
                domains = []
                device_dict['endpts'] = endpts
                device_dict['domains'] = domains
                device_dict['IoT'] = False
                device_dict['maufacturer'] = ""
                device_dict['os'] = ""
                device_dict['device_type'] = ""
                device_dict['static_profile'] = profile
                if(not device_exists(device_dict)):
                    print("Add Device\n")
                    add_device(device_dict)
                    #handle other cases here
            else:
                print("Error: profile retrieveal failed")

        elif check_dhcp_type(pkt) == 'OFFER':
            pass
           
        elif check_dhcp_type(pkt) == 'REQUEST':
            print("DHCP Request")
            dhcp_msgs_dict[pkt[BOOTP].xid].append(('REQUEST', pkt.time))
            device_dict = dict()
            device_dict['mac_address'] = pkt[Ether].src
            endpts = []
            domains = []
            device_dict['endpts'] = endpts
            device_dict['domains'] = domains
            if(not device_exists(device_dict)):
                print("Found DHCP Request, non existing device, Adding to database")
                add_device(device_dict)

        elif check_dhcp_type(pkt) == 'DECLINE':
            pass
        
        elif check_dhcp_type(pkt) == 'ACK':
            print("DHCP ACK")
            if dhcp_msgs_dict[pkt[Ether].dst] != []:
                print("DHCP ACK,  Update device IP  MAC ", pkt[IP].dst, pkt[Ether].dst)
                device = {'mac_address': pkt[Ether].dst}
                update_device_ip(device, pkt[IP].dst)
                try:
                    discover_message = "Discovered;"+pkt[IP].dst
                    channel.basic_publish(exchange='', routing_key='deviceip', body=discover_message)
                except Exception as e:
                   pass
                dhcp_msgs_dict.pop(pkt[BOOTP].xid)
            else:
                pass
        
        elif check_dhcp_type(pkt) == 'NAK':
            pass
        elif check_dhcp_type(pkt) == 'RELEASE':
            pass
        elif check_dhcp_type(pkt) == 'INFORM':
            pass
        
