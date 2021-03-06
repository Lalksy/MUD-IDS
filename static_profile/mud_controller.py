#!/usr/bin/python

# Author: Lalka Riger
# About: refactored controller code as module

# Copyright (c) 2016, Cisco Systems
# All rights reserved.
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

##-->>>>>>>>>>>>>$ CISCO MUD SERVER YANG FILE EXTRACTION PYTHON CODE $<<<<<<<<<<<<<<--##
##-->>>>>>$ mud_controller.py python code to extract the ACL name and DACL content from MUD server$<<<<<<<--##
##-->>>>>>$ MUD file reference https://www.ofcourseimright.com/mudmaker/ $<<<<<<<<<--##

#from urllib2 import urlopen, URLError, HTTPError
from subprocess import call
import sys
import os
import json
import glob

def mac_auth(mac, sig):
    # verify the sha256 signature on mac
    # mac and sig are text-encoded for transmission
    dir_input = "./"
    key = dir_input+"pub.key"

    f = open("mac.txt.tmp", 'w')
    n = f.write(mac)
    f.close()

    f = open("sign.txt.tmp", 'w')
    f.write(sig)
    f.close()

    # convert signature to openssl-pasrasble format
    converted = call(['base64', '-D', './sign.txt.tmp', '-o', 'sign.txt.sha256.tmp'])

    ver = call(['openssl', 'dgst', '-sha256','-verify', key, '-signature', 'sign.txt.sha256.tmp', 'mac.txt.tmp'])
    
    #remove temporary files
    clean_tmp()

    return ver

def clean_tmp():
    # remove temporary files
    try:
        os.remove("mac.txt.tmp")
        os.remove("sign.txt.tmp")
        os.remove("sign.txt.sha256.tmp")
    except OSError:
        pass

def dlfile(device_json, device_ps7):
    # Open the url
    # device_json for json file form mudserver
    # device_ps7 for getting signed signature
    dir_input = "./"
    mud_file_store = dir_input+'mud.json'
    CA = './static_profile/ck.pem'
    try:
        f1 = urlopen(device_json)
        device_name = device_json.split("mud/",1)[1]
        if device_name.endswith(".json"):
            device_json_path = dir_input+device_name
            # writing json file
            with open(device_json_path, "wb") as local_file:
                local_file.write(f1.read())
            device_name_ps7_format = device_json.split("mud/",1)[1]
            device_name_ps7_format = os.path.splitext(device_name_ps7_format)[0]
            device_name_ps7 = dir_input+device_name_ps7_format+".p7s"
            f2 = urlopen(device_ps7)
            # writing signature file
            with open(device_name_ps7, "wb") as local_file:
                local_file.write(f2.read())
        else:
            device_json_path = dir_input+device_name
            device_json_format = device_json.split("mud/",1)[1]+".json"
		    # writing json file
            with open(device_json_path, "wb") as local_file:
                local_file.write(f1.read())
            f2 = urlopen(device_ps7)
            device_name_ps7_format = device_ps7.split("mud/",1)[1][:-1]
            device_name_ps7 = dir_input+device_name_ps7_format
            # writing signature file
            with open(device_name_ps7, "wb") as local_file:
                local_file.write(f2.read())
        # calling openssl command
        decrypted = call(['openssl', 'cms', '-verify', '-in', device_name_ps7, '-CAfile', CA, '-out', mud_file_store, '-inform', 'DER', '-content', device_json_path])
        return decrypted
        #delete(device_name) # remove old download files
    #handle errors
    except HTTPError as e:
        print("HTTP Error:", e.code, device_json, device_ps7)
        return 1
    except URLError as e:
        print("URL Error:", e.reason, device_json, device_ps7)
        return 1

def delete(device_name_del):
    dir_input = "./"
    filename = device_name_del
    search_trace = [filename+'.p7s', filename+'.json']
    file_list = []
    for root, dirs, files in os.walk(dir_input):
        for trace in search_trace:
            search_trace_path = os.path.join(root, trace)
            for filename in glob.glob(search_trace_path):
                if os.path.exists(filename):
                    file_list.append(filename)
                else:
                    print('No files path found +name')
    for device_file in file_list:
        os.remove(device_file)
                        
def radius(device_url):
    device_json = device_url
    if device_json.endswith(".json"):
        device_url_ps7 = device_url
        device_url_ps7 = device_url_ps7.split(".json",1)[0]
        device_name_ps7 = device_url_ps7.split("mud/",1)[1]
        device_name_ps7_format = os.path.splitext(device_name_ps7)[0]
        device_ps7 = device_url_ps7+".p7s"
        print(device_ps7)
    else: 
        device_ps7 = device_url+".p7s/"
    return dlfile(device_json, device_ps7)

def get_json_value(json_object, index):
    mud_file_store = './mud.json'
    try:
        with open(mud_file_store, 'r') as f:
            data = f.read()
    except IOError:
        print('cannot open file to read', mud_file_store)
    else:
        data = json.loads(data)
    in_acl = (data['ietf-access-control-list:access-lists']['acl'][0]['aces']['ace'])
    len_in_acl = len(in_acl)
    out_acl = (data['ietf-access-control-list:access-lists']['acl'][1]['aces']['ace'])
    len_out_acl = len(out_acl)
    last_update = data['ietf-mud:mud']['last-update']
    cache_validity = data['ietf-mud:mud']['cache-validity']
    new_list = []
    for row in in_acl:
        try:
            if json_object == "acl_name_in":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][0]['acl-name']))
                new_list += [mylist]
            if json_object == "acl_type_in":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][0]['acl-name']))
                new_list += [mylist]
            if json_object == "rule_name_in":
                mylist = ((row['rule-name']))
                new_list += [mylist]
            if json_object == "src_dnsname_in":
                mylist = ((row['matches']['ipv4-acl']['ietf-acldns:src-dnsname']))
                new_list += [mylist]
            if json_object == "src_protocol_in":
                mylist = ((row['matches']['ipv4-acl']['protocol']))
                new_list += [mylist]
            if json_object == "src_lower_port_in":
                mylist = ((row['matches']['ipv4-acl']['source-port-range']['lower-port']))
                new_list += [mylist]
            if json_object == "src_upper_port_in":
                mylist = ((row['matches']['ipv4-acl']['source-port-range']['upper-port']))
                new_list += [mylist]
            if json_object == "src_actions_in":
                mylist = ((row['actions']['forwarding']))
                new_list += [mylist]
        except KeyError:
            mylist = ((""))
            new_list += [mylist]
    for row in out_acl:
        try:
            if json_object == "acl_name_out":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][1]['acl-name']))
                new_list += [mylist]
            if json_object == "acl_type_out":
                mylist = ((data['ietf-access-control-list:access-lists']['acl'][1]['acl-name']))
                new_list += [mylist]
            if json_object == "rule_name_out":
                mylist = ((row['rule-name']))
                new_list += [mylist]
            if json_object == "src_dnsname_out":
                mylist = ((row['matches']['ipv4-acl']['ietf-acldns:dst-dnsname']))
                new_list += [mylist]
            if json_object == "src_protocol_out":
                mylist = ((row['matches']['ipv4-acl']['protocol']))
                new_list += [mylist]
            if json_object == "src_lower_port_out":
                mylist = ((row['matches']['ipv4-acl']['source-port-range']['lower-port']))
                new_list += [mylist]
            if json_object == "src_upper_port_out":
                mylist = ((row['matches']['ipv4-acl']['source-port-range']['upper-port']))
                new_list += [mylist]
            if json_object == "src_actions_out":
                mylist = ((row['actions']['forwarding']))
                new_list += [mylist]
        except KeyError:
            mylist = ((""))
            new_list += [mylist]

    if index < len_in_acl:
        try:
            return new_list[index]
        except IndexError:
            print ("")

def read_json():
    rules = []
    i = 0
    more = True
    while more:
        # In_ACL
        if (get_json_value("acl_name_in", i)):
            acl = dict()
            in_acl = dict()
            in_acl['name'] = get_json_value("acl_name_in", i)
            in_acl['type'] = get_json_value("acl_type_in", i)
            in_acl['rule'] = get_json_value("rule_name_in", i)
            in_acl['dnsname'] = get_json_value("src_dnsname_in", i)
            in_acl['protocol'] = get_json_value("src_protocol_in", i)
            in_acl['lower_port'] = get_json_value("src_lower_port_in", i)
            in_acl['upper-port'] = get_json_value("src_upper_port_in", i)
            in_acl['action'] = get_json_value("src_actions_in", i)
            acl['in'] = in_acl
          
            # Out_ACL
            out_acl = dict()
            out_acl['name'] = get_json_value("acl_name_out", i)
            out_acl['type'] = get_json_value("acl_type_out", i)
            out_acl['rule'] = get_json_value("rule_name_out", i)
            out_acl['dnsname'] = get_json_value("src_dnsname_out", i)
            out_acl['protocol'] = get_json_value("src_protocol_out", i)
            out_acl['lower_port'] = get_json_value("src_lower_port_out", i)
            out_acl['upper_port'] = get_json_value("src_upper_port_out", i)
            out_acl['action'] = get_json_value("src_actions_out", i)
            acl['out'] = out_acl
            rules.append(acl)
            i += 1
        else :
            more = False
    return rules

