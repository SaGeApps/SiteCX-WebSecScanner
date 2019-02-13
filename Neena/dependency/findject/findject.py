#!/usr/bin/env python
#
# findject 1.4
#
# Searches through PCAP files for TCP packet injection attacks, also known as Man-on-the-Side (MOTS) attacks
#
#
# Examples of such attacks can be found here:
# https://www.netresec.com/?page=Blog&month=2016-03&post=Packet-Injection-Attacks-in-the-Wild
#
# Created by: Erik Hjelmvik, NETRESEC
# Open Source License: GPLv2
#
#
# Usage: ./findject.py somefile1.pcap somefile2.pcap etc..
# Usage: ./findject.py *.pcap

# ==DEPENDENCIES==
# python 2.6 or 2.7
# pip install dpkt
# pip install repoze.lru
#
# On Debian/Ubuntu you can also do:
# apt-get install python-dpkt python-repoze.lru

import dpkt
import socket
import sys
import os
from repoze.lru import LRUCache
from sets import Set
from multiprocessing import Pool, Manager, Queue, Lock


PORT_SET = {80} #only inspect TCP port 80
manager = Manager()
results = Queue()
lock = Lock()

def get_key(ip, tcp):
    five_tuple = ip.src + ":" + str(tcp.sport) + "\t" + ip.dst + ":" + str(tcp.dport)
    return five_tuple + "\t" + str(tcp.seq)

def get_five_tuple_string(ip, tcp):
    return socket.inet_ntoa(ip.src) + ":" + str(tcp.sport) + "-" + socket.inet_ntoa(ip.dst) + ":" + str(tcp.dport)
    

def get_ip_packet(buf, pcap):
    
    if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
        sll = dpkt.sll.SLL(buf)
        return sll.data
    elif pcap.datalink() == dpkt.pcap.DLT_IEEE802 or pcap.datalink() == dpkt.pcap.DLT_EN10MB:
        try:
            ethernet = dpkt.ethernet.Ethernet(buf)
            if(ethernet.type == dpkt.ethernet.ETH_TYPE_IP):
                return ethernet.data
            else:
                return None
        except dpkt.UnpackError as e:
            return None
    elif pcap.datalink() == dpkt.pcap.DLT_RAW or pcap.datalink() == dpkt.pcap.DLT_LOOP:
        #Raw IP only supported for ETH_TYPE 0x0c. Type 0x65 is not supported by DPKT
        return dpkt.ip.IP(buf)
    elif pcap.datalink() == dpkt.pcap.DLT_NULL:
        frame = dpkt.loopback.Loopback(buf)
        return frame.data
    else:
        print >> sys.stderr, "unknown datalink!"
        exit

def injection_found(fn,ip, tcp, old_tcp_data):
    res=dict()
    res["filename"]=fn
    res["5tuple"]=get_five_tuple_string(ip,tcp)
    res["seq"]=str(tcp.seq)
    res["first"]=repr(old_tcp_data)
    res["last"]=repr(tcp.data)
    #results.append(res)
    results.put(res)
    lock.acquire()
    print(fn + " - INJECTION FOUND!")
    print("5-tuple:       \t" + res["5tuple"])
    print("Sequence numer:\t" + res["seq"])
    print("First:         \t" + res["first"])
    print("Last:          \t" + res["last"])
    sys.stdout.flush()
    lock.release()


def find_injections(pcap_file):
    _cache = LRUCache(10000) #100.000 entries - should last at least 100 msec on a 100% utilized gigabit network
    _hitset = Set()
    with open(pcap_file, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                ip = get_ip_packet(buf, pcap)
                try:
                    if(ip is not None and ip.p == dpkt.ip.IP_PROTO_TCP):
                        tcp = ip.data
                        if((tcp.sport in PORT_SET or tcp.dport in PORT_SET) and len(tcp.data) > 1):
                            key = get_key(ip, tcp)
                            #ip.len    : 11 bits
                            #ip.ttl    : 8 bits
                            #tcp.flags : 8 bits (normally)
                            value = ip.ttl<<24 ^ (tcp.flags<<16) ^ ip.len
                            if(_cache.get(key) is None):
                                _cache.put(key, value)
                            else:
                                if(_cache.get(key) != value):
                                    _hitset.add(key)
                except: pass
    
        except dpkt.dpkt.NeedData: pass
        except ValueError:
            if(len(_cache.data) == 0):
                print >> sys.stderr, "Unable to parse " + pcap_file + ", incorrect file format!"
                return
    injection_count = 0
    if(len(_hitset) > 0):
        _cache = LRUCache(1024)
        with open(pcap_file, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            try:
                for ts, buf in pcap:
                    ip = get_ip_packet(buf, pcap)
                    try:
                        if(ip is not None and ip.p == dpkt.ip.IP_PROTO_TCP and (ip.data.sport in PORT_SET or ip.data.dport in PORT_SET)):
                            key = get_key(ip, ip.data)
                            if(key in _hitset and len(ip.data.data) > 1):
                                tcp = ip.data
                                _cached_tcp_data = _cache.get(key)
                                if(_cached_tcp_data is None):
                                    _cache.put(key, tcp.data)
                                else:
                                    if(tcp.data != _cached_tcp_data):
                                        if(len(tcp.data) > len(_cached_tcp_data)):
                                            #new data is longer, store that
                                            if(tcp.data[:len(_cached_tcp_data)] != _cached_tcp_data):
                                                injection_found(pcap_file,ip, tcp, _cached_tcp_data)
                                                injection_count+=1
                                            _cache.put(key, tcp.data)
                                        elif(len(tcp.data) < len(_cached_tcp_data)):
                                            if(tcp.data != _cached_tcp_data[:len(tcp.data)]):
                                                injection_found(pcap_file,ip, tcp, _cached_tcp_data)
                                                injection_count+=1
                                        else:
                                            injection_found(pcap_file,ip, tcp, _cached_tcp_data)
                                            injection_count+=1
                    except AttributeError: pass
            except dpkt.dpkt.NeedData: pass
    if(injection_count == 0):
        lock.acquire()
        print(pcap_file+" - no injections")
        sys.stdout.flush()
        lock.release()


if len(sys.argv) < 2:
    sys.exit('Usage: %s dump.pcap' % sys.argv[0])

flist = list()
pool = Pool(processes=4)
for file in sys.argv[1:]:
    if not os.path.exists(file):
        print("ERROR: File %s does not exist!" % file)
    else:
        flist.append(file)
pool.map(find_injections, flist)
