#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: Karan, Anmy
"""
import os
import json
from dependency.ssltest import sslcheck

def calc_portScan(hostname):
    d = portScan(hostname)
    score = 10 - len(d)
    return score

def calc_OSdetection(hostname):
    d = OSdetection(hostname)
    d =0 
    return d

def  calc_EmailHijacking(hostname):
    d=EmailHijacking(hostname)
    
    return 
    

def portScan(hostname):
    d=os.popen("nmap -p 1-65535 "+hostname+"| grep open").read()
    d= d[:-1].split("/n")
    return d

def OSdetection(hostname):
    d=os.popen("nmap "+hostname+" -A | grep -E '(ubuntu|win|linux|Mac)'").read()
    return d

def dnsspoof(hostname):
    d=os.popen("dnsspoof -i eth0 -f "+hostname).read()
    return d


def EmailHijacking(hostname):
    a=os.getcwd()
    os.chdir(a+"/dependency/spoofcheck")
    d=os.popen("./spoofcheck.py "+hostname).read()
    os.chdir(a)
    return d
def MITM(hostname):  
    d = sslcheck.TLS(hostname)    
    if d["SSLv3"] == 'False':
        tscore = 3
    else:
        tscore = 0
    if sslcheck.isInsecureSignatureAlgorithm(hostname) == 'False':
        sscore = 2
    else:
        sscore = 0
    if int(sslcheck.DaysLeft(sslcheck.Date(hostname))) > 0:
        dscore = 5
    else:
        dscore = 0
        sscore = 0
        tscore = 0
    score = sscore + tscore + dscore
    return score


    
        
        
        
        
        