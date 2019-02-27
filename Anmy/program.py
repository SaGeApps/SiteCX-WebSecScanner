#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: Karan, Anmy
"""
import os
import requests



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
    d=os.popen("./spoofcheck.py "+hostname)
    os.chdir("../..")
    return d

