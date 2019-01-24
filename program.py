#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: karan
"""
import os
import requests

def xmas(hostname):
    d=os.popen('nmap –sX –p-  -Pn '+ hostname+'| grep open').read()
    d= d[:-1].split("\n")
    return d

def XSSProtection(hostname):
    r = requests.head("http://"+hostname, allow_redirects=True)
    d=os.popen('curl -s -I '+ r.url+'| grep X-XSS-Protection').read()
    XSSProtection = ('X-XSS-Protection: 1; mode=block' in d)
    return XSSProtection

def XFrameOptions(hostname):
    r = requests.head("http://"+hostname, allow_redirects=True)
    d=os.popen('curl -s -I '+ r.url+'| grep X-Frame-Options').read()
    XFrameOptions = ('SAMEORIGIN' in d or 'deny' in d)
    return XFrameOptions
    
def XContentTypeOptions(hostname):
    r = requests.head("http://"+hostname, allow_redirects=True)
    d=os.popen('curl -s -I '+ r.url+'| grep X-Content-Type-Options').read()
    XContentTypeOptions = ('nosniff' in d )
    return XContentTypeOptions

def cors(hostname):
    a=os.getcwd()
    os.chdir(a+'/CORStest')
    with open('outfile.cors', 'w') as outfile:
        outfile.write(hostname)
    d=os.popen(' ./corstest.py -q outfile.cors').read()
    os.chdir('..')
    return d

    