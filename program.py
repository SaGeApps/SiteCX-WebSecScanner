#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: karan
"""
import os
import requests

## Var declares

#COMMON
newLine="\n"
http_var="http://"

#XMAS
xmas_cmd_str1='nmap –sX –p-  -Pn '
xmas_cmd_str2='| grep open'


#XSS
XSSProtection_cmd_str1='curl -s -I '
XSSProtection_cmd_str2='| grep X-XSS-Protection'
XSSProtection_indicator_str1='X-XSS-Protection: 1; mode=block'




def xmas(hostname):
    d=os.popen(xmas_cmd_str1+ hostname+xmas_cmd_str2).read()
    d= d[:-1].split(newLine)
    return d

def XSSProtection(hostname):
    r = requests.head(http_var+hostname, allow_redirects=True)
    d=os.popen(XSSProtection_cmd_str1+ r.url+XSSProtection_cmd_str2).read()
    XSSProtection = (XSSProtection_indicator_str1 in d)
    return XSSProtection

def XFrameOptions(hostname):
    r = requests.head(http_var+hostname, allow_redirects=True)
    d=os.popen('curl -s -I '+ r.url+'| grep X-Frame-Options').read()
    XFrameOptions = ('SAMEORIGIN' in d or 'deny' in d)
    return XFrameOptions
    
def XContentTypeOptions(hostname):
    r = requests.head(http_var+hostname, allow_redirects=True)
    d=os.popen('curl -s -I '+ r.url+'| grep X-Content-Type-Options').read()
    XContentTypeOptions = ('nosniff' in d )
    return XContentTypeOptions

def cors(hostname):
    a=os.getcwd()
    os.chdir(a+'/dependency/CORStest')
    with open('outfile.cors', 'w') as outfile:
        outfile.write(hostname)
    d=os.popen(' ./corstest.py -q outfile.cors').read()
    os.chdir('..')
    return d

    