#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: karan ,Neena
"""
import os
import requests

## Var declares

#COMMON
newLine="\n"
http_var="http://"
curl_header='curl -s -I '
predir='..'

#XMAS
xmas_cmd_str1='nmap –sX –p-  -Pn '
xmas_cmd_str2='| grep open'


#XSS
XSSProtection_cmd_str1='curl -s -I '
XSSProtection_cmd_str2='| grep X-XSS-Protection'
XSSProtection_indicator_str1='X-XSS-Protection: 1; mode=block'

#XFrameOptions
XFrameOptions_cmd_str1='| grep X-Frame-Options'
XFrameOptions_indicator_str1='SAMEORIGIN'
XFrameOptions_indicator_str2='deny'

#XContentTypeOptions
XContentTypeOptions_cmd_str1='| grep X-Content-Type-Options'
XContentTypeOptions_indicator_str1='nosniff'

#cors
cors_cmd_str1='/dependency/CORStest'
cors_filename='outfile.cors'
cors_cmd_str2=' ./corstest.py -q outfile.cors'


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
    d=os.popen(curl_header+ r.url+XFrameOptions_cmd_str1).read()
    XFrameOptions = (XFrameOptions_indicator_str1 in d or XFrameOptions_indicator_str2 in d)
    return XFrameOptions
    
def XContentTypeOptions(hostname):
    r = requests.head(http_var+hostname, allow_redirects=True)
    d=os.popen(curl_header+ r.url+XContentTypeOptions_cmd_str1).read()
    XContentTypeOptions = (XContentTypeOptions_indicator_str1 in d )
    return XContentTypeOptions

def cors(hostname):
    a=os.getcwd()
    os.chdir(a+cors_cmd_str1)
    with open(cors_filename, 'w') as outfile:
        outfile.write(hostname)
    d=os.popen(cors_cmd_str2).read()
    os.chdir(predir)
    return d

    
