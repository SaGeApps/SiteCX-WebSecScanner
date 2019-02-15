#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: Karan, Neena
"""
import os
import requests
from selenium import webdriver 
import re
import urllib.request
import dns.resolver
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
app.config["DEBUG"] = True
CORS(app)


## Var declares

#COMMON
newLine="\n"
http_var="http://"
https_var="https://"
curl_header='curl -s -I '
predir='../..'

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
    try:
        d=os.popen(xmas_cmd_str1+ hostname+xmas_cmd_str2).read()
        d= d[:-1].split(newLine)
    except Exception as e:
        print(str(e)+"xmas")
        d=""
    return d

def XSSProtection(hostname):
    try:
        r = requests.head(http_var+hostname, allow_redirects=True)
        d=os.popen(XSSProtection_cmd_str1+ r.url+XSSProtection_cmd_str2).read()
        XSSProtection = (XSSProtection_indicator_str1 in d)
    except Exception as e:
         print(str(e)+"XSSProtection")
         XSSProtection=False
    return XSSProtection

def XFrameOptions(hostname):
    try:
        r = requests.head(http_var+hostname, allow_redirects=True)
        d=os.popen(curl_header+ r.url+XFrameOptions_cmd_str1).read()
        XFrameOptions = (XFrameOptions_indicator_str1 in d or XFrameOptions_indicator_str2 in d)
    except Exception as e:
         print(str(e)+"XFrameOptions")
         XFrameOptions=False
    return XFrameOptions
    
def XContentTypeOptions(hostname):
    try:
        r = requests.head(http_var+hostname, allow_redirects=True)
        d=os.popen(curl_header+ r.url+XContentTypeOptions_cmd_str1).read()
        XContentTypeOptions = (XContentTypeOptions_indicator_str1 in d )
    except Exception as e:
        print(str(e)+"XContentTypeOptions")
        XContentTypeOptions=False
    return XContentTypeOptions

def cors(hostname):
    try:
        a=os.getcwd()
        os.chdir(a+cors_cmd_str1)
        try:
            os.remove(cors_filename)
        except OSError:
            pass
        with open(cors_filename, 'w') as outfile:
            outfile.write(hostname)
        d=os.popen(cors_cmd_str2).read()
        try:
            os.remove(cors_filename)
        except OSError:
            pass
        os.chdir(predir)
    except Exception as e:
        print(str(e)+"XContentTypeOptions")
        d=""
        try:
            os.remove(cors_filename)
        except OSError:
            pass
    return d

def SQLInjection(hostname):
    try:
        d=os.popen('python2 ./dependency/DTECT1/d-tect.py '+hostname+' |grep "Click Jacking"').read()
        sqlnjection= (" vulnerable to Click Jacking" in d )
    except Exception as e:
        print(str(e)+"sqlnjection")
        sqlnjection=False
    return sqlnjection

def borkenACL(hostname):
    arr=[]
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    driver=webdriver.Chrome(executable_path=r'/usr/local/bin/chromedriver',chrome_options=chrome_options)
    driver.get("http://"+hostname)
    d=int(driver.execute_script('return document.getElementsByTagName("a").length;'))
    for i in range(d):
        performance_data = driver.execute_script('return (document.getElementsByTagName("a")['+str(i)+'].href);') 
        if "//"+hostname in performance_data:
            arr.append(re.findall('^[^?]*', performance_data)[0])
        elif "//www."+hostname in performance_data:
            arr.append(re.findall('^[^?]*', performance_data)[0])
        else:
            pass
    a=countlong(arr)
    a=req(arr[a])
    return a

def countlong(arr):
    a=[]
    for i in arr:
       a.append(i.count("/")) 
    val=a.index(max(a))
    return val

def req(d):
    print(d)
    d=d[:-1][::-1]
    d=d.replace(d[:d.find("/")],'..')
    print(d[::-1])
    d=urllib.request.urlopen(d[::-1]).getcode()
    return d

def ArecordRedirection(hostname):
    try:
        txt = dns.resolver.query(hostname, 'A')
        s=str(txt.response.answer[0].to_text)
        s=s.replace("<bound method RRset.to_text of <DNS ","").replace(". IN A RRset>>","")
        ArecordRedirection = (hostname != s)
    except Exception as e:
        print(str(e)+"ArecordRedirection")
        ArecordRedirection=False
    return ArecordRedirection

def blindjacking(hostname):
    try:
        a=os.getcwd()
        os.chdir(a+"/dependency/findject/")
        d=os.popen("tshark -i  eth0 -F pcap -w test.pcap").read()
        d=os.popen("python findject.py test.pcap")
    except Exception as e:
        print(str(e)+"blindjacking")
        d=""
    return d

def checkcaptcha(hostname):
    try:
        r = requests.head(http_var+hostname, allow_redirects=True)
    except ConnectionError:
        r = requests.head(https_var+hostname, allow_redirects=True)
        
    d=os.popen("curl -s "+r.url+" |grep alt=").read()
    checkcaptcha = ("captcha" in d)
    return checkcaptcha

@app.route('/main/<hostname>', methods=['GET'])    
def Main(hostname):
    try:
        json_data = {}
        json_data["domain"]=hostname
        json_data["xmas"]=xmas(hostname)
        json_data["XSSProtection"]=XSSProtection(hostname)
        json_data["XFrameOptions"]=XFrameOptions(hostname)
        json_data["XContentTypeOptions"]=XContentTypeOptions(hostname)
        json_data["cors"]=cors(hostname)
        json_data["blindjacking"]=blindjacking(hostname)
        json_data["ArecordRedirection"]=ArecordRedirection(hostname)
        json_data["SQLInjection"]=SQLInjection(hostname)
        
    except Exception as e:
        print(str(e)+"main")
        json_data = {}
        json_data["domain"]=hostname
    return str(json_data).replace("\'", "\"")
        

if __name__ == "__main__":
    app.run(host='192.168.35.33',port=7444)
     

