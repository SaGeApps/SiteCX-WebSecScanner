#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: Karan, Neena
"""
from bs4 import BeautifulSoup
import os
import requests
from selenium import webdriver 
import re
import urllib.request
import dns.resolver
from flask import Flask ,render_template
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
cors_cmd_str1='/dependency/CORStest/'
cors_filename='outfile.cors'
cors_cmd_str2='python2 corstest.py -q outfile.cors'

@app.route('/<hostname>', methods=['GET'])  
def index(hostname):
    data=Main(hostname)
    dm = data["domain"]
    sq = data["SQLInjection"]
    xmas = data["xmas"]
    borkenACL = data["borkenACL"]
    ArecordRedirection = data["ArecordRedirection"]
    cors = data["cors"]
    bad = data["Bad_authentication"]
    session = data["Sessionhijack"]
     
    return render_template('index.html',Domain = dm,sqlinjection = sq ,xmas = xmas , borkenACL = borkenACL ,ArecordRedirection = ArecordRedirection ,cors = cors,Bad_authentication = bad,Sessionhijack = session)


def Main(hostname):
    try:
        json_data = {}
        json_data["domain"]=hostname
        json_data["xmas"]=calcXmas(hostname)
        json_data["Bad_authentication"]=calcauthentication(hostname)
        json_data["borkenACL"]=calcborkenACL(hostname)
        json_data["cors"]=calccors(hostname)
        json_data["Sessionhijack"]=calcSessionhijack(hostname)
        json_data["ArecordRedirection"]=calcArecordRedirection(hostname)
        json_data["SQLInjection"]=calcSQLInjection(hostname)
        
    except Exception as e:
        print(str(e)+"main")
        json_data = {}
        json_data["domain"]=hostname
    return json_data


def calcXmas(hostname):
    d=xmas(hostname)
    score=10 - len(d)
    return score
    
def calcauthentication(hostname):
    score = 10 - int(not XFrameOptions(hostname)) - int(not XContentTypeOptions(hostname)) -int(not XSSProtection(hostname)) - int(not checkcaptcha(hostname))
    return score

def calcborkenACL(hostname):
    score = int(not borkenACL(hostname))
    return score

def calcSQLInjection(hostname):
    score = int(not SQLInjection(hostname))
    return score

def calcArecordRedirection(hostname):
    score = int(not ArecordRedirection(hostname))
    return score

def calccors(hostname):
    d=cors(hostname)
    if d == '':
        score = 10
    elif "Alert:" in d:
        score = 0
    elif "Warning:" in d:
        score = 5
    else:
        score = 7
    return score

def calcSessionhijack(hostname):
    d= blindjacking(hostname)
    if d == "":
        score = 1
    else:
        score = 0
    return score


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

def xsspy(hostname):
    try:
        a=os.getcwd()
        os.chdir(a+"/dependency/XssPy")
        d=os.popen("python2 XssPy.py "+hostname).read()
    except Exception as e:
        print(str(e)+"XContentTypeOptions")
        xsspy=''
    return xsspy
    
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
        print(str(e)+"cors")
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
    try:
        status=[]
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
        a=[]
        for i in arr:
           a.append(i.count("/")) 
        val=a.index(max(a))
        f=arr[val]
        while(f.count("/") >=2):
            f=f[:-1][::-1]
            f=f.replace(f[:f.find("/")],'')
            try:
                page = urllib.request.urlopen(f[::-1])
                html = BeautifulSoup(page.read(),"html.parser")
                status.append(("Index of" in html.title.string))
            except Exception as e: 
                if "HTTP Error" in str(e):
                    status.append(False)
                else:
                    status.append("")
            f=f.replace(f[:f.find("/")],'')
    except :
        status.append("")
    driver.close()
    driver.quit()
    borkenACL = ("True" in status)
    return borkenACL

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
        d=os.popen("python findject.py test.pcap").read()
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


        

if __name__ == "__main__":
    app.run(host='192.168.35.33',port=7444)
     

