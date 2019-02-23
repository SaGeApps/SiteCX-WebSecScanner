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
    x = data["xmas"]
    acl = data["borkenACL"]
    ar = data["ArecordRedirection"]
    c = data["cors"]
    bad = data["Bad_authentication"]
    session = data["Sessionhijack"]
     
    return render_template('index.html',Domain = dm, sqlinjection = sq ,xmas = x , borkenACL = acl ,ArecordRedirection = ar ,cors = c,Bad_authentication = bad,Sessionhijack = session)


def Main(hostname):
    try:
        json_data = {}
        json_data["domain"]=hostname
        json_data["SQLInjection"]=calcSQLInjection(hostname)
        json_data["xmas"]=calcXmas(hostname)
        json_data["Bad_authentication"]=calcauthentication(hostname)
        json_data["borkenACL"]=calcborkenACL(hostname)
        json_data["cors"]=calccors(hostname)
        json_data["Sessionhijack"]=calcSessionhijack(hostname)
        json_data["ArecordRedirection"]=calcArecordRedirection(hostname)
        
        
    except Exception as e:
        print(str(e)+"main")
        json_data = {}
        json_data["domain"]=hostname
    return json_data


def calcXmas(hostname):
    try:
        d=xmas(hostname)
        score=10 - len(d)
    except:
        score = ""
    return str(score)
    
def calcauthentication(hostname):
    try:
        score = 10 - int(not XFrameOptions(hostname)) - int(not XContentTypeOptions(hostname)) -int(not XSSProtection(hostname)) - int(not checkcaptcha(hostname))
    except:
        score = ""
    return str(score)

def calcborkenACL(hostname):
    try:
        score = int(not borkenACL(hostname))
    except:
        score = ""
    return str(score)

def calcSQLInjection(hostname):
    try:
        score = int(not SQLInjection(hostname))
    except:
        score = ""
    return str(score)

def calcArecordRedirection(hostname):
    try:
        score = int(not ArecordRedirection(hostname))
    except:
        score = ""
    return str(score)

def calccors(hostname):
    try:
        d=cors(hostname)
        if d == '':
            score = 10
        elif "Alert:" in d:
            score = 0
        elif "Warning:" in d:
            score = 5
        else:
            score = 7
    except:
        score = ""    
    return str(score)

def calcSessionhijack(hostname):
    try:
        d= blindjacking(hostname)
        if d == "":
            score = 1
        else:
            score = 0
    except:
        score = ""            
    return str(score)


def xmas(hostname):
    try:
        d=os.popen(xmas_cmd_str1+ hostname+xmas_cmd_str2).read()
        d= d[:-1].split(newLine)
    except Exception as e:
        print(str(e)+"xmas")
        d=[]
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
        if (cors_cmd_str1 in os.getcwd()):
            os.chdir(predir)
        else:
            pass
    return d

def SQLInjection(hostname):
    try:
        d=os.popen('python2 ./dependency/DTECT1/d-tect.py '+hostname+' |grep "Click Jacking"').read()
        sqlnjection= ("Click Jacking" in d )
    except Exception as e:
        print(str(e)+"sqlnjection")
        sqlnjection=False
        print("asd")
    return sqlnjection

def borkenACL(hostname):
    try:
        status=[]
        arr=[]
        chrome_options = webdriver.ChromeOptions()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        driver=webdriver.Chrome(executable_path=r'./dependency/Drivers/chromedriver',chrome_options=chrome_options)
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
    except Exception as e:
        print("------------/nborkenACL--------"+str(e))
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
        os.chdir(predir)
    except Exception as e:
        print(str(e)+"blindjacking")
        os.chdir(predir)
        d=""
    return d

def checkcaptcha(hostname):
    try:
        try:
            r = requests.head(http_var+hostname, allow_redirects=True)
        except ConnectionError:
            r = requests.head(https_var+hostname, allow_redirects=True)
            
        d=os.popen("curl -s "+r.url+" |grep alt=").read()
        checkcaptcha = ("captcha" in d)
    except:
        checkcaptcha=False
    return checkcaptcha


        

if __name__ == "__main__":
    app.run(host='localhost',port=7444)
     

