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
from flask import Flask ,render_template , make_response
from flask_cors import CORS
import pdfkit
import base64

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


def get_image_file_as_base64_data():
    encoded = base64.b64encode(open("static/logo_s.png", "rb").read())
    return encoded
    
    
@app.route('/<hostname>', methods=['GET'])  
def index(hostname):
    data=Main(hostname)
    dm = data["domain"]
    sq = data["SQLInjection"]
    x = data["xmas"]
    acl = data["brokenACL"]
    ar = data["ArecordRedirection"]
    c = data["cors"]
    bad = data["Bad_authentication"]
    session = data["Sessionhijack"]
    xss = data["XSS"]
    encoded = base64.b64encode(open("static/logo_s.png", "rb").read()).decode('utf-8')
    render = render_template('index.html',path = os.getcwd(),xss = xss, img = encoded, Domain = dm, sqlinjection = sq ,xmas = x , brokenACL = acl ,ArecordRedirection = ar ,cors = c,Bad_authentication = bad,Sessionhijack = session)
    '''options = {
    'load-error-handling': 'ignore',
    'load-media-error-handling': 'ignore',
    'orientation': 'landscape',
    'enable-smart-shrinking': '',
    'margin-top': '0',
    'margin-right': '0',
    'margin-bottom': '0',
    'margin-left': '0',
    'no-outline': '',
    'quiet': ''}
    pdf = pdfkit.from_string(render,False,options=options)
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename =output.pdf'
    '''
    return render


def Main(hostname):
    try:
        json_data = {}
        json_data["domain"]=hostname
        json_data["SQLInjection"]=calc_SQLInjection(hostname)
        json_data["xmas"]=calc_Xmas(hostname)
        json_data["Bad_authentication"]=calc_Authentication(hostname)
        json_data["brokenACL"]=calc_BrokenACL(hostname)
        json_data["cors"]=calc_CORS(hostname)
        json_data["Sessionhijack"]=calc_SessionHijack(hostname)
        json_data["ArecordRedirection"]=calc_A_RecordRedirection(hostname)
        json_data["XSS"]=calc_xss(hostname)
        
    except Exception as e:
        print(str(e)+"main")
        json_data = {}
        json_data["domain"]=hostname
    return json_data

def calc_xss(hostname):
    if XSSProtection(hostname) == True:
        xssp = 3
    else :
        xssp = 0
    if xsspy(hostname) == True:
        xss = 7
    else:
        xss = 0
    score = xssp + xss
    return score
def calc_Xmas(hostname):
    try:
        d=xmas(hostname)
        score=10 - len(d)
    except:
        score = ""
    return str(score)
    
def calc_Authentication(hostname):
    try:
        score = 10 - int(not XFrameOptions(hostname)) - int(not XContentTypeOptions(hostname)) -int(not XSSProtection(hostname)) - int(not checkCaptcha(hostname))
    except:
        score = ""
    return str(score)

def calc_BrokenACL(hostname):
    try:
        score = int(not brokenACL(hostname))
    except:
        score = ""
    return str(score)

def calc_SQLInjection(hostname):
    try:
        score = int(not SQLInjection(hostname))
    except:
        score = ""
    return str(score)

def calc_A_RecordRedirection(hostname):
    try:
        score = int(not ArecordRedirection(hostname))
    except:
        score = ""
    return str(score)

def calc_CORS(hostname):
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

def calc_SessionHijack(hostname):
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

def brokenACL(hostname):
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
    except Exception as e:
        print("------------/nbrokenACL--------"+str(e))
        status.append("")
    driver.close()
    driver.quit()
    brokenACL = ("True" in status)
    return brokenACL

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

def checkCaptcha(hostname):
    try:
        try:
            r = requests.head(http_var+hostname, allow_redirects=True)
        except ConnectionError:
            r = requests.head(https_var+hostname, allow_redirects=True)
            
        d=os.popen("curl -s "+r.url+" |grep alt=").read()
        checkCaptcha = ("captcha" in d)
    except:
        checkCaptcha=False
    return checkCaptcha

def xsspy(hostname):
    try:
        a=os.getcwd()
        os.chdir(a+"/dependency/XssPy/")
        d=os.popen("python XssPy.py -u "+hostname).read()
        d=d.remove("\n","").split("Started finging XSS")
        d= (d == "")
        os.chdir(a)
    except:
        d = False
        os.chdir(a)
    return d

if __name__ == "__main__":
    app.run(host='localhost',port=7444)
     

