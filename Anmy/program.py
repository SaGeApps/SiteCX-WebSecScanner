#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: Karan, Anmy
"""
import os
from dependency.ssltest import sslcheck
from flask import Flask ,render_template , make_response
from flask_cors import CORS
import pdfkit
import base64

app = Flask(__name__)
app.config["DEBUG"] = True
CORS(app)

@app.route('/<hostname>', methods=['GET'])  
def index(hostname):
    data=Main(hostname)
    dm = data["domain"]
    mitm_score = data["mitm_score"]
    portscan_score = data["portscan_score"]
    osscan_score = data["osscan_score"]
    EmailHijacking_score = data["EmailHijacking_score"]
    sniff_score = data["sniff_score"]
    encoded = base64.b64encode(open("static/logo_s.png", "rb").read()).decode('utf-8')
    render = render_template('index.html',img = encoded, Domain = dm, mitm_score = mitm_score ,portscan_score = portscan_score , osscan_score = osscan_score ,EmailHijacking_score = EmailHijacking_score ,sniff_score = sniff_score)
    pdf = pdfkit.from_string(render,False)
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename =output.pdf'
    return response

def Main(hostname):
    try:
        json_data = {}
        json_data["domain"]=hostname
        json_data["mitm_score"]=MITM(hostname)
        json_data["portscan_score"]=calc_portScan(hostname)
        json_data["osscan_score"]=calc_OSdetection(hostname)
        json_data["EmailHijacking_score"]=calc_EmailHijacking(hostname)
        json_data["sniff_score"]=calc_spoof(hostname)
    except Exception as e:
        print(str(e)+"main")
        json_data = {}
        json_data["domain"]=hostname
    return json_data

def calc_portScan(hostname):
    d = portScan(hostname)
    score = 10 - len(d)
    return score

def calc_OSdetection(hostname):
    d = OSdetection(hostname)
    d = 1
    return d

def calc_EmailHijacking(hostname):
    d=EmailHijacking(hostname)
    if d == True:
        score = 1
    else:
        score = 0
    return score

def  calc_spoof(hostname):
    d=dnsspoof(hostname)
    if d == "":
        score = 1
    else:
        score = 0
    return score 



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
    d=os.popen("python2 spoofcheck.py "+hostname).read()
    d=d.replace("[*","").replace("[-","").replace("\n","").split("]")
    d = ('Spoofing not possible' in d[-1])
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

if __name__ == "__main__":
    app.run(host='localhost',port=7555)

    
        
        
        
        
        