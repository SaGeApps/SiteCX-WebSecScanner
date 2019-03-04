#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jan 21 10:50:16 2019

@author: Karan, Anmy
"""
import os
import json
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
    sq = data["SQLInjection"]
    x = data["xmas"]
    acl = data["brokenACL"]
    ar = data["ArecordRedirection"]
    c = data["cors"]
    bad = data["Bad_authentication"]
    session = data["Sessionhijack"]
    encoded = base64.b64encode(open("static/logo_s.png", "rb").read()).decode('utf-8')
    render = render_template('index.html',img = encoded, Domain = dm, sqlinjection = sq ,xmas = x , brokenACL = acl ,ArecordRedirection = ar ,cors = c,Bad_authentication = bad,Sessionhijack = session)
    pdf = pdfkit.from_string(render,False)
    
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'inline; filename =output.pdf'
    return response

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
    d =0 
    return d

def  calc_EmailHijacking(hostname):
    d=EmailHijacking(hostname)
    return d
    return 
def  calc_spoof(hostname):
    d=dnsspoof(hostname)
    if d == "":
        score = 0
    else:
        score = 1
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


    
        
        
        
        
        