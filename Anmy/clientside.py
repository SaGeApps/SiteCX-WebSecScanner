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
from confluent_kafka import Consumer
import json


app = Flask(__name__)
app.config["DEBUG"] = True
CORS(app)


def Main_kafka():
    consumer = Consumer({
    'bootstrap.servers': '192.168.100.80:9092',
    'group.id': 'server_side_scanning',
    'client.id': 'sslcheck',
    'enable.auto.commit': True,
    'auto.commit.interval.ms': 1000,
    'session.timeout.ms': 6000,
        'default.topic.config': {'auto.offset.reset': 'latest'}})
    consumer.subscribe(['domaindetails'])
    try:
        while True:
            msg = consumer.poll(0.1)
            if msg is None:
                continue
            elif not msg.error():
                try:
                    print('Received message: {0}'.format(msg.value()))
                    d=json.loads(msg.value())
                    print (d)
                    if d["featureConfig"]["webSecurity"] == True:
                        print("true")
                        Main(d["companyDomain"])
                    else:
                        pass
                    #elif d["job"] == "single":
                        #run((d["id"],d["domain"]))
                except:
                    pass
        else:
            print('Error occured: {0}'.format(msg.error().str()))

    except KeyboardInterrupt:
        pass

    finally:
        consumer.close()
    return

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
    print(data)
    return response
    #return render
@app.route('/find/<hostname>', methods=['GET']) 
def compare(hostname):
    data=Main(hostname)
    return str(data).replace("\'", "\"")
def Main(hostname):
    try:
        print("---------started---------")
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
    print(json_data)
    return json_data

def calc_portScan(hostname):
    try:
        d = portScan(hostname)
        score = 10 - len(d)
        if score > 0:
            pass
        else:
            score = 0
    except :
        score = 0
    return score

def calc_OSdetection(hostname):
    try:
        d = OSdetection(hostname)
        d = 1
    except :
        d = 0        
    return  d

def calc_EmailHijacking(hostname):
    try:
        d=EmailHijacking(hostname)
        if d == True:
            score = 1
        else:
            score = 0
    except :
        score = 0
    return score

def  calc_spoof(hostname):
    try:
        d=dnsspoof(hostname)
        if d == "":
            score = 1
        else:
            score = 0
    except :
        score = 0
    return score



def portScan(hostname):
    try:
        d=os.popen("nmap "+hostname+"| grep open").read()
        d= d[:-1].split("\n")
    except :
        d = ""
    return d

def OSdetection(hostname):
    try:
        d=os.popen("nmap "+hostname+" -A | grep -E '(ubuntu|win|linux|Mac)'").read()

    except :
        d = ""
    return d

def dnsspoof(hostname):
    try:
        d=os.popen("dnsspoof -i eth0 -f "+hostname).read()
    except :
        d = ""
    return d


def EmailHijacking(hostname):
    try:
        a=os.getcwd()
        os.chdir(a+"/dependency/spoofcheck")
        d=os.popen("python2 spoofcheck.py "+hostname).read()
        d=d.replace("[*","").replace("[-","").replace("\n","").split("]")
        d = ('Spoofing not possible' in d[-1])
        os.chdir(a)
    except :
        os.chdir(a)
        d = ""
    return d
def MITM(hostname):  
    try:
        d = sslcheck.TLS(hostname)
        if d["SSLv3"] == 'False':
            tscore = 3
        else:
            tscore = 0
        if sslcheck.isInsecureSignatureAlgorithm(hostname) == 'False':
            sscore = 2
        else:
            sscore = 0
        print(sslcheck.DaysLeft(sslcheck.Date(hostname)))
        if float(sslcheck.DaysLeft(sslcheck.Date(hostname))) > 0:
            dscore = 5
        else:
            dscore = 0
            sscore = 0
            tscore = 0
        score = sscore + tscore + dscore
    except Exception as e:
        print(str(e)+"g======================")
        score = 0
    return score

if __name__ == "__main__":
    Main_kafka()
    #app.run(host='localhost',port=7555)

    
        
        
        
        
        