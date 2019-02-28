import os
from datetime import datetime
import ssl
import urllib.request
from socket import timeout  
import requests
import re
    

store=['AAA Certificate Services','Actalis Authentication Root CA','AddTrust Class 1 CA Root','AddTrust External CA Root','Admin-Root-CA','AffirmTrust Commercial','AffirmTrust Networking','AffirmTrust Premium ECC','AffirmTrust Premium','Amazon Root CA 1','Amazon Root CA 2','Amazon Root CA 3','Amazon Root CA 4','ANF Global Root CA','Apple Root CA - G2','Apple Root CA - G3','Apple Root CA','Apple Root Certificate Authority','ApplicationCA2 Root','Atos TrustedRoot 2011','Autoridad de Certificacion Firmaprofesional CIF A62634068','Autoridad de Certificacion Raiz del Estado Venezolano','Baltimore CyberTrust Root','Belgium Root CA2','Buypass Class 2 Root CA','Buypass Class 3 Root CA','CA Disig Root R1','CA Disig Root R2','Certigna','Certinomis - AutoritÃ© Racine','Certinomis - Root CA','Certplus Root CA G1','Certplus Root CA G2','certSIGN ROOT CA','Certum CA','Certum Trusted Network CA 2','Certum Trusted Network CA','CFCA EV ROOT','Chambers of Commerce Root - 2008','Chambers of Commerce Root','Cisco Root CA 2048','Class 2 Primary CA','COMODO Certification Authority','COMODO ECC Certification Authority','COMODO RSA Certification Authority','ComSign CA','ComSign Global Root CA','ComSign Secured CA','D-TRUST Root CA 3 2013','D-TRUST Root Class 3 CA 2 2009','D-TRUST Root Class 3 CA 2 EV 2009','Deutsche Telekom Root CA 2','DigiCert Assured ID Root CA','DigiCert Assured ID Root G2','DigiCert Assured ID Root G3','DigiCert Global Root CA','DigiCert Global Root G2','DigiCert Global Root G3','DigiCert High Assurance EV Root CA','DigiCert Trusted Root G4','DST Root CA X3','DST Root CA X4','E-Tugra Certification Authority','Echoworx Root CA2','EE Certification Centre Root CA','Entrust Root Certification Authority - EC1','Entrust Root Certification Authority - G2','Entrust Root Certification Authority','Entrust.net Certification Authority (2048)','Entrust.net Certification Authority (2048)','ePKI Root Certification Authority','Federal Common Policy CA','GeoTrust Global CA','GeoTrust Primary Certification Authority - G2','GeoTrust Primary Certification Authority - G3','GeoTrust Primary Certification Authority','Global Chambersign Root - 2008','Global Chambersign Root','GlobalSign Root CA','GlobalSign','GlobalSign','GlobalSign','GlobalSign','Go Daddy Class 2 Certification Authority','Go Daddy Root Certificate Authority - G2','Government Root Certification Authority','Hellenic Academic and Research Institutions RootCA 2011','Hongkong Post Root CA 1','I.CA - Qualified Certification Authority, 09/2009','IdenTrust Commercial Root CA 1','IdenTrust Public Sector Root CA 1','ISRG Root X1','Izenpe.com','Izenpe.com','KISA RootCA 1','Microsec e-Szigno Root CA 2009','NetLock Arany (Class Gold) FÅ‘tanÃºsÃ­tvÃ¡ny','Network Solutions Certificate Authority','OISTE WISeKey Global Root GA CA','OISTE WISeKey Global Root GB CA','OpenTrust Root CA G1','OpenTrust Root CA G2','OpenTrust Root CA G3','QuoVadis Root CA 1 G3','QuoVadis Root CA 2 G3','QuoVadis Root CA 2','QuoVadis Root CA 3 G3','QuoVadis Root CA 3','QuoVadis Root Certification Authority','Secure Global CA','SecureTrust CA','Security Communication EV RootCA1','Security Communication RootCA1','Security Communication RootCA2','Sonera Class2 CA','Staat der Nederlanden EV Root CA','Staat der Nederlanden Root CA - G2','Staat der Nederlanden Root CA - G3','Starfield Class 2 Certification Authority','Starfield Root Certificate Authority - G2','Starfield Services Root Certificate Authority - G2','StartCom Certification Authority G2','StartCom Certification Authority','StartCom Certification Authority','Swisscom Root CA 1','Swisscom Root CA 2','Swisscom Root EV CA 2','SwissSign Gold CA - G2','SwissSign Gold Root CA - G3','SwissSign Platinum CA - G2','SwissSign Platinum Root CA - G3','SwissSign Silver CA - G2','SwissSign Silver Root CA - G3','Symantec Class 1 Public Primary Certification Authority - G4','Symantec Class 1 Public Primary Certification Authority - G6','Symantec Class 2 Public Primary Certification Authority - G4','Symantec Class 2 Public Primary Certification Authority - G6','Symantec Class 3 Public Primary Certification Authority - G4','Symantec Class 3 Public Primary Certification Authority - G6','SZAFIR ROOT CA','T-TeleSec GlobalRoot Class 2','T-TeleSec GlobalRoot Class 3','TeliaSonera Root CA v1','thawte Primary Root CA - G2','thawte Primary Root CA - G3','thawte Primary Root CA','TRUST2408 OCES Primary CA','Trustis FPS Root CA','TWCA Global Root CA','TWCA Root Certification Authority','UCA Global Root','UCA Root','USERTrust ECC Certification Authority','USERTrust RSA Certification Authority','UTN - DATACorp SGC','UTN-USERFirst-Client Authentication and Email','UTN-USERFirst-Hardware','UTN-USERFirst-Object','VeriSign Class 1 Public Primary Certification Authority - G3','VeriSign Class 2 Public Primary Certification Authority - G3','VeriSign Class 3 Public Primary Certification Authority - G3','VeriSign Class 3 Public Primary Certification Authority - G4','VeriSign Class 3 Public Primary Certification Authority - G5','VeriSign Universal Root Certification Authority','Visa eCommerce Root','Visa Information Delivery Root CA','VRK Gov. Root CA','XRamp Global Certification Authority','Chambers of Commerce Root','Chambers of Commerce Root - 2008','Global Chambersign Root','Global Chambersign Root - 2008','Actalis Authentication Root CA','Amazon Root CA 1','Amazon Root CA 2','Amazon Root CA 3','Amazon Root CA 4','Starfield Services Root Certificate Authority - G2','Certum CA','Certum Trusted Network CA','Certum Trusted Network CA 2','Atos TrustedRoot 2011','Autoridad de Certificacion Firmaprofesional CIF A62634068','Buypass Class 2 Root CA','Buypass Class 3 Root CA','AC Raíz Certicámara S.A.','Certinomis - Root CA','certSIGN ROOT CA','CFCA EV ROOT','Chunghwa Telecom Co., Ltd. - ePKI Root Certification Authority','AAA Certificate Services','AddTrust Class 1 CA Root','AddTrust External CA Root','COMODO Certification Authority','COMODO ECC Certification Authority','COMODO RSA Certification Authority','USERTrust ECC Certification Authority','USERTrust RSA Certification Authority','UTN-USERFirst-Client Authentication and Email','EC-ACC','SecureSign RootCA11','D-TRUST Root CA 3 2013','D-TRUST Root Class 3 CA 2 2009','D-TRUST Root Class 3 CA 2 EV 2009','Certigna','Baltimore CyberTrust Root','Cybertrust Global Root','DigiCert Assured ID Root CA','DigiCert Assured ID Root G2','DigiCert Assured ID Root G3','DigiCert Global Root CA','DigiCert Global Root G2','DigiCert Global Root G3','DigiCert High Assurance EV Root CA','DigiCert Trusted Root G4','GeoTrust Global CA','GeoTrust Primary Certification Authority','GeoTrust Primary Certification Authority - G2','GeoTrust Primary Certification Authority - G3','GeoTrust Universal CA','GeoTrust Universal CA 2','Symantec Class 1 Public Primary Certification Authority - G4','Symantec Class 1 Public Primary Certification Authority - G6','Symantec Class 2 Public Primary Certification Authority - G4','Symantec Class 2 Public Primary Certification Authority - G6','thawte Primary Root CA','thawte Primary Root CA - G2','thawte Primary Root CA - G3','VeriSign Class 1 Public Primary Certification Authority - G3','VeriSign Class 2 Public Primary Certification Authority - G3','VeriSign Class 3 Public Primary Certification Authority - G3','VeriSign Class 3 Public Primary Certification Authority - G4','VeriSign Class 3 Public Primary Certification Authority - G5','VeriSign Universal Root Certification Authority','CA Disig Root R2','Certplus Root CA G1','Certplus Root CA G2','Class 2 Primary CA','OpenTrust Root CA G1','OpenTrust Root CA G2','OpenTrust Root CA G3','E-Tugra Certification Authority','AffirmTrust Commercial','AffirmTrust Networking','AffirmTrust Premium','AffirmTrust Premium ECC','Entrust Root Certification Authority','Entrust Root Certification Authority - EC1','Entrust Root Certification Authority - G2','Entrust.net Certification Authority (2048)','GDCA TrustAUTH R5 ROOT','GlobalSign','GlobalSign','GlobalSign','GlobalSign Extended Validation CA - SHA256 - G2','GlobalSign Root CA','Go Daddy Class 2 CA','Go Daddy Root Certificate Authority - G2','Starfield Class 2 CA','Starfield Root Certificate Authority - G2','GlobalSign','GlobalSign','Hongkong Post Root CA 1','ACCVRAIZ1','FNMT-RCM - SHA256','Government Root Certification Authority - Taiwan','Staat der Nederlanden EV Root CA','Staat der Nederlanden Root CA - G2','Staat der Nederlanden Root CA - G3','TUBITAK Kamu SM SSL Kok Sertifikasi - Surum 1','Hellenic Academic and Research Institutions ECC RootCA 2015','Hellenic Academic and Research Institutions RootCA 2011','Hellenic Academic and Research Institutions RootCA 2015','DST Root CA X3','IdenTrust Commercial Root CA 1','IdenTrust Public Sector Root CA 1','ISRG Root X1','Izenpe.com','SZAFIR ROOT CA2','LuxTrust Global Root 2','Microsec e-Szigno Root CA 2009','NetLock Arany (Class Gold) Főtanúsítvány','QuoVadis Root CA 1 G3','QuoVadis Root CA 2','QuoVadis Root CA 2 G3','QuoVadis Root CA 3','QuoVadis Root CA 3 G3','QuoVadis Root Certification Authority','SECOM Trust.net - Security Communication RootCA1','Security Communication RootCA2','EE Certification Centre Root CA','SSL.com EV Root Certification Authority ECC','SSL.com EV Root Certification Authority RSA R2','SSL.com Root Certification Authority ECC','SSL.com Root Certification Authority RSA','Swisscom Root CA 2','SwissSign Gold CA - G2','SwissSign Platinum CA - G2','SwissSign Silver CA - G2','Deutsche Telekom Root CA 2','T-TeleSec GlobalRoot Class 2','T-TeleSec GlobalRoot Class 3','TWCA Global Root CA','TWCA Root Certification Authority','Sonera Class2 CA','TeliaSonera Root CA v1','TrustCor ECA-1','TrustCor RootCert CA-1','TrustCor RootCert CA-2','Trustis Limited - Trustis FPS Root CA','Secure Global CA','SecureTrust CA','XRamp Global Certification Authority','Visa eCommerce Root','Network Solutions Certificate Authority','OISTE WISeKey Global Root GA CA','OISTE WISeKey Global Root GB CA','OISTE WISeKey Global Root GC CA ']
p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'




def DaysLeft(date):
    try:
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        time=datetime.strptime(date, ssl_date_fmt)
        daysLeft= time - datetime.now()
        daysLeft=repr(daysLeft.days)
    
    except:
        
        daysLeft=''
    return daysLeft

def Date(hostname):
    try:
        date=os.popen('echo | gnutls-cli --print-cert '+hostname+'< /dev/null 2>/dev/null| openssl x509 -inform pem -noout -dates 2>/dev/null').read()
        date=date.split("\n")
        date=date[1].replace('notAfter=','')
    except:
        
        date=''
    return date

def Issuer_CN(hostname):
    try:
        Issuer=os.popen('echo | gnutls-cli --print-cert '+hostname+'< /dev/null 2>/dev/null| openssl x509 -inform pem -noout -issuer 2>/dev/null').read()
        Issuer=Issuer.replace('\n','').replace('issuer= /','').split("/")
        Issuer_CN=Issuer[-1]
        Issuer_CN=Issuer_CN.replace('CN=','')
    except:
        
        Issuer_CN=''
    return Issuer_CN

def subject_CN(hostname):
    try:
        subject=os.popen('echo | gnutls-cli --print-cert '+hostname+'< /dev/null 2>/dev/null| openssl x509 -inform pem -noout -subject 2>/dev/null').read()
        subject=subject.replace('\n','').replace('subject= /','').split("/")
        subject_CN=subject[-1]
        subject_CN=subject_CN.replace('CN=','')
    except:
        
        subject_CN=''     
    return subject_CN


def TLSv12(hostname):
    try:
        url="https://"+hostname
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # set other SSLContext options you might need
        response = urllib.request.urlopen(url, context=ctx, timeout=30).read()
        TLSv1_2=True
    except timeout:
        
        TLSv1_2='timeout'
    except Exception as e:
        
        if str(e) == "<urlopen error [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:833)>":
            TLSv1_2=False
        else:
            
            TLSv1_2=False
    return str(TLSv1_2)

def TLSv11(hostname):
    try:
        url="https://"+hostname
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
        # set other SSLContext options you might need
        response = urllib.request.urlopen(url, context=ctx, timeout=30).read()
        TLSv1_1=True
    except timeout:
            pass
    except Exception as e:
        
        if str(e) == "<urlopen error [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version (_ssl.c:833)>":
            TLSv1_1=False
        else:
        
            TLSv1_1=False
    return str(TLSv1_1)
    
def TLSv10(hostname):
    
    try:
        url="https://"+hostname
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        # set other SSLContext options you might need
        response = urllib.request.urlopen(url, context=ctx, timeout=30).read()
        TLSv1_0=True
    except timeout:
        
        TLSv1_0='timeout'
    except Exception as e:
        
        if str(e) == "<urlopen error [SSL: TLSV1_ALERT_PROTOCOL_VERSION] tlsv1 alert protocol version (_ssl.c:833)>":
            TLSv1_0=False
        else:
           
            TLSv1_0=False
    return str(TLSv1_0)
    
def SSLv3(hostname):
    
    try:
        url="https://"+hostname
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        # set other SSLContext options you might need
        response = urllib.request.urlopen(url, context=ctx, timeout=30).read()
        SSLv3=True
    except timeout:
    
        SSLv3='timeout'
    except Exception as e:
        if str(e) == "<urlopen error [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:833)>":
            SSLv3=False
        else:
        
            SSLv3=False
    return str(SSLv3)


def TLS(hostname):
    try:
        v1_2 = (TLSv12(hostname))
        v1_1 = (TLSv11(hostname))
        v1_0 = (TLSv10(hostname))
        v3 = (SSLv3(hostname))
        ciphers=sslCiphers(hostname)
        
        json_data={} 
        json_data['TLSv1_2']=v1_2  
        json_data['TLSv1_1']=v1_1
        json_data['TLSv1_0']=v1_0
        json_data['SSLv3']=v3
        json_data['ciphers']=ciphers
    except:
        
        json_data={} 
    return json_data

def domainMatchWithCN(hostname):
    try:
        dns=os.popen('echo | gnutls-cli --print-cert '+hostname+'< /dev/null 2>/dev/null| openssl x509 -inform pem -noout -text 2>/dev/null | grep DNS').read()
        dns=dns.replace(" ","").replace("\n","").replace("DNS:","").split(",")
        star=[]
        nostar=[]
        for i in dns:
            if i.find("*.") == 0:
                star.append(i[2:])
            else:
                nostar.append(i)
                
        if hostname in nostar:
            domainMatchWithCN=True
        elif hostname in star:
            domainMatchWithCN=True
        elif hostname[hostname.find('.')+1:] in star:
            domainMatchWithCN=True
        else:
            domainMatchWithCN=False 
    except:
         
         domainMatchWithCN=False
    return str(domainMatchWithCN)

def isSelfSign(hostname):
    try:
        if (subject_CN(hostname)) == (Issuer_CN(hostname)):
            isSelfSign= True
        else:
            isSelfSign= False
    except:
        
        isSelfSign= ""
    return str(isSelfSign)

def trustedRoot(hostname):
    try:
        d=os.popen('echo | gnutls-cli --ocsp '+ hostname +'< /dev/null 2>/dev/null| grep - | grep subject').read()
        d=d.split(" - subject")
        d=str(str(d[-1:]).split(" issuer")[-1:]).split(",")

        for i in d:
            if i.startswith("CN=") == True:
                rootCN = i
        
        rootCN=rootCN.replace("CN=","").replace('\\','').replace("'","")

        rootAuth =( rootCN in store)

    except:
    
        rootAuth= ""
    return str(rootAuth)

def redirection(hostname):
    try:
        r = requests.head("http://"+hostname)
        if r.status_code != 200:
            r = requests.head("http://"+hostname, allow_redirects=True)
            m=re.search(p,r.url)
            if m.group('host').replace("www.","") == hostname:
                reDirction = True
            else:
                reDirction = False
        else:
            reDirction = False
    except:
    
        reDirction = ""
    return str(reDirction)

def sslCiphers(hostname):
    try:
        d=os.popen('nmap --script ssl-enum-ciphers -p 443 '+ hostname).read()
        d=d.replace("|",'').replace(' ','')
        d=d.split("\n")
        
        def arr(key):
            n=d.copy().index(key)
            v=d[n+2:]
            arr1=v[:v.index('compressors:')]
            return arr1
        if "TLSv1.0:" in d:
            TLSv10=[]
            for i in arr("TLSv1.0:"):
                TLSv10.append(i.split("-"))
                
        else:
            TLSv10 =[]
        if "TLSv1.1:" in d:
            TLSv11=[]
            for i in arr("TLSv1.1:"):
                TLSv11.append(i.split("-"))
        else:
            TLSv11 =[]
        if "TLSv1.2:" in d:
            TLSv12=[]
            for i in arr("TLSv1.2:"):
                TLSv12.append(i.split("-"))
        else:
            TLSv12 =[]
        if "SSLv3:" in d:
            SSLv3=[]
            for i in arr("SSLv3:"):
                SSLv3.append(i.split("-"))
        else:
            SSLv3 =[]
    except:
        
        TLSv12 =[]
        TLSv11 =[]
        TLSv10 =[]
        SSLv3=[]
    sslciphers={}
    sslciphers['TLSv1_2']=TLSv12
    sslciphers['TLSv1_1']=TLSv11
    sslciphers['TLSv1_0']=TLSv10
    sslciphers['SSLv3']=SSLv3
    return sslciphers
def usedBeforeActivationDate(hostname): 
    try:
        date=os.popen('echo | gnutls-cli --print-cert google.com< /dev/null 2>/dev/null| openssl x509 -inform pem -noout -dates 2>/dev/null | grep  notBefore=').read()
        date=date.replace('notBefore=','').replace('\n','')
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        time=datetime.strptime(date, ssl_date_fmt)
        daysLeft= time - datetime.now()
        daysLeft=repr(daysLeft.days)
        if int(daysLeft) > 0:
            usedBeforeActivationDate= True
        else:
            usedBeforeActivationDate= False
    except:
        
        usedBeforeActivationDate=""
    return str(usedBeforeActivationDate)


def sslChain(hostname):
    try:
        subjectCN=[]
        issuerCN=[]
        activated=[]
        expires=[]
        def subject(key):
        
           d=key.split("issuer")
           v=(d[0].split(","))
           v.pop(len(v)-1)
           subjectCN.append(v[-1:][0].replace("CN=",""))
           return subjectCN
        def issuer(key):
        
           d=key.split("issuer")
           v=(d[1].split(","))
           for i in v:
               if i.startswith("CN=") == True:
                   #print(i.replace("CN=",""))
                   issuerCN.append(i.replace("CN=",""))
               if i.startswith(" activated `") == True:
                   activated.append(i.replace(" activated `",""))
               if i.startswith(" expires `") == True:
                   expires.append(i.replace(" expires `",""))
        
           return issuerCN ,activated,expires
        
        
        d=os.popen('echo | gnutls-cli --ocsp '+hostname+'< /dev/null 2>/dev/null| grep - | grep subject').read()
        d=d.replace("'","").split(" - subject")
        d.pop(0)
        for i in d:
            subject(i)
            issuer(i)
        Chain={}
        for i in range(len(issuerCN)):
            Chain[str(i)]={}
            Chain[str(i)]["subjectCN"]=subjectCN[i]
            Chain[str(i)]["issuerCN"]=issuerCN[i]
            Chain[str(i)]["activated"]=activated[i]
            Chain[str(i)]["expires"]=expires[i]
    except:
        
        Chain=""   
    return Chain

def SignatureAlgorithm(hostname):
    try:
        
        d=os.popen('gnutls-cli --print-cert '+hostname+'< /dev/null 2>/dev/null| openssl x509 -inform pem -noout -text 2>/dev/null | grep  Signature | grep Algorithm:').read()
        sinAlgo = d.replace(" ","").split("\n")[0].replace("SignatureAlgorithm:","")
    except:
        
        sinAlgo="" 
    return sinAlgo

def isInsecureSignatureAlgorithm(hostname):
    try:
        d=os.popen('gnutls-cli --print-cert '+hostname+'< /dev/null 2>/dev/null| openssl x509 -inform pem -noout -text 2>/dev/null | grep  Signature | grep Algorithm:').read()
        sinAlgo = d.replace(" ","").split("\n")[0].replace("SignatureAlgorithm:","")
        status= 'sha1' in sinAlgo or 'md5' in sinAlgo
    except:
        
        status="" 
    return str(status)


def isSSLRevoked(hostname):
    try:
        d=os.popen('gnutls-cli --ocsp '+hostname+'< /dev/null 2>/dev/null | grep Status ').read()
        sslRevoked = ('chain is revoked' in d)
    except:
    
        sslRevoked="" 
    return str(sslRevoked)
def isSSLchainExpired(hostname):
    try:
        d=os.popen('gnutls-cli --ocsp '+hostname+'< /dev/null 2>/dev/null | grep Status ').read()
        SSLchainExpired = ('chain uses expired certificate' in d)
    except:
    
        SSLchainExpired="" 
    return str(SSLchainExpired)

    
