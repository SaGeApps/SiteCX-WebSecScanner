import clientside
from mock import Mock

def test_portScan_best():
    assert len(clientside.portScan("www.google.com")) == 2
    assert len(clientside.portScan("google.com")) == 2
    
def test_portScan_worst():
    assert clientside.portScan("www.") == ['']
    assert clientside.portScan("") == ['  -sV: Probe open ports to determine service/version info',
 '  --open: Only show open (or possibly open) ports']

def test_OSdetection_best():
    assert clientside.OSdetection("www.google.com") != ''

    
def test_OSdetection_worst():
    assert clientside.OSdetection("www.") == ''
    assert clientside.OSdetection("") == ''

def test_dnsspoof_best():
    assert clientside.dnsspoof("www.google.com") == ''

def test_dnsspoof_worst():
    assert clientside.dnsspoof("www.") == ''
    assert clientside.dnsspoof("") == ''

def test_EmailHijacking_best():
    assert clientside.EmailHijacking("www.google.com") == False

    
def test_EmailHijacking_worst():
    assert clientside.EmailHijacking("www.") == False
    assert clientside.EmailHijacking("") == False
    
def test_MITM_best():
    assert clientside.MITM("www.google.com") == 10

    
def test_MITM_worst():
    assert clientside.MITM("www.") == 0
    assert clientside.MITM("") == 0
    



def test_calc_portScan_best():
    assert clientside.calc_portScan("google.com") == 8

    
def test_calc_portScan_worst():
    assert clientside.calc_portScan("www.") == ''
 

def test_calc_OSdetection_best():
    assert clientside.calc_OSdetection("www.google.com") == 10

    
def test_calc_OSdetection_worst():
    assert clientside.calc_OSdetection("www.") == 0
    assert clientside.calc_OSdetection("") == 0

def test_calc_EmailHijacking_best():
    assert clientside.calc_EmailHijacking("www.google.com") == 0

    
def test_calc_EmailHijacking_worst():
    assert clientside.calc_EmailHijacking("www.") == 0
    assert clientside.calc_EmailHijacking("") == 0

def test_calc_spoof_best():
    assert clientside.calc_spoof("www.google.com") == 0

    
def test_calc_spoof_worst():
    assert clientside.calc_spoof("www.") == 0
    assert clientside.calc_spoof("") == 0


    