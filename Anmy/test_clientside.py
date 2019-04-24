import clientside

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












    