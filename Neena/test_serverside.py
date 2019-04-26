import serverside

def test_findlogin_best():
    assert serverside.findlogin("www.google.com") == False
    assert serverside.findlogin("google.com") == False

def test_findlogin_worst():
    assert serverside.findlogin("www.") == False
    assert serverside.findlogin("") == False
    
def test_xsspy_best():
    assert serverside.xsspy("www.google.com") == False
    assert serverside.xsspy("google.com") == False

def test_xsspy_worst():
    assert serverside.xsspy("www.") == False
    assert serverside.xsspy("") == False
    
def test_checkCaptcha_best():
    assert serverside.checkCaptcha("www.google.com") == False
    assert serverside.checkCaptcha("deadlinkchecker.com") == True

def test_checkCaptcha_worst():
    assert serverside.checkCaptcha("www.") == False
    assert serverside.checkCaptcha("") == False
    
def test_blindjacking_best():
    assert serverside.blindjacking("www.google.com") == False
    assert serverside.blindjacking("deadlinkchecker.com") == True

def test_blindjacking_worst():
    assert serverside.blindjacking("www.") == False
    assert serverside.blindjacking("") == False
   

def test_ArecordRedirection_best():
    assert serverside.ArecordRedirection("www.google.com") == False
    assert serverside.ArecordRedirection("deadlinkchecker.com") == False

def test_ArecordRedirection_worst():
    assert serverside.ArecordRedirection("www.") == True
    assert serverside.ArecordRedirection("") == False
   

def test_brokenACL_best():
    assert serverside.brokenACL("www.google.com") == False
    assert serverside.brokenACL("deadlinkchecker.com") == False

def test_brokenACL_worst():
    assert serverside.brokenACL("www.") == False
    assert serverside.brokenACL("") == False
    

def test_SQLInjection_best():
    assert serverside.SQLInjection("www.google.com") == False
    assert serverside.SQLInjection("deadlinkchecker.com") == False

def test_SQLInjection_worst():
    assert serverside.SQLInjection("www.") == False
    assert serverside.SQLInjection("") == False
    

def test_cors_best():
    assert serverside.cors("www.google.com") == False
    assert serverside.cors("deadlinkchecker.com") == False

def test_cors_worst():
    assert serverside.cors("www.") == False
    assert serverside.cors("") == False


def test_XContentTypeOptions_best():
    assert serverside.XContentTypeOptions("www.google.com") == False
    assert serverside.XContentTypeOptions("ibm.com") == True

def test_XContentTypeOptions_worst():
    assert serverside.XContentTypeOptions("www.") == False
    assert serverside.XContentTypeOptions("") == False
    

def test_XFrameOptions_best():
    assert serverside.XFrameOptions("www.google.com") == True
    assert serverside.XFrameOptions("ibm.com") == False

def test_XFrameOptions_worst():
    assert serverside.XFrameOptions("www.") == False
    assert serverside.XFrameOptions("") == False