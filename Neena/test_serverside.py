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
    

def test_XSSProtection_best():
    assert serverside.XSSProtection("google.com") == False
    assert serverside.XSSProtection("ibm.com") == True

def test_XSSProtection_worst():
    assert serverside.XSSProtection("www.") == False
    assert serverside.XSSProtection("") == False


def test_xmas_best():
    assert len(serverside.xmas("www.google.com")) == 2
    assert len(serverside.xmas("google.com")) == 2

def test_xmas_worst():
    assert serverside.xmas("") == ['']


def test_calc_SessionHijack_best():
    assert serverside.calc_SessionHijack("www.google.com") == '1'
    assert serverside.calc_SessionHijack("google.com") == '1'

def test_calc_SessionHijack_worst():
    assert serverside.calc_SessionHijack("") == '1'


def test_calc_CORS_best():
    assert serverside.calc_CORS("www.google.com") == '10'
    assert serverside.calc_CORS("google.com") == '10'

def test_calc_CORS_worst():
    assert serverside.calc_CORS("asss") == '10'


def test_calc_A_RecordRedirection_best():
    assert serverside.calc_A_RecordRedirection("www.google.com") == '1'
    assert serverside.calc_A_RecordRedirection("google.com") == '1'

def test_calc_A_RecordRedirection_worst():
    assert serverside.calc_A_RecordRedirection("") == '1'


def test_calc_calc_SQLInjection_best():
    assert serverside.calc_SQLInjection("www.google.com") == '1'
    assert serverside.calc_SQLInjection("google.com") == '1'

def test_calc_SQLInjection_worst():
    assert serverside.calc_SQLInjection("") == '1'


def test_calc_BrokenACL_best():
    assert serverside.calc_BrokenACL("www.google.com") == '1'
    assert serverside.calc_BrokenACL("google.com") == '1'

def test_calc_BrokenACL_worst():
    assert serverside.calc_BrokenACL("") == '1'


def test_calc_Authentication_best():
    assert serverside.calc_Authentication("www.google.com") == '7'
    assert serverside.calc_Authentication("google.com") == '7'

def test_calc_Authentication_worst():
    assert serverside.calc_Authentication("www.") == '6'
    

def test_calc_Xmas_best():
    assert serverside.calc_Xmas("www.google.com") == '8'
    assert serverside.calc_Xmas("google.com") == '8'

def test_calc_Xmas_worst():
    assert serverside.calc_Xmas("www.") == '9'


def test_calc_xss_best():
    assert serverside.calc_xss("www.google.com") == '7'
    assert serverside.calc_xss("google.com") == 7

def test_calc_xss_worst():
    assert serverside.calc_xss("www.") == 7

    
