#!/usr/bin/python3

from termcolor import colored
import sys
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'
        }


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


if __name__ == '__main__':

    if len(sys.argv) != 5:
        print("Usage: %s <host> <username> <password> <otp>" % (sys.argv[0]))
        print("Example: %s https://citrix.domain.com/ UserName Rand0mPwd123* 123456)" % (sys.argv[0]))
        quit()

    host = sys.argv[1]
    usr = sys.argv[2]
    pwd = sys.argv[3]
    otp = sys.argv[4]

    if not host.endswith('/'):
        host += '/'

    autologin(host, usr, pwd, otp)

