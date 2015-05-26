#!/usr/bin/env python

from contextlib import closing
from lxml import html
import httplib2
import requests # requires > = 1.2
import argparse
import re
import sys

versions = [
    '5.0.0', '5.1.1', '5.2.1', '5.3.1.1', '5.3.2', '5.3.3', '5.3.3.1', 
    '5.4.0.5', '5.4.1', '5.4.1.1', '5.4.2', '5.4.2.1', '5.4.2.2',
    '5.5.0', '5.5.1', '5.5.2', '5.5.2.1', '5.6.0', '5.6.0.1', '5.6.0.2', 
    '5.6.1', '5.6.1.1', '5.6.1.2', '5.6.2', '5.6.2.1', '5.6.3', '5.6.3.1',
    '5.6.3.2', '5.6.3.3', '5.7.0', '5.7.0.1', '5.7.0.3', '5.7.0.4',
    '5.7.1', '5.7.2', '5.7.2.1', '5.7.3', '5.7.3.1', '5.7.4', '5.7.4.1'
]

known_vulns = {
    '5.4.2.1': {'title': 'Concrete5 <= 5.4.2.1 SQL Injection and XSS Vulnerabilities', 'url': 'http://www.exploit-db.com/exploits/17925/'},
    '5.6.1.2': {'title': 'Multiple CSRF and Stored XSS Vulnerabilities', 'url': 'http://www.exploit-db.com/exploits/26077/'},
    '5.6.2.1': {'title': 'SQL Injection in index.php cID param', 'url': 'http://www.exploit-db.com/exploits/31735/'},
    '5.7.0.4': {'title': 'Stored XSS', 'url': 'https://hackerone.com/reports/30019'},
    '5.7.2': {'title': 'Reflected XSS Vulnerabilities', 'url': 'http://www.morxploit.com/morxploits/morxconxss.txt'},
    '5.7.2.1': {'title': 'Reflected XSS Vulnerabilities', 'url': 'http://www.morxploit.com/morxploits/morxconxss.txt'},
    '5.7.3.1': {'title': 'CVE-2015-2250 - Multiple XSS Vulnerabilities', 'url': 'http://seclists.org/fulldisclosure/2015/May/51'}
}

readme_locations = [
    'concrete/libraries/3rdparty/adodb/readme.txt',
    'concrete/libraries/3rdparty/adodb/docs/docs-adodb.htm',
    'concrete/blocks/video/README',
    'concrete/libraries/3rdparty/StandardAnalyzer/Readme.txt',
    'concrete/libraries/3rdparty/securimage/README.txt'
]

class Conn:
    """Connect to the target"""
    def __init__(self, url):
        self.url = url
        self.verify = False

        try:
            # Server is responsive
            h = httplib2.Http(disable_ssl_certificate_validation=True)
            self.headers = h.request(self.url, 'HEAD')
            assert int(self.headers[0]['status']) < 400
            r = requests.get(self.url + 'concrete/js', verify=self.verify)
            if r.status_code == 404:
                r = requests.get(self.url, verify=self.verify)
                if not 'concrete5' in r.text:
                    redtext('The site is up but does not appear to be running concrete5')
                    exit(1)
        except Exception as e:
            redtext("%s is not reachable" % self.url)
            exit(1)

    def get(self, path):
        try:
            r = requests.get(self.url + path, verify=self.verify)
            return r
        except Exception as e:
            redtext("Danger Will Robinson! %s" %  e)
            exit(1)

    def heads(self):
        return self.headers

    def url(self):
        return self.url


def banner():
    banner=(
            "\n**********************************************************\n" 
            "*                      ~ C5scan ~                        *\n"
            "* A vulnerability and information gatherer for concrete5 *\n"
            "*                auraltension@riseup.net                 *\n"
            "**********************************************************\n" 
    )
    print banner 

def redtext(text):
    print '\033[91m' + text + '\033[0m'

def orangetext(text):
    print '\033[33m' + text + '\033[0m'

def yellowtext(text):
    print '\033[36m' + text + '\033[0m'

def format_url(url):
    if not re.search('^http', url):
        print "No http:// or https:// provided. Trying http://"
        url = 'http://' + url
    if not re.search('/$', url):
        url += '/'
    return url

def returns_404(c):
    r = c.get('404check')
    if r.status_code == 404:
        r.close
        return True
    else:
        r.close
        return False

def check_headers(c):
    h = c.heads()
    for i in ['server', 'x-powered-by']:
        try:
            orangetext('[+] Interesting header: %s: %s' % (i, h[0][i]))
        except KeyError:
            pass


def get_robots(c, return_codes, verbose):
    r = c.get('robots.txt')
    if (r.status_code == 200) and return_codes:
        print "[+] robots.txt found at ", c.url + 'robots.txt'
        if verbose:
            yellowtext(r.content)

def get_version(url):
    try:
        r = requests.get(url, verify=False)
        tree = html.fromstring(r.text)
        version = tree.cssselect('meta[name="generator"]')[0].get('content')
        return version
    except:
        return False

def check_updates(conn, versions, return_codes):
    print "\nEnumerating updates in /updates/"
    #TODO: check that updates dir exists before enumeration attempts?
    updates = []
    for v in versions:
        for extension in ['', '_updater']:
            path = '/updates/concrete' + v + extension
            r = conn.get(path)
            if r.status_code == 200 and (return_codes or (r.content == '')):
                print "[+] Update version %s exists" % v
                updates.append(v)
    return updates

def check_readmes(c, readme_locations):
    print "\nLooking for Readme files"
    for i in readme_locations:
        r = c.get(i)
        if r.status_code == 200:
            print "[+] Found a readme at: ", c.url + i

def check_vulns(versions, known_vulns):
    for i in versions:
        if i in known_vulns:
            orangetext(
                '[+] A known vulnerability exists for %s:' % i
            )
            print known_vulns[i]['title'] + '\n' + known_vulns[i]['url'] + '\n'

def main():
    parser = argparse.ArgumentParser(description='A c5 scanner')
    parser.add_argument('-u','--url', help='The URL to test')
    parser.add_argument('-r','--robots', action="store_true", help='Print the contents of robots.txt')
    args = parser.parse_args()

    if not args.url:
        parser.error('URL required.\n\n See --help.')

    # Print the banner
    banner()

    # Format the url and ensure it is reachable
    url = format_url(args.url)
    print 'URL: ' + url + '\n'

    # Connect to host
    conn = Conn(url)

    # Some versions didn't return status codes correctly
    return_codes = returns_404(conn)
    if not return_codes:
        print "[+] Site may not be correctly handling HTTP return codes\n"

    # Get version from meta tags
    version = get_version(url)
    if version and re.search('\d', version):
        version = version.split(' ')[-1]
        print "[+] Discovered version %s from meta 'generator' tag" % version

    check_headers(conn)

    # Check for robots.txt
    get_robots(conn, return_codes, args.robots)

    # Enumerate update versions
    updates = check_updates(conn, versions, return_codes)

    # Check for known readme locations
    check_readmes(conn, readme_locations)

    # Check for known vulns
    print "\nChecking for known vulnerabilities in updates"
    updates = list(set(updates))
    check_vulns(updates, known_vulns)
    if version:
        print "Checking for known vulnerabilities in current version"
        check_vulns(version.split(), known_vulns)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print '\n User Exit'
    except Exception as e:
        print "An error has occured. Exiting", e
        exit(1)
