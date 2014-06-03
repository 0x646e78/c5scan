#!/usr/bin/env python

from contextlib import closing
from lxml import html
import requests # requires > = 1.2
import argparse
import re
import sys

versions = [
    '5.0.0', '5.1.1', '5.2.1', '5.3.1.1', '5.3.2', '5.3.3', '5.3.3.1', 
    '5.4.0.5', '5.4.1', '5.4.1.1', '5.4.2', '5.4.2.1', '5.4.2.2',
    '5.5.0', '5.5.1', '5.5.2', '5.5.2.1', '5.6.0', '5.6.0.1', '5.6.0.2', 
    '5.6.1', '5.6.1.1', '5.6.1.2', '5.6.2', '5.6.2.1', '5.6.3', '5.6.3.1'
]

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

def format_url(url):
    if not re.search('^http', url):
        print "No http:// or https:// provided. Trying http://"
        url = 'http://' + url
    if not re.search('/$', url):
        url += '/'
    return url

def site_available(url):
    try:
        closing(requests.get(url, stream=True, verify=False))
        r = requests.get(url + 'concrete/', verify=False)
        if r.status_code == 404:
            redtext('The site is up but does not appear to be running concrete5')
            exit(1)
    except Exception as e:
        redtext("%s is not reachable" % url)
        exit(1)

def returns_404(url):
    r = requests.get(url + '404check', stream=True, verify=False)
    if r.status_code == 404:
        r.close
        return True
    else:
        r.close
        return False

def check_headers(url):
    r = requests.get(url, verify=False)
    for i in ['server', 'x-powered-by']:
        try:
            print '[+] Interesting header: %s: %s' % (i, r.headers[i])
        except KeyError:
            pass


def get_robots(url, return_codes):
    r = requests.get(url + '/robots.txt', verify=False)
    if (r.status_code == 200) and return_codes:
        print "[+] robots.txt found:\n ", r.content

def get_version(url):
    try:
        r = requests.get(url, verify=False)
        tree = html.fromstring(r.text)
        version = tree.cssselect('meta[name="generator"]')[0].get('content')
        return version
    except:
        return False

def check_updates(url, versions, return_codes):
    print "Enumerating updates"
    for v in versions:
        for extension in ['', '_updater']:
            r = requests.get(url + '/updates/concrete' + v + extension, verify=False)
            if r.status_code == 200 and (return_codes or (r.content == '')):
                print "[+] Update version %s exists" % v

def main():
    parser = argparse.ArgumentParser(description='A c5 scanner')
    parser.add_argument('-u','--url', help='The URL to test')
    args = parser.parse_args()

    if not args.url:
        parser.error('URL required.\n\n See --help.')

    # Print the banner
    banner()

    # Format the url and ensure it is reachable
    url = format_url(args.url)
    print 'URL: ' + url + '\n'
    site_available(url)

    # Some versions didn't return status codes correctly
    return_codes = returns_404(url)
    if not return_codes:
        print "[+] Site is not correctly handling HTTP return codes\n"

    # Get version from meta tags
    version = get_version(url)
    if version and re.search('\d', version):
        print "[+] Discovered version %s from meta 'generator' tag" % version

    check_headers(url)

    # Check for robots.txt
    get_robots(url, return_codes)

    # Enumerate update versions
    check_updates(url, versions, return_codes)

if __name__ == "__main__":
    main()
