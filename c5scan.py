#!/usr/bin/env python

from contextlib import closing
import requests # requires > = 1.2
import argparse
import sys

oldversions = ['5.4.2.1']
versions = ['5.5.0', '5.5.1', '5.5.2', '5.5.2.1', '5.6.0', '5.6.0.1', '5.6.0.2', '5.6.1', '5.6.1.1', '5.6.1.2_updater', '5.6.2_updater', '5.6.2.1_updater', '5.6.3_updater', '5.6.3.1_updater']

def banner():
    banner="\n******************************************************************\n" 
    banner+="*                          ~ C5scan ~                            *\n"
    banner+="* A vulnerability and information gatherer for the concrete5 cms *\n"
    banner+="*                    auraltension@riseup.net                     *\n"
    banner+="******************************************************************\n" 
    print banner 

def site_available(url):
    try:
        closing(requests.get(url, stream=True))
    except Exception as e:
        print "%s is not reachable" % url
        exit(1)

def returns_404(url):
    r = requests.get(url + '404check', stream=True)
    if r.status_code == 404:
        r.close
        return False
    r.close

def check_updates(url, versions, return_codes):
    print "Enumerating concrete5 updates"
    for v in versions:
        r = requests.get(url + '/updates/concrete' + v)
        if r.status_code == 200:
            if return_codes:
                print "Update version %s exist" % v
            else:
                print "check http content"

def main():
    parser = argparse.ArgumentParser(description='A c5 scanner')
    parser.add_argument('-u','--url', help='The URL to test')
    args = parser.parse_args()

    if not args.url:
        parser.error('URL required.\n\n See --help.')

    url = args.url

    banner()

    # Check that the url is reachable
    site_available(url)

    # Older versions didn't return status codes correctly
    if returns_404:
        return_codes = True

    # Enumerate update versions
    check_updates(url, versions, return_codes)

if __name__ == "__main__":
    main()
