c5scan
======

Vulnerability scanner and information gatherer for the Concrete5 CMS

Use
---

```
python c5scan.py -u <url> (-r)

-u   --url      Insert your target URL here
-r   --robots   If found, print contents of robots.txt
```

Dependencies
------------

`pip install httplib2 requests`

Example
-------

```
$ python c5scan.py -u localhost -r

**********************************************************
*                      ~ C5scan ~                        *
* A vulnerability and information gatherer for concrete5 *
*                auraltension@riseup.net                 *
**********************************************************

No http:// or https:// provided. Trying http://
URL: http://localhost/

[+] Discovered version 5.6.2.1 from meta 'generator' tag
[+] Interesting header: server: Apache/2.2.14 (Ubuntu)
[+] Interesting header: x-powered-by: PHP/5.3.2-1ubuntu4.24
[+] robots.txt found at  http://localhost/robots.txt
User-agent: *
Disallow: /blocks 
Disallow: /concrete 
Disallow: /config 
Disallow: /controllers 
Disallow: /css 
Disallow: /elements 
Disallow: /helpers 
Disallow: /jobs 
Disallow: /js 
Disallow: /languages 
Disallow: /libraries 
Disallow: /mail 
Disallow: /models 
Disallow: /packages 
Disallow: /single_pages 
Disallow: /themes 
Disallow: /tools
Disallow: /updates

Enumerating updates in /updates/
[+] Update version 5.5.2.1 exists
[+] Update version 5.6.2.1 exists

Looking for Readme files
[+] Found a readme at:  http://localhost/concrete/libraries/3rdparty/adodb/readme.txt
[+] Found a readme at:  http://localhost/concrete/libraries/3rdparty/adodb/docs/docs-adodb.htm
[+] Found a readme at:  http://localhost/concrete/blocks/video/README
[+] Found a readme at:  http://localhost/concrete/libraries/3rdparty/StandardAnalyzer/Readme.txt
[+] Found a readme at:  http://localhost/concrete/libraries/3rdparty/securimage/README.txt

Checking for known vulnerabilities
[+] A known vulnerability exists for 5.6.2.1:
 http://www.exploit-db.com/exploits/31735/

[!] Current version is vulnerable
```
