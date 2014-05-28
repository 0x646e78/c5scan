c5scan
======

Vulnerability scanner and information gatherer for the Concrete5 CMS

Use
---

python c5scan.py -u <url>

Example
-------

```
$ python c5scan.py -u localhost

******************************************************************
*                          ~ C5scan ~                            *
* A vulnerability and information gatherer for the concrete5 cms *
*                    auraltension@riseup.net                     *
******************************************************************

No http:// or https:// provided. Assuming http://
URL: http://localhost/


[+] robots.txt found:
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
Disallow: /login

Enumerating updates
[+] Update version 5.5.2.1 exists
[+] Update version 5.6.0.1 exists
[+] Update version 5.6.0.2 exists
[+] Update version 5.6.1.2_updater exists
[+] Update version 5.6.2.1_updater exists
[+] Update version 5.6.3.1_updater exists
```
